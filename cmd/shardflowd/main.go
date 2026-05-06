package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/hett-patell/ShardFlow/internal/arpengine"
	"github.com/hett-patell/ShardFlow/internal/devicestore"
	"github.com/hett-patell/ShardFlow/internal/iface"
	"github.com/hett-patell/ShardFlow/internal/nftmgr"
	"github.com/hett-patell/ShardFlow/internal/pcapwriter"
	"github.com/hett-patell/ShardFlow/internal/policycompiler"
	"github.com/hett-patell/ShardFlow/internal/rpc"
	"github.com/hett-patell/ShardFlow/internal/scan/active"
	"github.com/hett-patell/ShardFlow/internal/scan/mdns"
	"github.com/hett-patell/ShardFlow/internal/scan/passive"
	"github.com/hett-patell/ShardFlow/internal/scan/ssdp"
	"github.com/hett-patell/ShardFlow/internal/tcmgr"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "shardflowd:", err)
		os.Exit(1)
	}
}

// run uses a named return + cleanup stack so any partial startup failure
// is rolled back instead of leaving orphaned kernel state. The same
// shutdown function is invoked by the signal handler on normal shutdown
// — idempotent via sync.Once.
func run() (err error) {
	var (
		ifaceFlag      = flag.String("i", "", "interface name (required)")
		sockFlag       = flag.String("sock", "/run/shardflow/sock", "Unix socket path")
		forceFlag      = flag.Bool("force", false, "remove stale socket if present")
		cleanFlag      = flag.Bool("clean-on-start", false, "clean orphaned kernel state from a prior run")
		defaultPcapDir = flag.String("default-pcap-dir", "/var/lib/shardflow/pcap", "directory used by Policy.Set pcap when its pcap_dir is empty")
	)
	flag.Parse()
	if *ifaceFlag == "" {
		return fmt.Errorf("-i <iface> is required")
	}

	info, err := iface.Lookup(*ifaceFlag)
	if err != nil {
		return err
	}
	if info.Gateway == nil {
		return fmt.Errorf("could not determine IPv4 default gateway on %s", info.Name)
	}

	if err := preflight(*sockFlag, info.Name, *forceFlag, *cleanFlag); err != nil {
		return err
	}
	prevForward, err := setIPv4Forward("1")
	if err != nil {
		return fmt.Errorf("enable forwarding: %w", err)
	}
	defer func() {
		_, _ = setIPv4Forward(prevForward)
	}()

	gwMAC, err := resolveGatewayMAC(info)
	if err != nil {
		return fmt.Errorf("resolve gateway MAC: %w", err)
	}

	store := devicestore.New()
	nft := nftmgr.New()
	tcm := tcmgr.New()
	pc := pcapwriter.New()
	arp := arpengine.New(info.Name, info.HwAddr, time.Second)
	comp := policycompiler.New(nft, tcm, pc, arp, info.Name)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var shutdownOnce sync.Once
	shutdown := func() {
		shutdownOnce.Do(func() {
			_ = arp.StopAll()
			_ = comp.Apply(context.Background(), map[string]policycompiler.Spec{})
			_ = nft.Teardown(context.Background())
			_ = pc.CloseAll()
			_ = tcm.Teardown(context.Background())
		})
	}
	defer func() {
		if err != nil {
			shutdown()
		}
	}()

	if err := nft.EnsureTables(ctx, info.Name); err != nil {
		return err
	}
	if err := tcm.EnsureIFB(ctx); err != nil {
		return err
	}
	if err := tcm.EnsureCaptureIface(ctx); err != nil {
		return err
	}
	if err := tcm.EnsureRedirect(ctx, info.Name); err != nil {
		return err
	}

	go func() { _ = passive.Run(ctx, info.Name, store.Upsert) }()

	enrich := func(obs devicestore.Observation) {
		if len(obs.MAC) == 0 && obs.IP != nil {
			if mac, ok := store.ResolveIP(obs.IP); ok {
				obs.MAC = mac
			}
		}
		store.Upsert(obs)
	}

	scanner := func(ctx context.Context) error {
		actCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := active.Sweep(actCtx, info.Name, info.HwAddr, info.IP, info.IPNet, 2*time.Second, store.Upsert); err != nil {
			return err
		}
		_ = mdns.Query(actCtx, info.Name, 3*time.Second, enrich)
		_ = ssdp.Query(actCtx, info.Name, 3*time.Second, enrich)
		return nil
	}

	var srv *rpc.Server
	handlers := rpc.BuildHandlers(&rpc.HandlerDeps{
		Store:    store,
		Compiler: comp,
		Scanner:  scanner,
		GwMAC:    gwMAC,
		GwIP:     info.Gateway,
		Broadcaster: func(method string, params any) {
			if srv != nil {
				srv.Broadcast(method, params)
			}
		},
		ActivePoisons:  func() int { return len(arp.Active()) },
		DefaultPcapDir: *defaultPcapDir,
	})
	srv = rpc.NewServer(handlers)

	go func() {
		ch := store.Subscribe()
		for ev := range ch {
			method := rpc.EventDeviceUpdated
			if ev.Kind == devicestore.EventDiscovered {
				method = rpc.EventDeviceDiscovered
			}
			dto := rpc.DeviceDTO{
				MAC:      ev.Device.MAC.String(),
				IP:       ev.Device.IP.String(),
				Hostname: ev.Device.Hostname,
				Vendor:   ev.Device.Vendor,
				LastSeen: ev.Device.LastSeen.Format(time.RFC3339),
			}
			srv.Broadcast(method, dto)
		}
	}()

	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				srv.Broadcast(rpc.EventCountersTick, map[string]any{"ts": time.Now().Unix()})
			}
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Fprintln(os.Stderr, "shardflowd: shutting down")
		_ = srv.Stop()
		shutdown()
		cancel()
	}()

	if err := srv.Listen(ctx, *sockFlag); err != nil {
		return err
	}
	return nil
}
