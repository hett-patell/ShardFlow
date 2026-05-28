package main

import (
	"context"
	"flag"
	"fmt"
	"net"
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
	"github.com/hett-patell/ShardFlow/internal/version"
	"github.com/hett-patell/ShardFlow/internal/wifi"
)

// scanStats tracks the most recent active sweep's results so the
// SESSION panel in the TUI can flag AP isolation (zero replies on a
// wireless iface = strong hint that the AP filters intra-client
// traffic — typical guest WiFi setup). Atomically updated by the
// scanner closure.
type scanStats struct {
	mu       sync.Mutex
	lastAt   time.Time
	replies  int
}

func (s *scanStats) record(replies int) {
	s.mu.Lock()
	s.lastAt = time.Now()
	s.replies = replies
	s.mu.Unlock()
}

func (s *scanStats) snapshot() (time.Time, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastAt, s.replies
}

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
		poisonCadence = flag.Duration("poison-cadence", 200*time.Millisecond,
			"interval between ARP poison bursts per target. Default 200ms is reliable for modern devices (iOS 16+, Android 12+). For older devices or stealth, use 500ms or 1s. Each burst sends 4 frames per target.")
		versionFlag = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()
	if *versionFlag {
		// Print to stdout (consumers grepping the daemon version
		// expect stdout, not the iface=… start-up banner on stderr).
		fmt.Println("shardflowd", version.String())
		return nil
	}
	if *ifaceFlag == "" {
		return fmt.Errorf("-i <iface> is required")
	}

	info, err := iface.Lookup(*ifaceFlag)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "shardflowd: iface=%s ip=%s mac=%s gw=%s\n", info.Name, info.IP, info.HwAddr, info.Gateway)
	if info.Gateway == nil {
		return fmt.Errorf("could not determine IPv4 default gateway on %s", info.Name)
	}

	fmt.Fprintln(os.Stderr, "shardflowd: preflight")
	if err := preflight(*sockFlag, info.Name, *forceFlag, *cleanFlag); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "shardflowd: enable forwarding")
	prevForward, err := setIPv4Forward("1")
	if err != nil {
		return fmt.Errorf("enable forwarding: %w", err)
	}
	defer func() {
		_, _ = setIPv4Forward(prevForward)
	}()

	fmt.Fprintln(os.Stderr, "shardflowd: disable ICMP send_redirects (all, default, "+info.Name+")")
	prevRedir, err := disableSendRedirects(info.Name)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = writeSysctl("/proc/sys/net/ipv4/conf/all/send_redirects", prevRedir.all)
		_, _ = writeSysctl("/proc/sys/net/ipv4/conf/default/send_redirects", prevRedir.def)
		_, _ = writeSysctl("/proc/sys/net/ipv4/conf/"+info.Name+"/send_redirects", prevRedir.iface)
	}()

	// Gateway MAC resolution runs in parallel with nft/tc Ensure* because
	// it spends most of its time sleeping (UDP kicks every 500ms, polling
	// the kernel neighbour table) — independent of any kernel-state setup
	// we're doing. Worst-case startup goes from ~8s sequential to whatever
	// the longer of {gw resolution, EnsureX chain} takes (typically the
	// EnsureX chain at ~250ms, so we save up to 7.5s on a cold start).
	gwMACCh := make(chan struct {
		mac net.HardwareAddr
		err error
	}, 1)
	go func() {
		fmt.Fprintln(os.Stderr, "shardflowd: resolving gateway MAC (background)...")
		mac, err := resolveGatewayMAC(info)
		gwMACCh <- struct {
			mac net.HardwareAddr
			err error
		}{mac, err}
	}()

	store := devicestore.New()
	nft := nftmgr.New()
	tcm := tcmgr.New()
	pc := pcapwriter.New()
	arp, err := arpengine.New(info.Name, info.HwAddr, *poisonCadence)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "shardflowd: poison cadence = %s (≈ %.0f bursts/sec/target)\n",
		*poisonCadence, float64(time.Second)/float64(*poisonCadence))
	comp := policycompiler.New(nft, tcm, pc, arp, info.Name, info.HwAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var shutdownOnce sync.Once
	shutdown := func() {
		shutdownOnce.Do(func() {
			fmt.Fprintln(os.Stderr, "shardflowd: running cleanup")
			_ = arp.StopAll()
			_ = comp.Apply(context.Background(), map[string]policycompiler.Spec{})
			_ = nft.Teardown(context.Background())
			_ = pc.CloseAll()
			_ = tcm.Teardown(context.Background(), info.Name)
			_ = arp.Close() // release shared pcap handle
		})
	}
	// Unconditional defer so cleanup runs on normal exit, error, AND panic.
	defer shutdown()

	// Forward-declare srv and deps so the signal handler closure can
	// reference them. deps is populated below so that MarkShuttingDown
	// flips the shuttingDown flag before shutdown() runs — without this,
	// a Policy.Set landing between Apply(empty) and arp.StopAll would
	// leave the new target uncorrected (spec §9.1).
	var (
		srv  *rpc.Server
		deps *rpc.HandlerDeps
	)

	// Signal handling installed BEFORE kernel-mutating EnsureX calls so a
	// signal during startup triggers the same shutdown path instead of
	// orphaning newly-created kernel state. The srv != nil guard handles
	// the window before srv = rpc.NewServer(...) is assigned.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Fprintln(os.Stderr, "shardflowd: shutting down")
		if deps != nil {
			deps.MarkShuttingDown()
		}
		if srv != nil {
			_ = srv.Stop()
		}
		shutdown()
		cancel()
	}()

	fmt.Fprintln(os.Stderr, "shardflowd: nft.EnsureTables")
	if err := nft.EnsureTables(ctx, info.Name); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "shardflowd: tcm.EnsureIFB")
	if err := tcm.EnsureIFB(ctx); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "shardflowd: tcm.EnsureCaptureIface")
	if err := tcm.EnsureCaptureIface(ctx); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "shardflowd: tcm.EnsureRedirect")
	if err := tcm.EnsureRedirect(ctx, info.Name); err != nil {
		return err
	}

	// Now collect the gateway MAC. By the time the EnsureX chain above
	// has run (~250ms), the background resolver has almost always
	// finished — so this receive is usually instant. On a slow LAN we
	// still wait its full 8s budget.
	gwRes := <-gwMACCh
	if gwRes.err != nil {
		return fmt.Errorf("resolve gateway MAC: %w", gwRes.err)
	}
	gwMAC := gwRes.mac
	fmt.Fprintf(os.Stderr, "shardflowd: gateway MAC = %s\n", gwMAC)

	go func() { _ = passive.Run(ctx, info.Name, store.Upsert) }()

	enrich := func(obs devicestore.Observation) {
		if len(obs.MAC) == 0 && obs.IP != nil {
			if mac, ok := store.ResolveIP(obs.IP); ok {
				obs.MAC = mac
			}
		}
		store.Upsert(obs)
	}

	stats := &scanStats{}

	scanner := func(ctx context.Context) error {
		// Active ARP sweep first: gives us the (MAC, IP) backbone the
		// later mDNS/SSDP enrich callbacks rely on for IP→MAC resolution.
		// mDNS and SSDP run concurrently afterwards because they're
		// independent multicast queries — sequential they took ~6s
		// total; parallel cuts it to ~3s and the operator's "scan
		// frozen" window halves.
		actCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		// Wrap store.Upsert so we can count unique reply MACs from
		// the active sweep specifically. The result is the AP-isolation
		// diagnostic exposed via Session.Get: on a wireless iface
		// with a healthy scan we expect at least the gateway plus a
		// handful of clients; <= 1 reply = strong hint isolation is on.
		seen := make(map[string]struct{})
		var seenMu sync.Mutex
		myMAC := info.HwAddr.String()
		countObs := func(obs devicestore.Observation) {
			if len(obs.MAC) > 0 {
				m := obs.MAC.String()
				if m != myMAC {
					seenMu.Lock()
					seen[m] = struct{}{}
					seenMu.Unlock()
				}
			}
			store.Upsert(obs)
		}
		// Pass arp as the FrameWriter: active.Sweep then uses the
		// engine's already-open pcap handle for ARP request sends
		// instead of opening a second write capacity on the same
		// iface. Also lets the read handle drop promisc mode — replies
		// to our own ARP arrive at our MAC regardless.
		if err := active.SweepWithWriter(actCtx, info.Name, info.HwAddr, info.IP, info.IPNet, 2*time.Second, arp, countObs); err != nil {
			stats.record(len(seen))
			return err
		}
		stats.record(len(seen))

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = mdns.Query(actCtx, info.Name, 3*time.Second, enrich)
		}()
		go func() {
			defer wg.Done()
			_ = ssdp.Query(actCtx, info.Name, 3*time.Second, enrich)
		}()
		wg.Wait()
		return nil
	}

	// Probe wireless association once at startup. SSID/BSSID won't change
	// during a session (a roam swaps the BSSID but operators typically
	// run shardflowd on a fixed iface bound to a fixed AP). Re-probing
	// per Session.Get would be wasted shell-out cost.
	wifiInfo := wifi.Probe(info.Name)
	if wifiInfo.Wireless && wifiInfo.SSID != "" {
		fmt.Fprintf(os.Stderr, "shardflowd: wifi assoc → ssid=%q bssid=%s signal=%ddBm\n",
			wifiInfo.SSID, wifiInfo.BSSID, wifiInfo.SignalDBm)
	} else if wifiInfo.Wireless {
		fmt.Fprintln(os.Stderr, "shardflowd: wifi iface present but not associated — skipping SSID probe")
	}

	deps = &rpc.HandlerDeps{
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
		Session: func() rpc.SessionDTO {
			lastAt, replies := stats.snapshot()
			cidrStr := ""
			if info.IPNet != nil {
				cidrStr = info.IPNet.String()
			}
			gwStr := ""
			if info.Gateway != nil {
				gwStr = info.Gateway.String()
			}
			lastAtStr := ""
			if !lastAt.IsZero() {
				lastAtStr = lastAt.Format(time.RFC3339)
			}
			// AP isolation detection: on a wireless iface with a
			// successful scan, zero or exactly 1 non-self reply means
			// other clients are unreachable — the AP is filtering
			// intra-client traffic. ARP poison frames won't reach
			// victims.
			apIso := wifiInfo.Wireless && replies <= 1
			// Check whether send_redirects is currently enforced.
			// The daemon sets these at startup, but NetworkManager
			// or systemd-networkd may reset them on link events.
			redirectsOn := legacySysctlGet("net/ipv4/conf/" + info.Name + "/send_redirects") != "0"
			fwdOn := legacySysctlGet("net/ipv4/ip_forward") == "1"

			return rpc.SessionDTO{
				Iface:              info.Name,
				MAC:                info.HwAddr.String(),
				IP:                 info.IP.String(),
				CIDR:               cidrStr,
				Gateway:            gwStr,
				GwMAC:              gwMAC.String(),
				Wireless:           wifiInfo.Wireless,
				SSID:               wifiInfo.SSID,
				BSSID:              wifiInfo.BSSID,
				SignalDBm:          wifiInfo.SignalDBm,
				TxRateMbit:         wifiInfo.TxRateMbit,
				FreqMHz:            wifiInfo.FreqMHz,
				PoisonsActive:      len(arp.Active()),
				ArpWriteFailures:   arp.WriteFailures(),
				ApIsolationLikely:  apIso,
				SendRedirectsActive: redirectsOn,
				ForwardingEnabled:  fwdOn,
				DevicesTotal:       len(store.List()),
				LastScanAt:         lastAtStr,
				LastScanReplies:    replies,
			}
		},
	}
	handlers := rpc.BuildHandlers(deps)
	srv = rpc.NewServer(handlers)

	go func() {
		ch := store.Subscribe()
		defer store.Unsubscribe(ch)
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-ch:
				if !ok {
					return
				}
				var method string
				switch ev.Kind {
				case devicestore.EventDiscovered:
					method = rpc.EventDeviceDiscovered
				case devicestore.EventEvicted:
					method = rpc.EventDeviceEvicted
				default:
					method = rpc.EventDeviceUpdated
				}
				dto := rpc.DeviceDTO{
					MAC:      ev.Device.MAC.String(),
					IP:       ev.Device.IP.String(),
					Hostname: ev.Device.Hostname,
					Vendor:   ev.Device.Vendor,
					Model:    ev.Device.Model,
					LastSeen: ev.Device.LastSeen.Format(time.RFC3339),
				}
				srv.Broadcast(method, dto)
			}
		}
	}()

	// Periodic eviction sweep. 30 min TTL, swept every minute. Devices
	// with active policies are preserved regardless. This bounds memory
	// on long-running sessions (a Wi-Fi sniff seeing privacy-randomised
	// MACs from a coffee shop's worth of phones grew unbounded otherwise).
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		const deviceTTL = 30 * time.Minute
		// hasPolicy gives Evict authoritative policy state — the
		// compiler.Snapshot is the source of truth (nothing populates
		// the prior store-side Policy field). Without this, a target
		// under active drop/throttle/pcap that goes idle for >TTL
		// would be evicted from the device map (TUI row vanishes,
		// ResolveIP starts failing for the policy command) while the
		// poison goroutine keeps running — a confusing operational
		// state. Snapshot is locked internally; safe to call from the
		// closure even while Evict holds the store lock.
		hasPolicy := func(mac string) bool {
			_, ok := comp.Snapshot()[mac]
			return ok
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = store.Evict(time.Now(), deviceTTL, hasPolicy)
			}
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
				// Skip the heartbeat when no client is around to
				// receive it. The TUI uses this to anchor its
				// "daemon alive" indicator, so we only need to send
				// when at least one consumer cares.
				if srv.HasClients() {
					srv.Broadcast(rpc.EventCountersTick, map[string]any{"ts": time.Now().Unix()})
				}
			}
		}
	}()

	// Periodic sysctl guard: NetworkManager and systemd-networkd can reset
	// send_redirects back to defaults when a link flaps or a DHCP renewal
	// touches the interface. Check every 10s and re-disable if necessary.
	// Dormant when no policies are active — redirects being on doesn't
	// matter when we're not MITMing anyone.
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if len(arp.Active()) == 0 {
					continue
				}
				if v := legacySysctlGet("net/ipv4/conf/all/send_redirects"); v != "" && v != "0" {
					_, _ = writeSysctl("/proc/sys/net/ipv4/conf/all/send_redirects", "0")
				}
				if v := legacySysctlGet("net/ipv4/conf/" + info.Name + "/send_redirects"); v != "" && v != "0" {
					_, _ = writeSysctl("/proc/sys/net/ipv4/conf/"+info.Name+"/send_redirects", "0")
				}
				if v := legacySysctlGet("net/ipv4/ip_forward"); v != "" && v != "1" {
					_, _ = writeSysctl("/proc/sys/net/ipv4/ip_forward", "1")
				}
			}
		}
	}()

	fmt.Fprintf(os.Stderr, "shardflowd: listening on %s\n", *sockFlag)
	if err := srv.Listen(ctx, *sockFlag); err != nil {
		return err
	}
	return nil
}
