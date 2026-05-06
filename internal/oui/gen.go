//go:build generate
// +build generate

package oui

//go:generate sh -c "curl -s https://standards-oui.ieee.org/oui/oui.txt | awk '/\\(base 16\\)/ { gsub(\"-\", \"\", $$1); print $$1, substr($$0, index($$0,\"(base 16)\")+11) }' > data/oui.txt"
