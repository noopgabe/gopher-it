//go:build !linux

package trace

import (
	"context"
	"fmt"
)

func ReplayPcap(ctx context.Context, opts Options) error {
	return fmt.Errorf("Packet injection requires Linux.")
}

func ArpSpoof(iface, targetIP, gatewayIP string) error {
	return fmt.Errorf("Arp spoofing requires Linux.") // LIES it's not even implemented yet
}
