//go:build linux

package trace

import (
	"context"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/google/gopacket/pcapgo"
)

func ReplayPcap(ctx context.Context, opts Options) error {
	f, err := os.Open(opts.ImportPcap)
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		return err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0003))) // i prefer my socks cooked
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if opts.Iface != "" && opts.Iface != "any" {
		ifi, err := net.InterfaceByName(opts.Iface)
		if err != nil {
			return err
		}
		addr := syscall.SockaddrLinklayer{Protocol: htons(0x0003), Ifindex: ifi.Index}
		if err := syscall.Bind(fd, &addr); err != nil {
			return err
		}
	}
	for {
		data, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		if _, err := syscall.Write(fd, data); err != nil {
			return err
		}
		time.Sleep(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
	fmt.Println("Replay complete.")
	return nil
}

func ArpSpoof(iface, targetIP, gatewayIP string) error {
	return fmt.Errorf("ARP spoofing requires --i-am-a-buffoon and is not yet implemented") // im too lazy to implement
}
