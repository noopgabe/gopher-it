package trace

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func htons(v uint16) uint16 { return (v << 8) | (v >> 8) }

func LiveCapture(ctx context.Context, opts Options) error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0003)))
	if err != nil {
		return err
	}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 0, Usec: 500000})
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

	var collected []gopacket.Packet
	count := 0
	limit := opts.Count
	timeout := time.Duration(opts.Duration) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := time.Now().Add(timeout)

	buf := make([]byte, 65536)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if isRetryableRecv(err) {
				continue
			}
			return fmt.Errorf("Capture: %w", err)
		}
		if n <= 0 {
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		ci := gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: n, Length: n}
		packet := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Default)
		packet.Metadata().CaptureInfo = ci
		if !MatchFilter(packet, opts.Filter) {
			continue
		}
		fmt.Println(DecodePacket(packet))
		collected = append(collected, packet)
		count++
		if limit > 0 && count >= limit {
			break
		}
	}
	fmt.Printf("Captured %d packets\n", count)
	if opts.ExportPcap != "" {
		return WritePcap(opts.ExportPcap, collected)
	}
	return nil
}

func isRetryableRecv(err error) bool {
	return errors.Is(err, syscall.EAGAIN) ||
		errors.Is(err, syscall.EWOULDBLOCK) ||
		errors.Is(err, syscall.EINTR)
}
