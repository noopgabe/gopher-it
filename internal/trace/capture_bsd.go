//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package trace

import (
	"context"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"golang.org/x/sys/unix"
)

func LiveCapture(ctx context.Context, opts Options) error {
	if opts.Iface == "" || opts.Iface == "any" {
		return fmt.Errorf("Live capture requires a real interface, e.g., en0")
	}
	fd, lt, err := openBPF(opts.Iface)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	// non-fatal: some interfaces just refuse promiscuous mode. promiscuous mode wherever you are
	_ = bpfIoctl(fd, unix.BIOCPROMISC, nil)

	if err := unix.SetNonblock(fd, true); err != nil {
		return fmt.Errorf("Nonblock: %w", err)
	}
	bufLen, err := bpfGetUint(fd, unix.BIOCGBLEN)
	if err != nil {
		return fmt.Errorf("BIOCBLEN: %w", err)
	}
	buf := make([]byte, bufLen)

	timeout := time.Duration(opts.Duration) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := time.Now().Add(timeout)

	var collected []gopacket.Packet
	count := 0
	done := false
	for time.Now().Before(deadline) && !done {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		n, err := unix.Read(fd, buf)
		if err == unix.EAGAIN || err == unix.EINTR {
			time.Sleep(20 * time.Millisecond)
			continue // im blindly typing code in im so tired
		}
		if err != nil {
			return fmt.Errorf("Capture: %w", err)
		}
		bpfEach(buf[:n], func(ts time.Time, frame []byte) {
			if done {
				return
			}
			data := append([]byte(nil), frame...)
			packet := gopacket.NewPacket(data, lt, gopacket.Default)
			packet.Metadata().CaptureInfo = gopacket.CaptureInfo{
				Timestamp:     ts,
				CaptureLength: len(data),
				Length:        len(data),
			}
			if !MatchFilter(packet, opts.Filter) {
				return
			}
			fmt.Println(DecodePacket(packet))
			collected = append(collected, packet)
			count++
			if opts.Count > 0 && count >= opts.Count {
				done = true
			}
		})
	}
	fmt.Printf("Captured %d packets\n", count)
	if opts.ExportPcap != "" {
		return WritePcap(opts.ExportPcap, collected)
	}
	return nil
}
