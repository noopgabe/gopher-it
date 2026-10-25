package trace

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func Run(ctx context.Context, opts Options) error {
	if opts.ImportPcap != "" {
		return ImportPcap(opts.ImportPcap, opts)
	}
	return LiveCapture(ctx, opts)
}

func ImportPcap(path string, opts Options) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	reader, err := pcapgo.NewReader(f)
	if err != nil {
		return err
	}
	linkType := reader.LinkType(0)
	n := 0
	for {
		data, ci, err := reader.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("Read packet %d: %w", n, err)
		}
		_ = ci
		packet := gopacket.NewPacket(data, linkType, gopacket.Default)
		fmt.Println(DecodePacket(packet))
		n++
		if n >= limit {
			break
		}
	}
	fmt.Printf("Read %d packets.\n", n)
	return nil
}

func WritePcap(path string, packets []gopacket.Packet) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return err
	}
	for _, p := range packets {
		ci := p.Metadata().CaptureInfo
		if ci.Timestamp.IsZero() {
			ci.Timestamp = time.Now()
		}
		if err := w.WritePacket(ci, p.Data()); err != nil {
			return err
		}
	}
	return nil
}
