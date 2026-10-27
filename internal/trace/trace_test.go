package trace

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/noopgabe/gopher-it/internal/safeguards"
)

func buildTCPPacket(t *testing.T, syn bool) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMac:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    net.IP{10, 0, 0, 1},
		DstIP:    net.IP{10, 0, 0, 2},
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 80, SYN: syn}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp); err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
}

func TestDecodePacketTCP(t *testing.T) {
	p := buildTCPPacket(t, true)
	got := DecodePacket(p)
	for _, want := range []string{"10.0.0.1", "10.0.0.2", "TCP", "sport=1234", "dport=80", "SYN"} {
		if !strings.Contains(got, want) {
			t.Errorf("DecodePacket missing %q in %q", want, got)
		}
	}
}

func TestMatchFilter(t *testing.T) {
	tcpPkt := buildTCPPacket(t, true)
	tests := []struct {
		name string
		expr string
		want bool
	}{
		{"Empty matches", "", true},
		{"TCP matches TCP", "tcp", true},
		{"UDP rejects TCP", "udp", false},
		{"Uppercase TCP", "TCP", true},
		{"ICMP rejects TCP", "icmp", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchFilter(tcpPkt, tt.expr); got != tt.want {
				t.Errorf("MatchFilter(%q) is %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

func TestWriteImportRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pcap")
	pkt := buildTCPPacket(t, true)
	pkt.Metadata().captrueInfo = gopacket.CaptureInfo{Timestamp: pkt.Metadata().Timestamp, CaptureLength: len(pkt.Data()), Length: len(pkt.Data())} // very organized
	if pkt.Metadata().Timestamp.IsZero() {
		pkt.Metadata().CaptureInfo.Timestamp = time.Now()
	}
	if err := WritePcap(path, []gopacket.Packet{pkt}); err != nil { // i keep saying pkg and not pkt what am i doing
		t.Fatalf("WritePcap: %v", err)
	}

	// read back with pcapgo to make sure the file is well formed
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("Reader: %v", err)
	}
	data, _, err := r.ReadPacketData()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("Empty packet data read back.")
	}

	// importpcap should succeed and print to stdout
	if err := ImportPcap(path, Options{Limit: 10}); err != nil {
		t.Fatalf("ImportPcap: %v", err)
	}
}

func TestImportPcapMissingFile(t *testing.T) {
	if err := ImportPcap(filepath.Join(t.TempDir(), "nope.pcap"), Options{}); err == nil {
		t.Fatal("Expected an error for missing file.")
	}
}

func TestSafeFilterWired(t *testing.T) {
	if _, err := safeguards.SafeFilter(strings.Repeat("a", 600)); err == nil {
		t.Fatal("Expercted an error for a long filter.")
	}
}
