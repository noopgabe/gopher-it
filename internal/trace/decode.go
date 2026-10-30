package trace

import (
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func DecodePacket(p gopacket.Packet) string {
	src, dst := "?", "?"
	if ip4 := p.Layer(layers.LayerTypeIPv4); ip4 != nil {
		i := ip4.(*layers.IPv4)
		src, dst = i.SrcIP.String(), i.DstIP.String()
	}
	if ip6 := p.Layer(layers.LayerTypeIPv6); ip6 != nil {
		i := ip6.(*layers.IPv6)
		src, dst = i.SrcIP.String(), i.DstIP.String()
	}
	proto := "other"
	if p.Layer(layers.LayerTypeTCP) != nil {
		proto = "TCP"
	}
	if p.Layer(layers.LayerTypeUDP) != nil {
		proto = "UDP"
	}
	if p.Layer(layers.LayerTypeICMPv4) != nil || p.Layer(layers.LayerTypeICMPv6) != nil {
		proto = "ICMP"
	}
	info := ""
	if tcp := p.Layer(layers.LayerTypeTCP); tcp != nil {
		t := tcp.(*layers.TCP)
		var flags []string
		if t.SYN {
			flags = append(flags, "SYN")
		}
		if t.ACK {
			flags = append(flags, "ACK")
		}
		if t.FIN {
			flags = append(flags, "FIN")
		}
		if t.RST {
			flags = append(flags, "RST")
		}
		info = fmt.Sprintf("Sport=%d Dport=%d Flags=%s", t.SrcPort, t.DstPort, strings.Join(flags, ","))
	}
	if udp := p.Layer(layers.LayerTypeUDP); udp != nil {
		u := udp.(*layers.UDP)
		info = fmt.Sprintf("Sport=%d Dport=%d", u.SrcPort, u.DstPort)
	}
	return fmt.Sprintf("%s -> %s %s %s", src, dst, proto, info)
}

// matchfilter applies a very minimal case-INsensitive protocol filter
// empty expressions match everything
func MatchFilter(p gopacket.Packet, expr string) bool {
	if expr == "" {
		return true
	}
	l := strings.ToLower(expr)
	if strings.Contains(l, "tcp") && p.Layer(layers.LayerTypeTCP) == nil {
		return false
	}
	if strings.Contains(l, "udp") && p.Layer(layers.LayerTypeUDP) == nil {
		return false
	}
	if strings.Contains(l, "icmp") && p.Layer(layers.LayerTypeICMPv4) == nil && p.Layer(layers.LayerTypeICMPv6) == nil {
		return false
	}
	return true
}
