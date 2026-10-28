// ip-info: IP adresi hakkında ağ bilgisi sunar: sınıf, özel/genel,
// loopback, CIDR hesaplama.
//
// Kullanım:
//   ip-info 192.168.1.100
//   ip-info 10.0.0.0/24
//   ip-info 2001:db8::1
package main

import (
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
)

func ipClass(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil { return "IPv6" }
	b := ip4[0]
	switch {
	case b < 128: return "A"
	case b < 192: return "B"
	case b < 224: return "C"
	case b < 240: return "D (Multicast)"
	default: return "E (Reserved)"
	}
}

func isPrivate(ip net.IP) bool {
	for _, cidr := range []string{"10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","fc00::/7"} {
		_, n, _ := net.ParseCIDR(cidr)
		if n.Contains(ip) { return true }
	}
	return false
}

func broadcastAddr(network *net.IPNet) net.IP {
	ip := network.IP.To4()
	if ip == nil { return nil }
	mask := network.Mask
	bc := make(net.IP, 4)
	for i := range bc { bc[i] = ip[i] | ^mask[i] }
	return bc
}

func analyzeIP(s string) {
	hasCIDR := strings.Contains(s, "/")
	ip := net.ParseIP(strings.Split(s, "/")[0])
	if ip == nil {
		fmt.Fprintf(os.Stderr, "Geçersiz IP: %s\n", s)
		return
	}
	isV4 := ip.To4() != nil
	fmt.Printf("IP Adresi    : %s\n", ip)
	fmt.Printf("Sürüm        : %s\n", func() string { if isV4 { return "IPv4" }; return "IPv6" }())
	if isV4 { fmt.Printf("Sınıf        : %s\n", ipClass(ip)) }
	fmt.Printf("Özel         : %v\n", isPrivate(ip))
	fmt.Printf("Loopback     : %v\n", ip.IsLoopback())
	fmt.Printf("Multicast    : %v\n", ip.IsMulticast())
	fmt.Printf("Link-local   : %v\n", ip.IsLinkLocalUnicast())

	if hasCIDR {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil { fmt.Println("CIDR hatası:", err); return }
		ones, bits := ipNet.Mask.Size()
		hostBits := bits - ones
		hosts := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(hostBits)), nil)
		usable := new(big.Int).Sub(hosts, big.NewInt(2))
		if usable.Sign() < 0 { usable = big.NewInt(0) }
		fmt.Printf("\nCIDR Analizi : /%d\n", ones)
		fmt.Printf("Ağ Adresi    : %s\n", ipNet.IP)
		if isV4 {
			bc := broadcastAddr(ipNet)
			if bc != nil { fmt.Printf("Broadcast    : %s\n", bc) }
			mask := net.IP(ipNet.Mask)
			fmt.Printf("Alt Ağ Maskesi: %s\n", mask)
		}
		fmt.Printf("Kullanılabilir Host: %s\n", usable.String())
	}
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Println("Kullanım: ip-info <ip[/prefix]> [ip2 ...]")
		return
	}
	for i, arg := range args {
		if i > 0 { fmt.Println(strings.Repeat("-", 40)) }
		analyzeIP(arg)
	}
}
