package hostnet

import (
	"fmt"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/tools"
	"github.com/coreos/go-iptables/iptables"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	"net"
	"strings"
	"syscall"
)

var IP4Mask = []byte{0xff, 0xff, 0xff, 0xff}
var IP6Mask = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

type IqIp struct {
	addr *net.IPNet

	protocol Proto
	error    error
}

func newList(ips []string, out interface{}) {
	var iqIp *IqIp
	for _, ip := range ips {
		iqIp = NewIP(ip)
		if iqIp.error == nil {
			switch out := out.(type) {
			case *[]*net.IPNet:
				*out = append(*out, iqIp.ToIPNet())
			case *[]net.IP:
				*out = append(*out, iqIp.ToIP())
			}
		}
	}
}

func NewIPList(ips []string) (out []net.IP) {
	newList(ips, &out)
	return
}

func NewIPNetList(ips []string) (out []*net.IPNet) {
	newList(ips, &out)
	return
}

func NewIP(in interface{}) *IqIp {
	var ipn *net.IPNet
	var ip *IqIp

	switch inTyped := in.(type) {
	case Proto:
		return &IqIp{protocol: inTyped}
	case *net.IPNet:
		ipn = inTyped
	case net.IPNet:
		ipn = &inTyped
	case *IqIp:
		return inTyped
	default:
		ipn = &net.IPNet{}
	}

	ip = &IqIp{addr: ipn}

	switch inTyped := in.(type) {
	case string:
		if strings.Contains(inTyped, "/") {
			ip.error = ip.fromCIDR(inTyped)
		} else {
			ip.fromIP(net.ParseIP(inTyped))
		}
	case net.IP:
		ip.fromIP(inTyped)
	}

	assignProtocol(ip)
	return ip
}

func (xip *IqIp) fromIP(ip net.IP) *IqIp {
	xip.addr.IP = ip
	return xip
}

func (xip *IqIp) fromCIDR(addr string) error {
	ip, ipnet, err := net.ParseCIDR(addr)
	if err != nil {
		xip.error = err
		return fmt.Errorf("can't parse string %s", err)
	}

	xip.addr.IP = ip
	xip.addr.Mask = ipnet.Mask
	return nil
}

func (xip *IqIp) ToBgpPrefix() bgp.AddrPrefixInterface {
	size, _ := xip.addr.Mask.Size()

	if xip.protocol == V4 {
		return bgp.NewIPAddrPrefix(uint8(size), xip.addr.IP.String())
	} else {
		return bgp.NewIPv6AddrPrefix(uint8(size), xip.addr.IP.String())
	}
}

func (xip *IqIp) ToBgpRouteAttrs(toAdvertise ...interface{}) bgp.PathAttributeInterface {
	if V4 == xip.protocol {
		return bgp.NewPathAttributeNextHop(xip.ToIP().String())
	}
	return bgp.NewPathAttributeMpReachNLRI(xip.ToIP().String(), xip.ToBgpPrefixArray(toAdvertise...))
}

func (xip *IqIp) ToBgpPrefixArray(toAdvertise ...interface{}) []bgp.AddrPrefixInterface {
	paths := make([]bgp.AddrPrefixInterface, 0)
	for _, ip := range toAdvertise {
		switch in := ip.(type) {
		case string:
			paths = append(paths, NewIP(in).ToBgpPrefix())
		case []string:
			for _, s := range in {
				paths = append(paths, NewIP(s).ToBgpPrefix())
			}
		case *IqIp:
			paths = append(paths, in.ToBgpPrefix())
		default:
		}
	}
	return paths
}

func (xip *IqIp) ToPolicyPrefix() *config.Prefix {
	return &config.Prefix{IpPrefix: xip.ToCIDR()}
}

func (xip *IqIp) ToString() string {
	return xip.String()
}

func (xip *IqIp) String() string {
	return xip.ToCIDR()
}

func (xip *IqIp) ToCIDR() string {
	return xip.addr.String()
}

func (xip *IqIp) ToIpvsNetmask() uint32 {
	if xip.protocol == V4 {
		return 0xffffffff
	} else {
		return 128
	}
}

func (xip *IqIp) ToStringWithPort(port uint16) string {
	if xip.protocol == V4 {
		return xip.ToIP().String() + ":" + fmt.Sprint(port)
	}
	return "[" + xip.ToIP().String() + "]:" + fmt.Sprint(port)
}

func (xip *IqIp) ToIP() net.IP {
	return xip.addr.IP
}

func (xip *IqIp) ToIPNet() *net.IPNet {
	return xip.addr
}

func (xip *IqIp) IptProtocol() iptables.Protocol {
	return iptables.Protocol(xip.protocol)
}

func (xip *IqIp) Protocol() Proto {
	return xip.protocol
}

func (xip *IqIp) ToError() error {
	return xip.error
}
func (xip *IqIp) Family() uint16 {
	if xip.IsIPv4() {
		return syscall.AF_INET
	}
	return syscall.AF_INET6
}

type IpCmdParams struct {
	Inet, Mode, IptCmd, IcmpStr, TunnelProto string
	ReduceMTU                                int
}

// lets calculate with gre(6)tap although we use ip(6)tnl
// reducemtu - ipv4 = tcp header (20) + eth header (8)
// reducemtu - ipv6 = tcp header (40) + eth header (8)
func (xip *IqIp) ProtocolCmdParam() *IpCmdParams {
	if xip.protocol == V4 {
		return &IpCmdParams{ReduceMTU: 28, Inet: "-4", Mode: "ipip", TunnelProto: "4", IptCmd: tools.GetExecPath("iptables"), IcmpStr: "icmp"}
	}
	return &IpCmdParams{ReduceMTU: 48, Inet: "-6", Mode: "ip6ip6", TunnelProto: "41", IptCmd: tools.GetExecPath("ip6tables"), IcmpStr: "icmpv6"}
}

func (xip *IqIp) Contains(in interface{}) bool {
	switch check := in.(type) {
	case *IqIp:
		return xip.addr.Contains(check.ToIP())
	case net.IP:
		return xip.addr.Contains(check)
	case *net.IP:
		return xip.addr.Contains(*check)
	case *net.IPNet:
		return xip.addr.Contains(check.IP)
	}
	return false
}

func (xip *IqIp) IsIPv4() bool {
	return xip.protocol == V4
}

func assignProtocol(xip *IqIp) {
	if Isipv4(xip.addr.IP) {
		xip.protocol = V4
	} else {
		xip.protocol = V6
	}
	if xip.addr.Mask != nil {
		return
	}

	switch xip.protocol {
	case V4:
		xip.addr.Mask = IP4Mask
	case V6:
		xip.addr.Mask = IP6Mask
	}
}

func Isipv4(ip net.IP) bool {
	return ip.To4() != nil
}
