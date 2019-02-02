package netutils

import (
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/vishvananda/netlink"
	"net"
	"strings"
	"syscall"
)

var IP4Mask = []byte{0xff, 0xff, 0xff, 0xff}
var IP6Mask = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

type IqIp struct {
	addr *net.IPNet

	protocol Proto
	error    *error
}

func NewList(ips []string) []*net.IPNet {
	var out []*net.IPNet
	for _, ip := range ips {
		out = append(out, NewIP(ip).ToIPNet())
	}
	return out
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
			ip.fromCIDR(inTyped)
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
		return fmt.Errorf("Can't get address %s", err)
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
		return bgp.NewPathAttributeNextHop(xip.ToString())
	}
	return bgp.NewPathAttributeMpReachNLRI(xip.ToString(), xip.ToBgpPrefixArray(toAdvertise...))
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
	return xip.addr.IP.String()
}

func (xip *IqIp) String() string {
	return xip.ToCIDR()
}

func (xip *IqIp) ToCIDR() string {
	return xip.addr.String()
}

func (xip *IqIp) ToSubnet() string {
	return xip.addr.IP.String()
}

func (xip *IqIp) ToNetmaskHex() string {
	return xip.addr.Mask.String()
}

func (xip *IqIp) ToIpvsNetmask() uint32 {
	if xip.protocol == V4 {
		return 0xffffffff
	} else {
		return 128
	}
}

func (xip *IqIp) ToPrefix() int {
	prefix, _ := xip.addr.Mask.Size()
	return prefix
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
	return *xip.error
}
func (xip *IqIp) Family() uint16 {
	if xip.protocol == V4 {
		return syscall.AF_INET
	}
	return syscall.AF_INET6
}

func (xip *IqIp) NetlinkFamily() uint16 {
	if xip.protocol == V4 {
		return netlink.FAMILY_V4
	}
	return netlink.FAMILY_V6
}

type IpCmdParams struct {
	Inet, Mode, IptCmd, IcmpStr string
}

func (xip *IqIp) ProtocolCmdParam() *IpCmdParams {
	if xip.protocol == V4 {
		return &IpCmdParams{Inet: "-4", Mode: "ipip", IptCmd: "iptables", IcmpStr: "icmp"}
	}
	return &IpCmdParams{Inet: "-6", Mode: "ip6ip6", IptCmd: "ip6tables", IcmpStr: "icmpv6"}
}

func (xip *IqIp) Contains(in interface{}) bool {
	switch check := in.(type) {
	case *IqIp:
		return xip.addr.Contains(check.ToIP())
	case net.IP:
	case *net.IP:
		return xip.Contains(NewIP(check))
	}
	return false
}

func (xip *IqIp) IsIPv4() bool {
	return Isipv4(xip.addr.IP)
}

func assignProtocol(xip *IqIp) {
	if xip.IsIPv4() {
		xip.protocol = V4
	} else {
		xip.protocol = V6
	}
	if xip.addr.Mask == nil {
		if xip.IsIPv4() {
			xip.addr.Mask = IP4Mask
		} else {
			xip.addr.Mask = IP6Mask
		}
	}
}

func Isipv4(ip net.IP) bool {
	return strings.Count(ip.String(), ":") < 2
}
