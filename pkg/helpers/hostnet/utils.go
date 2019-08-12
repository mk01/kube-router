package hostnet

import (
	"net"

	"bytes"
	"errors"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/tools"
	"github.com/golang/glog"
	"github.com/google/go-cmp/cmp"
	"github.com/vishvananda/netlink"
	"os/exec"
	"strings"
)

type FilterOperation byte

const (
	ExcludePattern FilterOperation = 1 << iota
	IncludePattern
	MatchPattern
)

type InterfaceMatchFunctionType struct {
	fn     func(string, string) bool
	result bool
}

type InterfaceFilterOperationMapType map[FilterOperation]InterfaceMatchFunctionType

var IntefaceFilterOperationMap = InterfaceFilterOperationMapType{
	MatchPattern:   {func(a, b string) bool { return strings.Compare(a, b) == 0 }, false},
	ExcludePattern: {strings.Contains, true},
	IncludePattern: {strings.Contains, false},
}

func getIPWithSubnet(linkFilter func(p net.Interface) bool, ip net.IP) (*IqIp, string, error) {
	links, err := net.Interfaces()
	if err != nil {
		return NewIP(ip), "", errors.New("Failed to get list of links")
	}
	for _, link := range links {
		if !linkFilter(link) || link.Name == "kube-dummy-if" {
			continue
		}
		addresses, err := link.Addrs()
		if err != nil {
			return NewIP(ip), "", errors.New("Failed to get list of addr")
		}
		for _, addr := range addresses {
			if iqip := NewIP(addr.String()); iqip.ToIP().Equal(ip) {
				glog.V(3).Infof("Found ip %s on %s", ip.String(), link.Name)
				return iqip, link.Name, nil
			}
		}
	}
	return NewIP(ip), "", errors.New("Failed to find interface with specified node ip")
}

func GetIPWithSubnet(ip net.IP) (*net.IPNet, string, error) {
	ipnet, link, err := getIPWithSubnet(tools.FilterInterfaces, ip)
	return ipnet.ToIPNet(), link, err
}

func GetInterfaceMACAddress(ifName string) string {
	return GetInterfaceAttribute(ifName, MAC).(string)
}

func GetInterfaceMTU(ifName string) int {
	return GetInterfaceAttribute(ifName, MTU).(int)
}

type ifAttributes byte

const (
	MTU ifAttributes = 1 << iota
	MAC
)

func GetInterfaceAttribute(ifName string, attr ifAttributes) interface{} {
	mtu := 1500
	hwaddr := "00:00:00:00:00:00"

	if link, _ := net.InterfaceByName(ifName); link != nil {
		mtu = link.MTU
		hwaddr = link.HardwareAddr.String()
	}

	switch attr {
	case MTU:
		return mtu
	case MAC:
		return hwaddr
	}

	return nil
}

// with IPv6 things work differently from v4. Prefix (what v4 calls subnet mask) is not
// considered part of IP, device owning particular IP can be moving accross different
// networks and keeping own IP and network has to assure proper handover when changing
// to other network and of course reachibility of the client while hosting the device
// (e.g. IPv6 Mobility extensions.
// This has a consequence that while passive address configuration assigns IP and the
// appropriate Prefix length (as the IP is in this case part of the Prefix, state-full
// IP configuration (DHCPv6) assigns just IP (/128) while expecting the routes and
// link-local IPv6 address used for that is configured by the network via Router Advertisements
// etc
// We could check if the currently hosting prefix is our home prefix and use it's size when
// calling subnet.Contains(IP), but this would miss cases when the target IP is being hosted
// inside our prefix range and test would mark the IP as remote, although it would be accessible
// without hoping routers.
// There are few ways coming to my mind:
// - check IPv6 neighbor table
// - get route for target and check if it is device route or contains router reference
// - try tracing hops to target
//
// lets go with route check
func CheckIPisLinkLocalReachable(ip net.IP) bool {
	out, err := exec.Command(tools.GetExecPath("ip"), NewIP(ip).ProtocolCmdParam().Inet, "route", "get", ip.String()).CombinedOutput()
	if err == nil && bytes.Contains(out, []byte(ip.String())) && !bytes.Contains(out, []byte(" via ")) {
		return true
	} else if err != nil {
		glog.Errorf("Can't check same subnet for %s. ERR: %s", ip.String(), err.Error())
	}
	return false
}

// returns all IP addresses found on any network address in the system, excluding dummy and docker interfaces
func GetAllLocalIPs(filterOp FilterOperation, names ...string) (localAddrs []*net.IPNet, err error) {
	var goNext bool

	links, _ := net.Interfaces()
	for _, link := range links {

		if !tools.FilterInterfaces(link) {
			continue
		}

		goNext = false
		for _, name := range names {
			if IntefaceFilterOperationMap[filterOp].fn(link.Name, name) == IntefaceFilterOperationMap[filterOp].result {
				goNext = true
				break
			}
		}

		if goNext {
			continue
		}

		addrs, _ := link.Addrs()
		for _, addr := range addrs {
			ip := NewIP(addr)
			if ip.ToIP().IsLinkLocalUnicast() {
				continue
			}
			localAddrs = append(localAddrs, ip.ToIPNet())
		}
	}
	return
}

func DelNetlinkInterface(link netlink.Link) (err error) {
	if link == nil {
		return
	}

	if err = netlink.LinkDel(link); err != nil {
		glog.Errorf("Error removing interface %s", link.Attrs().Name)
		return tools.NewError(err.Error())
	}

	glog.Infof("Successfully removed interface %s", link.Attrs().Name)
	return
}

var RouteComparer = cmp.Comparer(RouteEqual)

func RouteEqual(x, r netlink.Route) bool {
	return r.LinkIndex == x.LinkIndex &&
		r.Dst.String() == x.Dst.String() &&
		r.Src.Equal(x.Src) &&
		r.Gw.Equal(x.Gw) &&
		r.Protocol == x.Protocol
}
