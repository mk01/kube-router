package routing

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/cloudnativelabs/kube-router/pkg/utils/net-tools"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
)

// Used for processing Annotations that may contain multiple items
// Pass this the string and the delimiter
func stringToSlice(s, d string) []string {
	ss := make([]string, 0)
	if strings.Contains(s, d) {
		ss = strings.Split(s, d)
	} else {
		ss = append(ss, s)
	}
	return ss
}

func stringSliceToIPs(s []string) ([]net.IP, error) {
	ips := make([]net.IP, 0)
	for _, ipString := range s {
		ip := net.ParseIP(ipString)
		if ip == nil {
			return nil, fmt.Errorf("Could not parse \"%s\" as an IP", ipString)
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func stringSliceToUInt16(s []string) ([]uint16, error) {
	ints := make([]uint16, 0)
	for _, intString := range s {
		newInt, err := strconv.ParseUint(intString, 0, 16)
		if err != nil {
			return nil, fmt.Errorf("Could not parse \"%s\" as an integer", intString)
		}
		ints = append(ints, uint16(newInt))
	}
	return ints, nil
}

func stringSliceToUInt32(s []string) ([]uint32, error) {
	ints := make([]uint32, 0)
	for _, intString := range s {
		newInt, err := strconv.ParseUint(intString, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("Could not parse \"%s\" as an integer", intString)
		}
		ints = append(ints, uint32(newInt))
	}
	return ints, nil
}

func stringSliceB64Decode(s []string) ([]string, error) {
	ss := make([]string, 0)
	for _, b64String := range s {
		decoded, err := base64.StdEncoding.DecodeString(b64String)
		if err != nil {
			return nil, fmt.Errorf("Could not parse \"%s\" as a base64 encoded string",
				b64String)
		}
		ss = append(ss, string(decoded))
	}
	return ss, nil
}

func getNodeSubnet(linkFilter func(p net.Interface) bool, nodeIP net.IP) (*netutils.IqIp, string, error) {
	links, err := net.Interfaces()
	if err != nil {
		return netutils.NewIP(nodeIP), "", errors.New("Failed to get list of links")
	}
	for _, link := range links {
		if !linkFilter(link) {
			continue
		}
		addresses, err := link.Addrs()
		if err != nil {
			return netutils.NewIP(nodeIP), "", errors.New("Failed to get list of addr")
		}
		for _, addr := range addresses {
			if ip := netutils.NewIP(addr.String()); ip.ToIP().Equal(nodeIP) {
				return ip, link.Name, nil
			}
		}
	}
	return netutils.NewIP(nodeIP), "", errors.New("Failed to find interface with specified node ip")
}

func getLinkAssignedPrefix(ip net.IP) (net.IPNet, string, error) {
	ipnet, link, err := getNodeSubnet(utils.FilterInterfaces, ip)
	if err != nil {
		return *ipnet.ToIPNet(), link, err
	}

	if netutils.NewIP(ip).IsIPv4() {
		return *ipnet.ToIPNet(), link, nil
	}

	ifnet, err := net.InterfaceByName(link)
	if err != nil {
		return *ipnet.ToIPNet(), link, err
	}

	addrs, err := ifnet.Addrs()
	if err != nil {
		return *ipnet.ToIPNet(), link, err
	}

	for _, addr := range addrs {
		toCheck := netutils.NewIP(addr)
		if toCheck.IsIPv4() || !toCheck.ToIP().IsLinkLocalUnicast() {
			continue
		}

		split := strings.Split(addr.String(), "/")
		if len(split) > 1 {
			ipnet = netutils.NewIP(ip.String() + "/" + split[1])
		}
	}
	return *ipnet.ToIPNet(), link, nil
}

// generateTunnelName will generate a name for a tunnel interface given a node IP
// for example, if the node IP is 10.0.0.1 the tunnel interface will be named tun-10001
// Since linux restricts interface names to 15 characters, if length of a node IP
// is greater than 12 (after removing "."), then the interface name is tunXYZ
// as opposed to tun-XYZ
func generateTunnelName(nodeIP string) string {
	var deleteChar = "."
	ip := netutils.NewIP(nodeIP)

	if !ip.IsIPv4() {
		deleteChar = ":"
	}

	// canonize, remove "[:.]" and substring last 11 chars
	hash := strings.Replace(ip.ToString(), deleteChar, "", -1)
	if len(hash) > 11 {
		hash = hash[len(hash)-11:]
	}

	return "tun-" + hash
}

func getAfiSafiTypes(ip net.IP) []config.AfiSafiType {
	if netutils.NewIP(ip).IsIPv4() {
		return []config.AfiSafiType{config.AFI_SAFI_TYPE_IPV4_UNICAST}
	}
	return []config.AfiSafiType{config.AFI_SAFI_TYPE_IPV6_UNICAST, config.AFI_SAFI_TYPE_IPV4_UNICAST}
}

func injectAsiSafiConfigs(ip net.IP, bgpGracefulRestart bool, addTo []config.AfiSafi) {
	for _, AfiSafi := range getAfiSafiTypes(ip) {
		addTo = append(addTo, config.AfiSafi{
			Config: config.AfiSafiConfig{
				AfiSafiName: AfiSafi,
				Enabled:     true,
			},
			MpGracefulRestart: config.MpGracefulRestart{
				Config: config.MpGracefulRestartConfig{
					Enabled: bgpGracefulRestart,
				},
			},
		})
	}
}

func getPathAttributes(cidr *netutils.IqIp, node *netutils.IqIp) []bgp.PathAttributeInterface {
	return []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		node.ToBgpRouteAttrs(cidr),
	}
}
