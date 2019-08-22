package routing

import (
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"

	"errors"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/api"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/hostnet"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/tools"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/golang/glog"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"os/exec"
	"sync"

	gobgp "github.com/osrg/gobgp/server"
)

const tunnelInterfacePrefix = "tun-"
const kubeRouterInterfaceOwnerAlias = "kube-router"

// Used for processing Annotations that may contain multiple items
// Pass this the string and the delimiter
func stringToSlice(s, d string) []string {
	return strings.Split(s, d)
}

func stringSliceToIPs(s []string) ([]net.IP, error) {
	return hostnet.NewIPList(s), nil
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

// generateTunnelName will generate a name for a tunnel interface given a node IP
// for example, if the node IP is 10.0.0.1 the tunnel interface will be named tun-10001
// Since linux restricts interface names to 15 characters, if length of a node IP
// is greater than 12 (after removing "."), then the interface name is tunXYZ
// as opposed to tun-XYZ
func generateTunnelName(nodeIP string) string {
	var deleteChar = "."
	ip := hostnet.NewIP(nodeIP)

	if !ip.IsIPv4() {
		deleteChar = ":"
	}

	// canonize, remove "[:.]" and substring last 11 chars
	hash := strings.Replace(ip.ToIP().String(), deleteChar, "", -1)
	if len(hash) > 11 {
		hash = hash[len(hash)-11:]
	}

	return tunnelInterfacePrefix + hash
}

func removeUnusedOverlayTunnels(nrc *NetworkRoutingController) (err error) {
	var ifss []net.Interface
	if ifss, err = net.Interfaces(); err != nil || !nrc.bgpServerStarted {
		return
	}
	activeTunnelNames := getAllActiveTunnelNames(nrc.activeNodes)

	for _, netif := range ifss {
		if !strings.HasPrefix(netif.Name, tunnelInterfacePrefix) {
			continue
		}

		netlinkifs, _ := netlink.LinkByIndex(netif.Index)
		if netlinkifs == nil || netlinkifs.Attrs().Alias != kubeRouterInterfaceOwnerAlias {
			continue
		}

		if tools.CheckForElementInArray(netlinkifs.Attrs().Name, activeTunnelNames) && checkTunnelLocalAddress(nrc, netlinkifs) {
			continue
		}

		hostnet.DelNetlinkInterface(netlinkifs)
	}
	return
}

func checkTunnelLocalAddress(nrc *NetworkRoutingController, link interface{}) bool {
	switch linkTyped := link.(type) {
	case *netlink.Iptun:
		return linkTyped.Local.Equal(nrc.GetNodeIP().IP)
	case *netlink.Ip6tnl:
		return linkTyped.Local.Equal(nrc.GetNodeIP().IP) && linkTyped.Proto == 41
	}
	return false
}

func getAllActiveTunnelNames(nodes sync.Map) (tunNames []string) {
	nodes.Range(func(ip, value interface{}) bool {
		tunNames = append(tunNames, generateTunnelName(ip.(string)))
		return true
	})
	return
}

func (nrc *NetworkRoutingController) getRoutesByTemplate(template *netlink.Route, filter uint64) (routes []netlink.Route, err error) {
	if routes, err = netlink.RouteListFiltered(nl.FAMILY_ALL, template, filter|netlink.RT_FILTER_PROTOCOL); err != nil {
		return nil, fmt.Errorf("Can't list network routes %s", err.Error())
	}
	return
}

func getAfiSafiTypes(ip net.IP) []config.AfiSafiType {
	if hostnet.NewIP(ip).IsIPv4() {
		return []config.AfiSafiType{config.AFI_SAFI_TYPE_IPV4_UNICAST}
	}
	return []config.AfiSafiType{config.AFI_SAFI_TYPE_IPV6_UNICAST, config.AFI_SAFI_TYPE_IPV4_UNICAST}
}

func injectGrRestart(krConfig *options.KubeRouterConfig, neighbor *config.Neighbor, setState bool) {
	if !krConfig.BGPGracefulRestart {
		return
	}

	neighbor.GracefulRestart = config.GracefulRestart{
		Config: config.GracefulRestartConfig{
			Enabled:      true,
			DeferralTime: uint16(krConfig.BGPGracefulRestartDeferralTime.Seconds()),
		},
		State: config.GracefulRestartState{
			LocalRestarting: true,
		},
	}

	if setState {
		neighbor.GracefulRestart.State.DeferralTime = uint16(krConfig.BGPGracefulRestartDeferralTime.Seconds())
	}
}

func injectAsiSafiConfigs(ip net.IP, krConfig *options.KubeRouterConfig, addTo *[]config.AfiSafi) {
	for _, AfiSafi := range getAfiSafiTypes(ip) {
		*addTo = append(*addTo, config.AfiSafi{
			Config: config.AfiSafiConfig{
				AfiSafiName: AfiSafi,
				Enabled:     true,
			},
			MpGracefulRestart: config.MpGracefulRestart{
				Config: config.MpGracefulRestartConfig{
					Enabled: krConfig.BGPGracefulRestart,
				},
			},
		})
	}
}

func getPathAttributes(cidr *hostnet.IqIp, node *hostnet.IqIp) []bgp.PathAttributeInterface {
	return []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
		node.ToBgpRouteAttrs(cidr),
	}
}

func (nrc *NetworkRoutingController) buildRouteForDst(dst *net.IPNet, isSimple bool, nh net.IP, tunName string) *netlink.Route {
	route := &netlink.Route{
		Dst:      dst,
		Protocol: 0x11,
		Src:      nrc.GetNodeIP().IP,
	}

	// create IPIP tunnels only when node is not in same subnet or overlay-type is set to 'full'
	// prevent creation when --override-nexthop=true as well
	if !isSimple && !nrc.GetConfig().OverrideNextHop {
		route.LinkIndex = nrc.getLinkIndexByName(tunName, nh)
	} else {
		route.Gw = nh
	}
	tools.Eval(removeUnusedOverlayTunnels(nrc))
	return route
}

func (nrc *NetworkRoutingController) getLinkIndexByName(tunnelName string, nexthop net.IP) int {
	glog.V(2).Infof("Overlay route via %s", nexthop)
	link, err := nrc.ensureTunnel(tunnelName, nexthop)
	if err != nil {
		glog.Error(err)
		return -1
	}
	return link.Attrs().Index
}

func (nrc *NetworkRoutingController) ensureTunnel(tunnelName string, nexthop net.IP) (link netlink.Link, err error) {

	if link, err = netlink.LinkByName(tunnelName); err != nil || !checkTunnelLocalAddress(nrc, link) {
		la := netlink.NewLinkAttrs()
		la.Name = tunnelName

		tools.Eval(hostnet.DelNetlinkInterface(link))

		switch hostnet.NewIP(nrc.GetNodeIP()).Protocol() {
		case hostnet.V4:
			err = netlink.LinkAdd(&netlink.Iptun{LinkAttrs: la, Local: nrc.GetNodeIP().IP, Remote: nexthop})
		case hostnet.V6:
			err = netlink.LinkAdd(&netlink.Ip6tnl{LinkAttrs: la, Proto: 41, Local: nrc.GetNodeIP().IP, Remote: nexthop})
		}

		if err != nil {
			return nil, fmt.Errorf("Route not injected for the route advertised by the node %s "+
				"Failed to create tunnel interface %s. error: %s, output: %s",
				nexthop.String(), tunnelName, err.Error())
		}

		if link, err = netlink.LinkByName(tunnelName); err != nil {
			return nil, fmt.Errorf("Route not injected for the route advertised by the node %s "+
				"Failed to get tunnel interface by name error: %s", tunnelName, err)
		}
	} else {
		glog.Infof("Tunnel interface: " + tunnelName + " for the node " + nexthop.String() + " already exists.")
	}

	if err = netlink.LinkSetUp(link); err != nil {
		link = nil
		err = errors.New("Failed to bring tunnel interface " + tunnelName + " up due to: " + err.Error())
	} else {
		tools.Eval(netlink.LinkSetAlias(link, kubeRouterInterfaceOwnerAlias))
	}

	var out []byte
	var nodeCidr, _ = api.GetPodCidrFromCniSpec(nrc.cniConfFile)

	if out, err = exec.Command("ip", hostnet.NewIP(nexthop).ProtocolCmdParam().Inet, "r", "get", nexthop.String(), "from", nodeCidr.String()).
		CombinedOutput(); err != nil {
		return nil, fmt.Errorf("Failed to verify if route already exists in %s table: %s",
			customRouteTableName, err.Error())
	}

	if !strings.Contains(string(out), " dev "+tunnelName) {
		if out, err = exec.Command("ip", "route", "replace", nexthop.String(), "dev", tunnelName, "table",
			customRouteTableID).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("failed to add route to custom route table, err: %s, output: %s", err, string(out))
		}
	}

	return
}

var (
	cmpExclude = cmpopts.IgnoreTypes(config.MpGracefulRestartState{}, config.AfiSafiState{})

	bgpFunc = map[bool]func(server *gobgp.BgpServer, config *config.Neighbor) (bool, error){
		true:  func(bgp *gobgp.BgpServer, n *config.Neighbor) (bool, error) { return bgp.UpdateNeighbor(n) },
		false: func(bgp *gobgp.BgpServer, n *config.Neighbor) (bool, error) { return false, bgp.AddNeighbor(n) },
	}
)
