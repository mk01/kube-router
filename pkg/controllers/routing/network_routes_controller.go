package routing

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloudnativelabs/kube-router/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/golang/glog"
	bgpapi "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	gobgp "github.com/osrg/gobgp/server"
	"github.com/osrg/gobgp/table"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"

	"github.com/cloudnativelabs/kube-router/pkg/controllers"
	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/cloudnativelabs/kube-router/pkg/utils/net-tools"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	IFACE_NOT_FOUND = "Link not found"

	CHAIN_BGP_EGRESS_RULE = "KUBE-ROUTER-BGP-EGRESS"

	customRouteTableID   = "77"
	customRouteTableName = "kube-router-overlay"
	podSubnetsIPSetName  = "kube-router-pod-subnets"
	nodeAddrsIPSetName   = "kube-router-node-ips"

	nodeASNAnnotation                  = "kube-router.io/node.asn"
	pathPrependASNAnnotation           = "kube-router.io/path-prepend.as"
	pathPrependRepeatNAnnotation       = "kube-router.io/path-prepend.repeat-n"
	peerASNAnnotation                  = "kube-router.io/peer.asns"
	peerIPAnnotation                   = "kube-router.io/peer.ips"
	peerPasswordAnnotation             = "kube-router.io/peer.passwords"
	peerPortAnnotation                 = "kube-router.io/peer.ports"
	routerID                           = "kube-router.io/router.id"
	rrClientAnnotation                 = "kube-router.io/rr.client"
	rrServerAnnotation                 = "kube-router.io/rr.server"
	svcLocalAnnotation                 = "kube-router.io/service.local"
	bgpLocalAddressAnnotation          = "kube-router.io/bgp-local-addresses"
	svcAdvertiseClusterAnnotation      = "kube-router.io/service.advertise.clusterip"
	svcAdvertiseExternalAnnotation     = "kube-router.io/service.advertise.externalip"
	svcAdvertiseLoadBalancerAnnotation = "kube-router.io/service.advertise.loadbalancerip"
	LeaderElectionRecordAnnotationKey  = "control-plane.alpha.kubernetes.io/leader"

	// Deprecated: use kube-router.io/service.advertise.loadbalancer instead
	svcSkipLbIpsAnnotation = "kube-router.io/service.skiplbips"
)

var CONTROLLER_NAME = []string{"Routes controller", "NRC"}

// NetworkRoutingController is struct to hold necessary information required by controller
type NetworkRoutingController struct {
	nodeIP                  net.IP
	nodeName                string
	nodeSubnet              net.IPNet
	nodeInterface           string
	routerId                string
	activeNodes             map[string]bool
	mu                      sync.Mutex
	clientset               kubernetes.Interface
	bgpServer               *gobgp.BgpServer
	syncPeriod              time.Duration
	clusterCIDR             string
	enablePodEgress         bool
	hostnameOverride        string
	advertiseClusterIP      bool
	advertiseExternalIP     bool
	advertiseLoadBalancerIP bool
	advertisePodCidr        bool
	defaultNodeAsnNumber    uint32
	nodeAsnNumber           uint32
	globalPeerRouters       []*config.Neighbor
	nodePeerRouters         []string
	enableCNI               bool
	bgpFullMeshMode         bool
	bgpEnableInternal       bool
	bgpGracefulRestart      bool
	ipSetHandler            *netutils.IPSet
	enableOverlays          bool
	overlayType             string
	peerMultihopTTL         uint8
	MetricsEnabled          bool
	bgpServerStarted        bool
	bgpPort                 uint16
	bgpRRClient             bool
	bgpRRServer             bool
	bgpClusterID            uint32
	cniConfFile             string
	disableSrcDstCheck      bool
	initSrcDstCheckDone     bool
	ec2IamAuthorized        bool
	pathPrependAS           string
	pathPrependCount        uint8
	pathPrepend             bool
	localAddressList        []string
	overrideNextHop         bool

	nodeLister cache.Indexer
	svcLister  cache.Indexer
	epLister   cache.Indexer

	NodeEventHandler      cache.ResourceEventHandler
	ServiceEventHandler   cache.ResourceEventHandler
	EndpointsEventHandler cache.ResourceEventHandler

	Ipm *netutils.IpTablesManager
	rtm *netutils.RouteTableManager
}

func (nrc *NetworkRoutingController) GetData() ([]string, time.Duration) {
	return CONTROLLER_NAME, nrc.syncPeriod
}

// Run runs forever until we are notified on stop channel
func (nrc *NetworkRoutingController) Run(healthChan chan *controllers.ControllerHeartbeat, stopCh <-chan struct{}, wg *sync.WaitGroup) (err error) {
	if nrc.enableCNI {
		nrc.updateCNIConfig()
	}

	glog.V(1).Info("Populating ipsets.")
	err = nrc.syncNodeIPSets()
	if err != nil {
		glog.Errorf("Failed initial ipset setup: %s", err)
	}

	// In case of cluster provisioned on AWS disable source-destination check
	if nrc.disableSrcDstCheck {
		nrc.disableSourceDestinationCheck()
		nrc.initSrcDstCheckDone = true
	}

	// enable IP forwarding for the packets coming in/out from the pods
	err = nrc.enableForwarding()
	if err != nil {
		glog.Errorf("Failed to enable IP forwarding of traffic from pods: %s", err.Error())
	}

	// Handle ipip tunnel overlay
	glog.V(1).Info("Setting up overlay networking.")
	err = nrc.setupPolicyBasedRouting(nrc.enableOverlays)
	if err != nil {
		glog.Errorf("Failed to %v policy based routing: %s", nrc.enableOverlays, err.Error())
	}

	glog.V(1).Infoln("Applying pod egress configuration.")
	nrc.enableIptables(netutils.IPTABLES_FULL_CHAIN_SYNC_NO_ORDER)

	// create 'kube-bridge' interface to which pods will be connected
	_, err = netlink.LinkByName("kube-bridge")
	if err != nil && err.Error() == IFACE_NOT_FOUND {
		linkAttrs := netlink.NewLinkAttrs()
		linkAttrs.Name = "kube-bridge"
		bridge := &netlink.Bridge{LinkAttrs: linkAttrs}
		if err = netlink.LinkAdd(bridge); err != nil {
			glog.Errorf("Failed to create `kube-router` bridge due to %s. Will be created by CNI bridge plugin when pod is launched.", err.Error())
		}
		kubeBridgeIf, err := netlink.LinkByName("kube-bridge")
		if err != nil {
			glog.Errorf("Failed to find created `kube-router` bridge due to %s. Will be created by CNI bridge plugin when pod is launched.", err.Error())
		}
		err = netlink.LinkSetUp(kubeBridgeIf)
		if err != nil {
			glog.Errorf("Failed to bring `kube-router` bridge up due to %s. Will be created by CNI bridge plugin at later point when pod is launched.", err.Error())
		}
	}

	// enable netfilter for the bridge
	if _, err := exec.Command("modprobe", "br_netfilter").CombinedOutput(); err != nil {
		glog.Errorf("Failed to enable netfilter for bridge. Network policies and service proxy may not work: %s", err.Error())
	}
	if err = ioutil.WriteFile("/proc/sys/net/bridge/bridge-nf-call-iptables", []byte(strconv.Itoa(1)), 0640); err != nil {
		glog.Errorf("Failed to enable iptables for bridge. Network policies and service proxy may not work: %s", err.Error())
	}
	if err = ioutil.WriteFile("/proc/sys/net/bridge/bridge-nf-call-ip6tables", []byte(strconv.Itoa(1)), 0640); err != nil {
		glog.Errorf("Failed to enable ip6tables for bridge. Network policies and service proxy may not work: %s", err.Error())
	}

	t := time.NewTicker(nrc.syncPeriod)
	defer t.Stop()
	defer wg.Done()

	glog.Infof("Starting network route controller")

	// Wait till we are ready to launch BGP server
	for {
		err := nrc.startBgpServer()
		if err != nil {
			glog.Errorf("Failed to start node BGP server: %s", err)
			select {
			case <-stopCh:
				glog.Infof("Shutting down network routes controller")
				return err
			case <-t.C:
				glog.Infof("Retrying start of node BGP server")
				continue
			}
		} else {
			break
		}
	}

	nrc.bgpServerStarted = true
	if !nrc.bgpGracefulRestart {
		defer nrc.bgpServer.Shutdown()
	}

	// loop forever till notified to stop on stopCh
	for {
		var err error
		select {
		case <-stopCh:
			glog.Infof("Shutting down network routes controller")
			return err
		default:
		}

		// Update ipset entries
		if nrc.enablePodEgress || nrc.enableOverlays {
			glog.V(1).Info("Syncing ipsets")
			err = nrc.syncNodeIPSets()
			if err != nil {
				glog.Errorf("Error synchronizing ipsets: %s", err.Error())
			}
		}

		// enable IP forwarding for the packets coming in/out from the pods
		err = nrc.enableForwarding()
		if err != nil {
			glog.Errorf("Failed to enable IP forwarding of traffic from pods: %s", err.Error())
		}

		nrc.enableIptables(netutils.IPTABLES_FULL_CHAIN_SYNC_NO_ORDER)
		nrc.cleanUpOverlayRules()

		// advertise or withdraw IPs for the services to be reachable via host
		toAdvertise, toWithdraw, err := nrc.getActiveVIPs()
		if err != nil {
			glog.Errorf("failed to get routes to advertise/withdraw %s", err)
		}

		glog.V(1).Infof("Performing periodic sync of service VIP routes")
		nrc.advertiseVIPs(toAdvertise)
		nrc.withdrawVIPs(toWithdraw)

		glog.V(1).Info("Performing periodic sync of pod CIDR routes")
		err = nrc.advertisePodRoute()
		if err != nil {
			glog.Errorf("Error advertising route: %s", err.Error())
		}

		err = nrc.addExportPolicies()
		if err != nil {
			glog.Errorf("Error adding BGP export policies: %s", err.Error())
		}

		if nrc.bgpEnableInternal {
			nrc.syncInternalPeers()
		}

		if err == nil {
			healthcheck.SendHeartBeat(healthChan, nrc, nil)
		} else {
			glog.Errorf("Error during periodic sync in network routing controller. Error: " + err.Error())
			glog.Errorf("Skipping sending heartbeat from network routing controller as periodic sync failed.")
		}

		select {
		case <-stopCh:
			glog.Infof("Shutting down network routes controller")
			return err
		case <-t.C:
		}
	}
	return err
}

func (nrc *NetworkRoutingController) updateCNIConfig() {
	cidr, err := utils.GetPodCidrFromCniSpec(nrc.cniConfFile)
	if err != nil {
		glog.Errorf("Failed to get pod CIDR from CNI conf file: %s", err)
	}

	if cidr == nil {
		glog.Infof("`subnet` in CNI conf file is empty so populating `subnet` in CNI conf file with pod CIDR assigned to the node obtained from node spec.")
	}

	currentCidr, err := utils.GetPodCidrFromNodeSpec(nrc.clientset, nrc.hostnameOverride)
	if err != nil {
		glog.Fatalf("Failed to get pod CIDR from node spec. kube-router relies on kube-controller-manager to allocate pod CIDR for the node or an annotation `kube-router.io/pod-cidr`. Error: %v", err)
	}

	if cidr == nil || cidr != currentCidr {
		err = utils.InsertPodCidrInCniSpec(nrc.cniConfFile, currentCidr.String())
		if err != nil {
			glog.Fatalf("Failed to insert `subnet`(pod CIDR) into CNI conf file: %s", err.Error())
		}
	}
}

func (nrc *NetworkRoutingController) setRouterId(args ...string) string {
	for _, try := range args {
		if netutils.Isipv4(net.ParseIP(try)) {
			nrc.routerId = try
			break
		}
	}
	return nrc.routerId
}

func (nrc *NetworkRoutingController) watchBgpUpdates() {
	watcher := nrc.bgpServer.Watch(gobgp.WatchBestPath(false))
	for {
		select {
		case ev := <-watcher.Event():
			switch msg := ev.(type) {
			case *gobgp.WatchEventBestPath:
				glog.V(3).Info("Processing bgp route advertisement from peer")
				if nrc.MetricsEnabled {
					metrics.ControllerBGPadvertisementsReceived.Inc()
				}
				for _, path := range msg.PathList {
					if path.IsLocal() {
						continue
					}
					if err := nrc.injectRoute(path); err != nil {
						glog.Errorf("Failed to inject routes due to: " + err.Error())
						continue
					}
				}
			}
		}
	}
}

func (nrc *NetworkRoutingController) advertisePodRoute() error {
	if nrc.MetricsEnabled {
		metrics.ControllerBGPadvertisementsSent.Inc()
	}

	scidr, err := utils.GetPodCidrFromNodeSpec(nrc.clientset, nrc.hostnameOverride)
	if err != nil {
		return err
	}

	cidr := netutils.NewIP(scidr)

	glog.V(2).Infof("Advertising route: '%s via %s' to peers", cidr.ToCIDR(), nrc.nodeIP.String())
	_, err = nrc.bgpServer.AddPath("", []*table.Path{table.NewPath(nil, cidr.ToBgpPrefix(), false, getPathAttributes(cidr, netutils.NewIP(nrc.nodeIP)), time.Now(), false)})
	return err
}

func (nrc *NetworkRoutingController) injectRoute(path *table.Path) error {
	nexthop := path.GetNexthop()
	nlri := path.GetNlri()
	dst, _ := netlink.ParseIPNet(nlri.String())
	var route *netlink.Route

	tunnelName := generateTunnelName(nexthop.String())
	sameSubnet := nrc.nodeSubnet.Contains(nexthop)

	// cleanup route and tunnel if overlay is disabled or node is in same subnet and overlay-type is set to 'subnet'
	if !nrc.enableOverlays || (sameSubnet && nrc.overlayType == "subnet") {
		glog.Infof("Cleaning up old routes if there are any")
		routes, err := netlink.RouteListFiltered(nl.FAMILY_ALL, &netlink.Route{
			Dst: dst, Protocol: 0x11,
		}, netlink.RT_FILTER_DST|netlink.RT_FILTER_PROTOCOL)
		if err != nil {
			glog.Errorf("Failed to get routes from netlink")
		}
		for i, r := range routes {
			if r.Dst.String() == dst.String() && r.Gw.Equal(nexthop) {
				continue
			}
			glog.V(2).Infof("Found route to remove: %s", r.String())
			if err := netlink.RouteDel(&routes[i]); err != nil {
				glog.Errorf("Failed to remove route due to " + err.Error())
			}
		}

		glog.Infof("Cleaning up if there is any existing tunnel interface for the node")
		if link, err := netlink.LinkByName(tunnelName); err == nil {
			if err = netlink.LinkDel(link); err != nil {
				glog.Errorf("Failed to delete tunnel link for the node due to " + err.Error())
			}
		}
	}

	route = &netlink.Route{
		Dst:      dst,
		Gw:       nexthop,
		Protocol: 0x11,
	}

	// create IPIP tunnels only when node is not in same subnet or overlay-type is set to 'full'
	// prevent creation when --override-nexthop=true as well
	if (!sameSubnet || nrc.overlayType == "full") && !nrc.overrideNextHop {
		// create ip-in-ip tunnel and inject route as overlay is enabled
		var link netlink.Link
		var err error

		ipHelper := netutils.NewIP(nrc.nodeIP)
		family := ipHelper.ProtocolCmdParam().Inet
		mode := ipHelper.ProtocolCmdParam().Mode

		link, err = netlink.LinkByName(tunnelName)
		if err != nil {
			out, err := exec.Command(utils.GetPath("ip"), family, "tunnel", "add", tunnelName, "mode", mode, "local", nrc.nodeIP.String(),
				"remote", nexthop.String(), "dev", nrc.nodeInterface).CombinedOutput()
			if err != nil {
				return fmt.Errorf("Route not injected for the route advertised by the node %s "+
					"Failed to create tunnel interface %s. error: %s, output: %s",
					nexthop.String(), tunnelName, err, string(out))
			}

			link, err = netlink.LinkByName(tunnelName)
			if err != nil {
				return fmt.Errorf("Route not injected for the route advertised by the node %s "+
					"Failed to get tunnel interface by name error: %s", tunnelName, err)
			}
			if err := netlink.LinkSetUp(link); err != nil {
				return errors.New("Failed to bring tunnel interface " + tunnelName + " up due to: " + err.Error())
			}
		} else {
			glog.Infof("Tunnel interface: " + tunnelName + " for the node " + nexthop.String() + " already exists.")
		}

		out, err := exec.Command(utils.GetPath("ip"), family, "route", "list", "table", customRouteTableID).CombinedOutput()
		if err != nil {
			return fmt.Errorf("Failed to verify if route already exists in %s table: %s",
				customRouteTableName, err.Error())
		}
		if !strings.Contains(string(out), "dev "+tunnelName) {
			if out, err = exec.Command(utils.GetPath("ip"), family, "route", "add", nexthop.String(), "dev", tunnelName, "table",
				customRouteTableID).CombinedOutput(); err != nil {
				return fmt.Errorf("failed to add route in custom route table, err: %s, output: %s", err, string(out))
			}
		}

		netlink.RouteDel(route)

		route = &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Src:       nrc.nodeIP,
			Dst:       dst,
			Protocol:  0x11,
		}
	}

	if path.IsWithdraw {
		glog.V(2).Infof("Removing route: '%s via %s' from peer in the routing table", dst, nexthop)
		return netlink.RouteDel(route)
	}
	glog.V(2).Infof("Inject route: '%s via %s' from peer to routing table", dst, nexthop)
	return netlink.RouteReplace(route)
}

// Cleanup performs the cleanup of configurations done
func (nrc *NetworkRoutingController) Cleanup() {
	nrc.Ipm.IptablesCleanUp(podEgressObsoleteChains.RuleContaining...)

	// delete all ipsets created by kube-router
	ipset := netutils.NewIPSet()
	err := ipset.Save()
	if err != nil {
		glog.Errorf("Failed to clean up ipsets: " + err.Error())
	}
	err = ipset.DestroyAllWithin()
	if err != nil {
		glog.Warningf("Error deleting ipset: %s", err.Error())
	}
}

func (nrc *NetworkRoutingController) syncNodeIPSets() error {
	start := time.Now()
	defer func() {
		if nrc.MetricsEnabled {
			metrics.ControllerRoutesSyncTime.Observe(time.Since(start).Seconds())
		}
		glog.V(2).Infof("Sync nodeIpSets in network routing controller took %v", time.Since(start))
	}()
	// Get the current list of the nodes from API server
	nodes, err := nrc.clientset.CoreV1().Nodes().List(metav1.ListOptions{})
	if err != nil {
		return errors.New("Failed to list nodes from API server: " + err.Error())
	}

	// Collect active PodCIDR(s) and NodeIPs from nodes
	currentPodCidrs := make([]string, 0)
	currentNodeIPs := make([]string, 0)
	for _, node := range nodes.Items {
		if len(strings.TrimSpace(node.Spec.PodCIDR)) > 0 {
			currentPodCidrs = append(currentPodCidrs, node.Spec.PodCIDR)
		}
		nodeIP, err := utils.GetNodeIP(&node)
		if err != nil {
			return fmt.Errorf("Failed to find a node IP: %s", err)
		}
		currentNodeIPs = append(currentNodeIPs, nodeIP.String())
	}

	// Syncing Pod subnet ipset entries
	psSet := nrc.ipSetHandler.Get(podSubnetsIPSetName)
	if psSet == nil {
		glog.Infof("Creating missing ipset \"%s\"", podSubnetsIPSetName)
		_, err = nrc.ipSetHandler.Create(podSubnetsIPSetName, netutils.OptionTimeout, "0")
		if err != nil {
			return fmt.Errorf("ipset \"%s\" not found in controller instance",
				podSubnetsIPSetName)
		}
	}
	err = psSet.Refresh(currentPodCidrs, psSet.Options...)
	if err != nil {
		return fmt.Errorf("Failed to sync Pod Subnets ipset: %s", err)
	}

	// Syncing Node Addresses ipset entries
	naSet := nrc.ipSetHandler.Get(nodeAddrsIPSetName)
	if naSet == nil {
		glog.Infof("Creating missing ipset \"%s\"", nodeAddrsIPSetName)
		_, err = nrc.ipSetHandler.Create(nodeAddrsIPSetName, netutils.OptionTimeout, "0")
		if err != nil {
			return fmt.Errorf("ipset \"%s\" not found in controller instance",
				nodeAddrsIPSetName)
		}
	}
	err = naSet.Refresh(currentNodeIPs, naSet.Options...)
	if err != nil {
		return fmt.Errorf("Failed to sync Node Addresses ipset: %s", err)
	}

	return nil
}

func (nrc *NetworkRoutingController) enableIptables(initial netutils.IpTableManipulationType) error {
	var err error = nil

	// Handle Pod egress masquerading configuration
	for protocol := range netutils.UsedTcpProtocols {
		if err == nil && nrc.enablePodEgress {
			err = nrc.createPodEgressRule(protocol, initial)
		} else if err == nil {
			err = nrc.deletePodEgressRule(protocol)
		}

		if err != nil {
			glog.Errorf("Error applying pod egress: %s", err.Error())
		}
	}

	if !netutils.NewIP(nrc.nodeIP).IsIPv4() {
		if err = nrc.EnableBgpSNAT(initial); err != nil {
			fmt.Errorf("Failed to setup SNAT for bgp %s", err)
		}
	}

	return err
}

func (nrc *NetworkRoutingController) EnableBgpSNAT(action netutils.IpTableManipulationType) error {
	nrl := &netutils.IpTablesRuleListType{
		netutils.NewRule("-m", "set", "--match-set", nodeAddrsIPSetName, "dst", "-p", "tcp", "--dport", fmt.Sprint(nrc.bgpPort), "-j", netutils.CHAIN_KUBE_SNAT_TARGET),
		netutils.NewRule("-m", "set", "!", "--match-set", nodeAddrsIPSetName, "dst", "-p", "tcp", "--dport", fmt.Sprint(nrc.bgpPort), "-j", netutils.CHAIN_KUBE_SNAT_TARGET),
	}

	return nrc.Ipm.CreateIpTablesRuleWithChain(netutils.V6, "nat", CHAIN_BGP_EGRESS_RULE, action, []string{"POSTROUTING"}, true, nrl)
}

// ensure there is rule in filter table and FORWARD chain to permit in/out traffic from pods
// this rules will be appended so that any iptables rules for network policies will take
// precedence
func (nrc *NetworkRoutingController) enableForwarding() error {
	return netutils.UsedTcpProtocols.ForEach(nrc._enableForwarding)
}

func (nrc *NetworkRoutingController) _enableForwarding(p netutils.Proto) error {

	rules := &netutils.IpTablesRuleListType{}

	comment := "allow outbound traffic from pods"
	args := []string{"-m", "comment", "--comment", comment, "-i", "kube-bridge", "-j", "ACCEPT"}
	rules.Add(netutils.NewRule(args...))

	comment = "allow inbound traffic to pods"
	args = []string{"-m", "comment", "--comment", comment, "-o", "kube-bridge", "-j", "ACCEPT"}
	rules.Add(netutils.NewRule(args...))

	comment = "allow outbound node port traffic on node interface with which node ip is associated"
	args = []string{"-m", "comment", "--comment", comment, "-o", nrc.nodeInterface, "-j", "ACCEPT"}
	rules.Add(netutils.NewRule(args...))

	return nrc.Ipm.CreateIpTablesRuleWithChain(p, "filter", netutils.CHAIN_KUBE_COMMON_FORWARD, netutils.IPTABLES_APPEND_UNIQUE,
		netutils.NoReferencedChains, true, rules)
}

func (nrc *NetworkRoutingController) startBgpServer() error {
	var nodeAsnNumber uint32
	node, err := utils.GetNodeObject(nrc.clientset, nrc.hostnameOverride)
	if err != nil {
		return errors.New("Failed to get node object from api server: " + err.Error())
	}

	if nrc.bgpFullMeshMode {
		nodeAsnNumber = nrc.defaultNodeAsnNumber
	} else {
		nodeasn, ok := node.ObjectMeta.Annotations[nodeASNAnnotation]
		if !ok {
			return errors.New("Could not find ASN number for the node. " +
				"Node needs to be annotated with ASN number details to start BGP server.")
		}
		glog.Infof("Found ASN for the node to be %s from the node annotations", nodeasn)
		asnNo, err := strconv.ParseUint(nodeasn, 0, 32)
		if err != nil {
			return errors.New("Failed to parse ASN number specified for the the node")
		}
		nodeAsnNumber = uint32(asnNo)
		nrc.nodeAsnNumber = nodeAsnNumber
	}

	if clusterid, ok := node.ObjectMeta.Annotations[rrServerAnnotation]; ok {
		glog.Infof("Found rr.server for the node to be %s from the node annotation", clusterid)
		clusterID, err := strconv.ParseUint(clusterid, 0, 32)
		if err != nil {
			return errors.New("Failed to parse rr.server clusterId number specified for the the node")
		}
		nrc.bgpClusterID = uint32(clusterID)
		nrc.bgpRRServer = true
	} else if clusterid, ok := node.ObjectMeta.Annotations[rrClientAnnotation]; ok {
		glog.Infof("Found rr.client for the node to be %s from the node annotation", clusterid)
		clusterID, err := strconv.ParseUint(clusterid, 0, 32)
		if err != nil {
			return errors.New("Failed to parse rr.client clusterId number specified for the the node")
		}
		nrc.bgpClusterID = uint32(clusterID)
		nrc.bgpRRClient = true
	}

	if prependASN, okASN := node.ObjectMeta.Annotations[pathPrependASNAnnotation]; okASN {
		prependRepeatN, okRepeatN := node.ObjectMeta.Annotations[pathPrependRepeatNAnnotation]

		if !okRepeatN {
			return fmt.Errorf("Both %s and %s must be set", pathPrependASNAnnotation, pathPrependRepeatNAnnotation)
		}

		_, err := strconv.ParseUint(prependASN, 0, 32)
		if err != nil {
			return errors.New("Failed to parse ASN number specified to prepend")
		}

		repeatN, err := strconv.ParseUint(prependRepeatN, 0, 8)
		if err != nil {
			return errors.New("Failed to parse number of times ASN should be repeated")
		}

		nrc.pathPrepend = true
		nrc.pathPrependAS = prependASN
		nrc.pathPrependCount = uint8(repeatN)
	}

	if !utils.CheckForElementInArray(nrc.nodeSubnet.IP.String(), nrc.localAddressList) {
		nrc.localAddressList = append(nrc.localAddressList, nrc.nodeSubnet.IP.String())
	}

	nrc.bgpServer = gobgp.NewBgpServer()
	go nrc.bgpServer.Serve()

	localAddressList := nrc.localAddressList

	global := &config.Global{
		Config: config.GlobalConfig{
			As:               nodeAsnNumber,
			RouterId:         nrc.routerId,
			LocalAddressList: localAddressList,
			Port:             int32(nrc.bgpPort),
		},
		GracefulRestart: config.GracefulRestart{
			Config: config.GracefulRestartConfig{
				Enabled:             true,
				StaleRoutesTime:     120,
			},
		},
	}

	if err := nrc.bgpServer.Start(global); err != nil {
		return errors.New("Failed to start BGP server due to : " + err.Error())
	}

	go nrc.watchBgpUpdates()

	g := bgpapi.NewGrpcServer(nrc.bgpServer, netutils.NewIP(nrc.nodeIP).ToStringWithPort("50051")+","+"127.0.0.1:50051")
	go g.Serve()

	// If the global routing peer is configured then peer with it
	// else attempt to get peers from node specific BGP annotations.
	if len(nrc.globalPeerRouters) == 0 {
		// Get Global Peer Router ASN configs
		nodeBgpPeerAsnsAnnotation, ok := node.ObjectMeta.Annotations[peerASNAnnotation]
		if !ok {
			glog.Infof("Could not find BGP peer info for the node in the node annotations so skipping configuring peer.")
			return nil
		}

		asnStrings := stringToSlice(nodeBgpPeerAsnsAnnotation, ",")
		peerASNs, err := stringSliceToUInt32(asnStrings)
		if err != nil {
			nrc.bgpServer.Stop()
			return fmt.Errorf("Failed to parse node's Peer ASN Numbers Annotation: %s", err)
		}

		// Get Global Peer Router IP Address configs
		nodeBgpPeersAnnotation, ok := node.ObjectMeta.Annotations[peerIPAnnotation]
		if !ok {
			glog.Infof("Could not find BGP peer info for the node in the node annotations so skipping configuring peer.")
			return nil
		}
		ipStrings := stringToSlice(nodeBgpPeersAnnotation, ",")
		peerIPs, err := stringSliceToIPs(ipStrings)
		if err != nil {
			nrc.bgpServer.Stop()
			return fmt.Errorf("Failed to parse node's Peer Addresses Annotation: %s", err)
		}

		// Get Global Peer Router ASN configs
		nodeBgpPeerPortsAnnotation, ok := node.ObjectMeta.Annotations[peerPortAnnotation]
		// Default to default BGP port if port annotation is not found
		var peerPorts = make([]uint16, 0)
		if ok {
			portStrings := stringToSlice(nodeBgpPeerPortsAnnotation, ",")
			peerPorts, err = stringSliceToUInt16(portStrings)
			if err != nil {
				nrc.bgpServer.Stop()
				return fmt.Errorf("Failed to parse node's Peer Port Numbers Annotation: %s", err)
			}
		}

		// Get Global Peer Router Password configs
		var peerPasswords []string
		nodeBGPPasswordsAnnotation, ok := node.ObjectMeta.Annotations[peerPasswordAnnotation]
		if !ok {
			glog.Infof("Could not find BGP peer password info in the node's annotations. Assuming no passwords.")
		} else {
			passStrings := stringToSlice(nodeBGPPasswordsAnnotation, ",")
			peerPasswords, err = stringSliceB64Decode(passStrings)
			if err != nil {
				nrc.bgpServer.Stop()
				return fmt.Errorf("Failed to parse node's Peer Passwords Annotation: %s", err)
			}
		}

		// Create and set Global Peer Router complete configs
		nrc.globalPeerRouters, err = newGlobalPeers(peerIPs, peerPorts, peerASNs, peerPasswords)
		if err != nil {
			nrc.bgpServer.Stop()
			return fmt.Errorf("Failed to process Global Peer Router configs: %s", err)
		}

		nrc.nodePeerRouters = ipStrings
	}

	if len(nrc.globalPeerRouters) != 0 {
		err := connectToExternalBGPPeers(nrc.bgpServer, nrc.globalPeerRouters, nrc.bgpGracefulRestart, nrc.peerMultihopTTL)
		if err != nil {
			nrc.bgpServer.Stop()
			return fmt.Errorf("Failed to peer with Global Peer Router(s): %s",
				err)
		}
	} else {
		glog.Infof("No Global Peer Routers configured. Peering skipped.")
	}

	return nil
}

// func (nrc *NetworkRoutingController) getExternalNodeIPs(

// NewNetworkRoutingController returns new NetworkRoutingController object
func NewNetworkRoutingController(clientset kubernetes.Interface,
	kubeRouterConfig *options.KubeRouterConfig,
	nodeInformer cache.SharedIndexInformer, svcInformer cache.SharedIndexInformer,
	epInformer cache.SharedIndexInformer) (*NetworkRoutingController, error) {

	var err error

	nrc := NetworkRoutingController{}
	if kubeRouterConfig.MetricsEnabled {
		//GetData the metrics for this controller
		prometheus.MustRegister(metrics.ControllerBGPadvertisementsReceived)
		prometheus.MustRegister(metrics.ControllerBGPInternalPeersSyncTime)
		prometheus.MustRegister(metrics.ControllerBPGpeers)
		prometheus.MustRegister(metrics.ControllerRoutesSyncTime)
		nrc.MetricsEnabled = true
	}

	nrc.bgpFullMeshMode = kubeRouterConfig.FullMeshMode
	nrc.enableCNI = kubeRouterConfig.EnableCNI
	nrc.bgpEnableInternal = kubeRouterConfig.EnableiBGP
	nrc.bgpGracefulRestart = kubeRouterConfig.BGPGracefulRestart
	nrc.peerMultihopTTL = kubeRouterConfig.PeerMultihopTtl
	nrc.enablePodEgress = kubeRouterConfig.EnablePodEgress
	nrc.syncPeriod = kubeRouterConfig.RoutesSyncPeriod
	nrc.overrideNextHop = kubeRouterConfig.OverrideNextHop
	nrc.clientset = clientset
	nrc.activeNodes = make(map[string]bool)
	nrc.bgpRRClient = false
	nrc.bgpRRServer = false
	nrc.bgpServerStarted = false
	nrc.disableSrcDstCheck = kubeRouterConfig.DisableSrcDstCheck
	nrc.initSrcDstCheckDone = false

	nrc.hostnameOverride = kubeRouterConfig.HostnameOverride
	node, err := utils.GetNodeObject(clientset, nrc.hostnameOverride)
	if err != nil {
		return nil, errors.New("Failed getting node object from API server: " + err.Error())
	}

	nrc.nodeName = node.Name

	nodeIP, err := utils.GetNodeIP(node)
	if err != nil {
		return nil, errors.New("Failed getting IP address from node object: " + err.Error())
	}
	nrc.nodeIP = nodeIP

	bgpLocalAddressListAnnotation, _ := node.ObjectMeta.Annotations[routerID]
	if !netutils.NewIP(nrc.nodeIP).IsIPv4() && "" == nrc.setRouterId(bgpLocalAddressListAnnotation, kubeRouterConfig.RouterId, nrc.nodeIP.String()) {
		return nil, errors.New("Router-id must be specified in ipv6 operation")
	}

	// lets start with assumption we hace necessary IAM creds to access EC2 api
	nrc.ec2IamAuthorized = true

	if nrc.enableCNI {
		nrc.cniConfFile = os.Getenv("KUBE_ROUTER_CNI_CONF_FILE")
		if nrc.cniConfFile == "" {
			nrc.cniConfFile = "/etc/cni/net.d/10-kuberouter.conf"
		}
		if _, err := os.Stat(nrc.cniConfFile); os.IsNotExist(err) {
			return nil, errors.New("CNI conf file " + nrc.cniConfFile + " does not exist.")
		}
	}

	nrc.ipSetHandler = netutils.NewIPSet()

	_, err = nrc.ipSetHandler.Create(podSubnetsIPSetName, netutils.TypeHashNet, netutils.OptionTimeout, "0")
	if err != nil {
		return nil, err
	}

	_, err = nrc.ipSetHandler.Create(nodeAddrsIPSetName, netutils.TypeHashIP, netutils.OptionTimeout, "0")
	if err != nil {
		return nil, err
	}

	if kubeRouterConfig.EnablePodEgress || len(nrc.clusterCIDR) != 0 {
		nrc.enablePodEgress = true
	}

	if kubeRouterConfig.ClusterAsn != 0 {
		if !((kubeRouterConfig.ClusterAsn >= 64512 && kubeRouterConfig.ClusterAsn <= 65535) ||
			(kubeRouterConfig.ClusterAsn >= 4200000000 && kubeRouterConfig.ClusterAsn <= 4294967294)) {
			return nil, errors.New("Invalid ASN number for cluster ASN")
		}
		nrc.defaultNodeAsnNumber = uint32(kubeRouterConfig.ClusterAsn)
	} else {
		nrc.defaultNodeAsnNumber = 64512 // this magic number is first of the private ASN range, use it as default
	}

	nrc.advertiseClusterIP = kubeRouterConfig.AdvertiseClusterIp
	nrc.advertiseExternalIP = kubeRouterConfig.AdvertiseExternalIp
	nrc.advertiseLoadBalancerIP = kubeRouterConfig.AdvertiseLoadBalancerIp
	nrc.advertisePodCidr = kubeRouterConfig.AdvertiseNodePodCidr
	nrc.enableOverlays = kubeRouterConfig.EnableOverlay
	nrc.overlayType = kubeRouterConfig.OverlayType

	nrc.bgpPort = kubeRouterConfig.BGPPort

	// Convert ints to uint32s
	peerASNs := make([]uint32, 0)
	for _, i := range kubeRouterConfig.PeerASNs {
		peerASNs = append(peerASNs, uint32(i))
	}

	// Convert uints to uint16s
	peerPorts := make([]uint16, 0)
	for _, i := range kubeRouterConfig.PeerPorts {
		peerPorts = append(peerPorts, uint16(i))
	}

	// Decode base64 passwords
	peerPasswords := make([]string, 0)
	if len(kubeRouterConfig.PeerPasswords) != 0 {
		peerPasswords, err = stringSliceB64Decode(kubeRouterConfig.PeerPasswords)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse CLI Peer Passwords flag: %s", err)
		}
	}

	nrc.globalPeerRouters, err = newGlobalPeers(kubeRouterConfig.PeerRouters, peerPorts,
		peerASNs, peerPasswords)
	if err != nil {
		return nil, fmt.Errorf("Error processing Global Peer Router configs: %s", err)
	}

	nrc.nodeSubnet, nrc.nodeInterface, err = getLinkAssignedPrefix(nrc.nodeIP)
	if err != nil {
		return nil, errors.New("Failed find the subnet of the node IP and interface on" +
			"which its configured: " + err.Error())
	}

	bgpLocalAddressListAnnotation, ok := node.ObjectMeta.Annotations[bgpLocalAddressAnnotation]
	if !ok {
		glog.Infof("Could not find annotation `kube-router.io/bgp-local-addresses` on node object so BGP will listen on node IP: %s address.", nrc.nodeIP.String())
		nrc.localAddressList = append(nrc.localAddressList, nrc.nodeIP.String())
	} else {
		glog.Infof("Found annotation `kube-router.io/bgp-local-addresses` on node object so BGP will listen on local IP's: %s", bgpLocalAddressListAnnotation)
		localAddresses := stringToSlice(bgpLocalAddressListAnnotation, ",")
		for _, addr := range localAddresses {
			ip := net.ParseIP(addr)
			if ip == nil {
				glog.Fatalf("Invalid IP address %s specified in `kube-router.io/bgp-local-addresses`.", addr)
			}
		}
		nrc.localAddressList = append(nrc.localAddressList, localAddresses...)
	}
	nrc.svcLister = svcInformer.GetIndexer()
	nrc.ServiceEventHandler = nrc.newServiceEventHandler()

	nrc.epLister = epInformer.GetIndexer()
	nrc.EndpointsEventHandler = nrc.newEndpointsEventHandler()

	nrc.nodeLister = nodeInformer.GetIndexer()
	nrc.NodeEventHandler = nrc.newNodeEventHandler()

	nrc.Ipm = netutils.NewIpTablesManager(nrc.localAddressList, podEgressObsoleteChains)

	return &nrc, nil
}
