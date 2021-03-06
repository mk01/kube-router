package routing

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloudnativelabs/kube-router/pkg/controllers"
	"github.com/cloudnativelabs/kube-router/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/api"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/hostconf"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/hostnet"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/tools"
	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/golang/glog"
	"github.com/google/go-cmp/cmp"
	bgpapi "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/config"
	gobgp "github.com/osrg/gobgp/server"
	"github.com/osrg/gobgp/table"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"
	"k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

const (
	IFACE_NOT_FOUND = "Link not found"

	CHAIN_BGP_EGRESS_RULE = "KUBE-ROUTER-BGP-EGRESS"

	customRouteTableID   = "77"
	customRouteTableName = "kube-router-overlay"
	podSubnetsIPSetName  = "kube-router-pod-subnets"
	nodeAddrsIPSetName   = "kube-router-node-ips"

	nodeMACAnnotation                  = "kube-router.io/node.mac"
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
	svcDSRAnnotation                   = "kube-router.io/service.dsr"
	bgpLocalAddressAnnotation          = "kube-router.io/bgp-local-addresses"
	svcAdvertiseClusterAnnotation      = "kube-router.io/service.advertise.clusterip"
	svcAdvertiseExternalAnnotation     = "kube-router.io/service.advertise.externalip"
	svcAdvertiseLoadBalancerAnnotation = "kube-router.io/service.advertise.loadbalancerip"
	LeaderElectionRecordAnnotationKey  = "control-plane.alpha.kubernetes.io/leader"

	// Deprecated: use kube-router.io/service.advertise.loadbalancer instead
	svcSkipLbIpsAnnotation = "kube-router.io/service.skiplbips"
)

// NetworkRoutingController is struct to hold necessary information required by controller
type NetworkRoutingController struct {
	controllers.Controller

	nodeInterfaceMAC     string
	routerId             string
	activeNodes          sync.Map
	mu                   sync.Mutex
	bgpServer            *gobgp.BgpServer
	clusterCIDR          string
	enablePodEgress      bool
	defaultNodeAsnNumber uint32
	nodeAsnNumber        uint32
	globalPeerRouters    []*config.Neighbor
	nodePeerRouters      []string
	ipSetHandler         *hostnet.IPSet
	peerMultihopTTL      uint8
	MetricsEnabled       bool
	bgpServerStarted     bool
	bgpPort              uint16
	bgpRRClient          bool
	bgpRRServer          bool
	bgpClusterID         uint32
	cniConfFile          string
	disableSrcDstCheck   bool
	initSrcDstCheckDone  bool
	ec2IamAuthorized     bool
	pathPrependAS        string
	pathPrependCount     uint8
	pathPrepend          bool
	localAddressList     []string

	nodeLister cache.Indexer
	svcLister  cache.Indexer
	epLister   cache.Indexer

	NodeEventHandler      cache.ResourceEventHandler
	ServiceEventHandler   cache.ResourceEventHandler
	EndpointsEventHandler cache.ResourceEventHandler

	Ipm *hostnet.IpTablesManager
	rtm *hostnet.RouteTableManager
}

// Run runs forever until we are notified on stop channel
func (nrc *NetworkRoutingController) run(stopCh <-chan struct{}) (err error) {
	defer glog.Infof("Shutting down %s", nrc.GetControllerName())

	if nrc.GetConfig().EnableCNI {
		nrc.updateCNIConfig()
	}

	glog.V(1).Info("Populating ipsets.")
	err = nrc.syncNodeIPSets()
	if err != nil {
		glog.Errorf("Failed initial ipset setup: %s", err)
	}

	// In case of cluster provisioned on AWS disable source-destination check
	if nrc.disableSrcDstCheck {
		nrc.disableSourceDestinationCheck(api.GetAllClusterNodes(nrc.nodeLister))
		nrc.initSrcDstCheckDone = true
	}

	// enable IP forwarding for the packets coming in/out from the pods
	err = nrc.enableForwarding()
	if err != nil {
		glog.Errorf("Failed to enable IP forwarding of traffic from pods: %s", err.Error())
	}

	// Handle ipip tunnel overlay
	glog.V(1).Info("Setting up overlay networking.")
	err = nrc.setupPolicyBasedRouting(nrc.GetConfig().EnableOverlay)
	if err != nil {
		glog.Errorf("Failed to %v policy based routing: %s", nrc.GetConfig().EnableOverlay, err.Error())
	}

	glog.V(1).Infoln("Applying pod egress configuration.")
	nrc.Ipm.RegisterPeriodicFunction(func(ipm *hostnet.IpTablesManager) {
		nrc.enableIptables(hostnet.IPTABLES_FULL_CHAIN_SYNC_NO_ORDER)
	})

	// create 'kube-bridge' interface to which pods will be connected
	_, err = netlink.LinkByName(options.KUBE_BRIDGE_IF)
	if err != nil && err.Error() == IFACE_NOT_FOUND {
		linkAttrs := netlink.NewLinkAttrs()
		linkAttrs.Name = options.KUBE_BRIDGE_IF
		bridge := &netlink.Bridge{LinkAttrs: linkAttrs}
		if err = netlink.LinkAdd(bridge); err != nil {
			glog.Errorf("Failed to create `kube-router` bridge due to %s. Will be created by CNI bridge plugin when pod is launched.", err.Error())
		}
		kubeBridgeIf, err := netlink.LinkByName(options.KUBE_BRIDGE_IF)
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
	sysctlConfig := &hostconf.SysCtlConfigRuleListType{
		{"net/bridge/bridge-nf-call-iptables", 1},
		{"net/bridge/bridge-nf-call-ip6tables", 1},
		{"net/ipv4/tcp_mtu_probing", 1},
		{"net/ipv4/ip_forward_use_pmtu", 1},
	}
	sysctlConfig.Apply()

	t := time.NewTicker(nrc.GetSyncPeriod())
	defer t.Stop()

	glog.Infof("Started %s", nrc.GetControllerName())

	// Wait till we are ready to launch BGP server
	for {
		err := nrc.startBgpServer()
		if err != nil {
			glog.Errorf("Failed to start node BGP server: %s", err)
			select {
			case <-stopCh:
				return err
			case <-t.C:
				glog.Infof("Retrying start of node BGP server")
				continue
			}
		} else {
			break
		}
	}

	if !nrc.GetConfig().BGPGracefulRestart {
		defer nrc.bgpServer.Shutdown()
	}

	// loop forever till notified to stop on stopCh
	for {
		var err error
		select {
		case <-stopCh:
			return err
		default:
		}

		// Update ipset entries
		if nrc.enablePodEgress || nrc.GetConfig().EnableOverlay {
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

		//nrc.enableIptables(hostnet.IPTABLES_FULL_CHAIN_SYNC_NO_ORDER)
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

		err = nrc.AddPolicies()
		if err != nil {
			glog.Errorf("Error adding BGP policies: %s", err.Error())
		}

		if nrc.GetConfig().EnableiBGP {
			nrc.syncInternalPeers()
		}
		nrc.bgpServerStarted = true

		if err == nil {
			healthcheck.SendHeartBeat(nrc, nil)
		} else {
			glog.Errorf("Error during periodic sync in network routing controller. Error: " + err.Error())
			glog.Errorf("Skipping sending heartbeat from network routing controller as periodic sync failed.")
		}

		select {
		case <-stopCh:
			return err
		case <-t.C:
		}
	}
	return err
}

func (nrc *NetworkRoutingController) updateCNIConfig() {
	cidr, err := api.GetPodCidrFromCniSpec(nrc.cniConfFile)
	if err != nil {
		glog.Errorf("Failed to get pod CIDR from CNI conf file: %s", err)
	}

	if cidr == nil {
		glog.Infof("`subnet` in CNI conf file is empty so populating `subnet` in CNI conf file with pod CIDR assigned to the node obtained from node spec.")
	}

	currentCidr, err := api.GetPodCidrFromNodeSpec(nrc.GetConfig().ClientSet, nrc.GetConfig().HostnameOverride)
	if err != nil {
		glog.Fatalf("Failed to get pod CIDR from node spec. kube-router relies on kube-controller-manager to allocate pod CIDR for the node or an annotation `kube-router.io/pod-cidr`. Error: %v", err)
	}

	if cidr == nil || cidr != currentCidr {
		err = api.UpdateCNIWithValues(nrc.cniConfFile, options.KUBE_BRIDGE_IF, api.UpdateSubnet, currentCidr.String())
		if err != nil {
			glog.Fatalf("Failed to insert `subnet`(pod CIDR) into CNI conf file: %s", err.Error())
		}
	}

	// calculate with worst case subnet=full
	err = api.UpdateCNIWithValues(nrc.cniConfFile, options.KUBE_BRIDGE_IF, api.UpdateMtu, hostnet.GetInterfaceMTU(nrc.GetConfig().GetNodeIF())-48)
	if err != nil {
		glog.Fatalf("Failed to insert `MTU` into CNI conf file: %s", err.Error())
	}
}

func (nrc *NetworkRoutingController) setRouterId(args ...string) string {
	for _, try := range args {
		if ip := net.ParseIP(try); ip != nil && hostnet.Isipv4(ip) {
			nrc.routerId = ip.String()
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

	scidr, err := api.GetPodCidrFromNodeSpec(nrc.GetConfig().ClientSet, nrc.GetConfig().HostnameOverride)
	if err != nil {
		return err
	}

	cidr := hostnet.NewIP(scidr)

	glog.V(2).Infof("Advertising route: '%s via %s' to peers", cidr.ToCIDR(), nrc.GetConfig().GetNodeIP().IP.String())
	_, err = nrc.bgpServer.AddPath("", []*table.Path{table.NewPath(nil, cidr.ToBgpPrefix(), false, getPathAttributes(cidr, hostnet.NewIP(nrc.GetConfig().GetNodeIP())), time.Now(), false)})
	return err
}

func (nrc *NetworkRoutingController) injectRoute(path *table.Path) (err error) {
	var route *netlink.Route
	var routes []netlink.Route
	var created bool

	nexthop := path.GetNexthop()
	dst, _ := netlink.ParseIPNet(path.GetNlri().String())

	tunnelName := generateTunnelName(nexthop.String())
	sameSubnet := hostnet.CheckIPisLinkLocalReachable(nexthop)

	if routes, err = nrc.getRoutesByTemplate(&netlink.Route{Dst: dst, Protocol: 0x11}, netlink.RT_FILTER_DST); err != nil {
		return
	}

	simpleRoute := !nrc.GetConfig().EnableOverlay || sameSubnet && nrc.GetConfig().OverlayType == "subnet"
	_, activeNode := nrc.activeNodes.Load(nexthop.String())
	route = nrc.buildRouteForDst(dst, simpleRoute || !activeNode, nexthop, tunnelName)

	if path.IsWithdraw {
		if tools.CheckForElementInArray(*route, routes, hostnet.RouteComparer) {
			return netlink.RouteDel(route)
		}
		return nil
	}

	for i := range routes {
		r := &routes[i]
		if i == 0 && cmp.Equal(r, route, hostnet.RouteComparer) {
			created = true
			continue
		} else if created && i > 0 {
			if err := netlink.RouteDel(r); err != nil {
				glog.Errorf("Failed to remove route due to " + err.Error())
			}
			continue
		}

		glog.V(2).Infof("Inject route to %s from peer to routing table: %s", dst, route.String())
		if err = netlink.RouteReplace(route); err != nil {
			glog.Errorf("Failed to ensure route due to " + err.Error())
			continue
		}
		created = true
	}

	if !created {
		err = netlink.RouteAdd(route)
	}

	// route replace doesn't currently work properly for ipv6 and transition tun <> gw
	// make sure there are not both route via tunnel and direct route via the nexthop host
	if !hostnet.NewIP(nexthop).IsIPv4() && !simpleRoute {
		glog.V(2).Infof("    Quirk - removal of routes which should have been replaced")
		nrc.removeRoutesForNode(nexthop)
	}
	return
}

func (nrc *NetworkRoutingController) removeRoutesForNode(ip net.IP) {
	var routes []netlink.Route
	var err error

	if routes, err = nrc.getRoutesByTemplate(&netlink.Route{Gw: ip, Protocol: 0x11}, netlink.RT_FILTER_GW); err != nil {
		return
	}

	for i, r := range routes {
		glog.V(2).Infof("Removing route: '%s via %s' from peer in the routing table", r.Dst, ip.String())
		netlink.RouteDel(&routes[i])
	}
}

// Cleanup performs the cleanup of configurations done
func (nrc *NetworkRoutingController) Cleanup() {
	nrc.Ipm.IptablesCleanUp(podEgressObsoleteChains.RuleContaining...)

	// delete all ipsets created by kube-router
	ipset := hostnet.NewIPSet()
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
	nodes := api.GetAllClusterNodes(nrc.nodeLister)

	// Collect active PodCIDR(s) and NodeIPs from nodes
	currentPodCidrs := make([]string, 0)
	currentNodeIPs := make([]string, 0)
	for _, node := range nodes {
		var podCIDR string
		if podCIDR = strings.TrimSpace(node.GetAnnotations()["kube-router.io/pod-cidr"]); podCIDR == "" {
			podCIDR = strings.TrimSpace(node.Spec.PodCIDR)
		}

		if len(podCIDR) == 0 {
			glog.Warningf("Couldn't determine PodCIDR of the %v node", node.Name)
		} else {
			currentPodCidrs = append(currentPodCidrs, podCIDR)
		}

		nodeIP := api.GetNodeIP(node)
		if nodeIP == nil {
			return tools.NewError("Failed to find a node IP")
		}
		currentNodeIPs = append(currentNodeIPs, nodeIP.String())
	}

	// Syncing Pod subnet ipset entries
	psSet, err := nrc.ipSetHandler.GetOrCreate(podSubnetsIPSetName)
	if err != nil {
		return fmt.Errorf("ipset \"%s\" not found in controller instance", podSubnetsIPSetName)
	}
	psSet.RefreshAsync(currentPodCidrs, psSet.Options...)

	if nrc.GetConfig().RunFirewall {
		return nil
	}

	// Syncing Node Addresses ipset entries
	naSet, err := nrc.ipSetHandler.GetOrCreate(nodeAddrsIPSetName)
	if err != nil {
		return fmt.Errorf("ipset \"%s\" not found in controller instance", nodeAddrsIPSetName)
	}
	naSet.RefreshAsync(currentNodeIPs, naSet.Options...)

	return nil
}

func (nrc *NetworkRoutingController) enableIptables(initial hostnet.IpTableManipulationType) error {
	var err error = nil

	// Handle Pod egress masquerading configuration
	for protocol := range hostnet.UsedTcpProtocols {
		if err == nil && nrc.enablePodEgress {
			err = nrc.createPodEgressRule(protocol, initial)
		} else if err == nil {
			err = nrc.deletePodEgressRule(protocol)
		}

		if err != nil {
			glog.Errorf("Error applying pod egress: %s", err.Error())
		}
	}

	if !hostnet.NewIP(nrc.GetConfig().GetNodeIP()).IsIPv4() {
		if err = nrc.EnableBgpSNAT(initial); err != nil {
			fmt.Errorf("Failed to setup SNAT for bgp %s", err)
		}
	}

	return err
}

func (nrc *NetworkRoutingController) EnableBgpSNAT(action hostnet.IpTableManipulationType) error {
	nrl := &hostnet.IpTablesRuleListType{
		hostnet.NewRule("-m", "set", "--match-set", nodeAddrsIPSetName, "dst", "-p", "tcp", "--dport", fmt.Sprint(nrc.bgpPort), "-j", hostnet.CHAIN_KUBE_SNAT_TARGET),
		hostnet.NewRule("-m", "set", "!", "--match-set", nodeAddrsIPSetName, "dst", "-p", "tcp", "--dport", fmt.Sprint(nrc.bgpPort), "-j", hostnet.CHAIN_KUBE_SNAT_TARGET),
	}

	return nrc.Ipm.CreateRuleChain(hostnet.V6, "nat", CHAIN_BGP_EGRESS_RULE, action, true, nrl, hostnet.ReferenceFromType{In: "POSTROUTING"})
}

// ensure there is rule in filter table and FORWARD chain to permit in/out traffic from pods
// this rules will be appended so that any iptables rules for network policies will take
// precedence
func (nrc *NetworkRoutingController) enableForwarding() error {
	return hostnet.UsedTcpProtocols.ForEach(nrc._enableForwarding)
}

func (nrc *NetworkRoutingController) _enableForwarding(p hostnet.Proto) error {

	rules := &hostnet.IpTablesRuleListType{}

	comment := "allow outbound traffic from pods"
	args := []string{"-m", "comment", "--comment", comment, "-i", options.KUBE_BRIDGE_IF, "-j", "ACCEPT"}
	rules.Add(hostnet.NewRule(args...))

	comment = "allow inbound traffic to pods"
	args = []string{"-m", "comment", "--comment", comment, "-o", options.KUBE_BRIDGE_IF, "-j", "ACCEPT"}
	rules.Add(hostnet.NewRule(args...))

	comment = "allow outbound node port traffic on node interface with which node ip is associated"
	args = []string{"-m", "comment", "--comment", comment, "-o", nrc.GetConfig().GetNodeIF(), "-j", "ACCEPT"}
	rules.Add(hostnet.NewRule(args...))

	return nrc.Ipm.CreateRuleChain(p, "filter", hostnet.CHAIN_KUBE_COMMON_FORWARD, hostnet.IPTABLES_APPEND_UNIQUE,
		true, rules)
}

func (nrc *NetworkRoutingController) startBgpServer() error {
	var nodeAsnNumber uint32
	node, err := api.GetNodeObject(nrc.GetConfig().ClientSet, nrc.GetConfig().HostnameOverride)
	if err != nil {
		return errors.New("Failed to get node object from api server: " + err.Error())
	}

	if nrc.GetConfig().FullMeshMode {
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

	if !tools.CheckForElementInArray(nrc.GetConfig().GetNodeIP().IP.String(), nrc.localAddressList) {
		nrc.localAddressList = append(nrc.localAddressList, nrc.GetConfig().GetNodeIP().IP.String())
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
	}

	if err := nrc.bgpServer.Start(global); err != nil {
		return errors.New("Failed to start BGP server due to : " + err.Error())
	}

	go nrc.watchBgpUpdates()

	g := bgpapi.NewGrpcServer(nrc.bgpServer, hostnet.NewIP(nrc.GetConfig().GetNodeIP()).ToStringWithPort(50051)+","+"127.0.0.1:50051")
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
		err := connectToExternalBGPPeers(nrc.bgpServer, nrc.globalPeerRouters, nrc.GetConfig(), nrc.peerMultihopTTL)
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

// NewNetworkRoutingController returns new NetworkRoutingController object
func NewNetworkRoutingController(kubeRouterConfig *options.KubeRouterConfig,
	nodeInformer cache.SharedIndexInformer, svcInformer cache.SharedIndexInformer,
	epInformer cache.SharedIndexInformer) controllers.ControllerType {

	var err error

	nrc := NetworkRoutingController{}
	nrc.Init("Network route controller", kubeRouterConfig.RoutesSyncPeriod, kubeRouterConfig, nrc.run)

	if kubeRouterConfig.MetricsEnabled {
		//GetData the metrics for this controller
		prometheus.MustRegister(metrics.ControllerBGPadvertisementsReceived)
		prometheus.MustRegister(metrics.ControllerBGPInternalPeersSyncTime)
		prometheus.MustRegister(metrics.ControllerBPGpeers)
		prometheus.MustRegister(metrics.ControllerRoutesSyncTime)
		nrc.MetricsEnabled = true
	}

	nrc.peerMultihopTTL = kubeRouterConfig.PeerMultihopTtl
	nrc.enablePodEgress = kubeRouterConfig.EnablePodEgress
	nrc.bgpRRClient = false
	nrc.bgpRRServer = false
	nrc.bgpServerStarted = false
	nrc.disableSrcDstCheck = kubeRouterConfig.DisableSrcDstCheck
	nrc.initSrcDstCheckDone = false

	var node *v1.Node
	if nrc.nodeInterfaceMAC = hostnet.GetInterfaceMACAddress(nrc.GetConfig().GetNodeIF()); nrc.nodeInterfaceMAC != "" {
		node = api.AnnotateNode(nrc.GetConfig().ClientSet, nrc.GetConfig().GetNode(), nodeMACAnnotation, nrc.nodeInterfaceMAC)
	}

	bgpLocalAddressListAnnotation, _ := node.ObjectMeta.Annotations[routerID]
	if "" == nrc.setRouterId(bgpLocalAddressListAnnotation, kubeRouterConfig.RouterId, nrc.GetConfig().GetNodeIP().IP.String(), fmt.Sprint(nrc.GetConfig().GetNodeIP().IP[12:])) {
		if !hostnet.NewIP(nrc.GetConfig().GetNodeIP()).IsIPv4() {
			glog.Error("Router-id must be specified in ipv6 operation")
			return nil
		}
	}

	// lets start with assumption we hace necessary IAM creds to access EC2 api
	nrc.ec2IamAuthorized = true

	if nrc.GetConfig().EnableCNI {
		nrc.cniConfFile = os.Getenv("KUBE_ROUTER_CNI_CONF_FILE")
		if nrc.cniConfFile == "" {
			nrc.cniConfFile = "/etc/cni/net.d/10-kuberouter.conf"
		}
		if _, err := os.Stat(nrc.cniConfFile); os.IsNotExist(err) {
			glog.Error("CNI conf file " + nrc.cniConfFile + " does not exist.")
			return nil
		}
	}

	nrc.ipSetHandler = hostnet.NewIPSet()

	if _, err = nrc.ipSetHandler.Create(podSubnetsIPSetName, hostnet.TypeHashNet, hostnet.OptionTimeout, "0"); err != nil {
		glog.Error(err)
		return nil
	}

	if _, err = nrc.ipSetHandler.Create(nodeAddrsIPSetName, hostnet.TypeHashIP, hostnet.OptionTimeout, "0"); err != nil {
		glog.Error(err)
		return nil
	}

	if kubeRouterConfig.EnablePodEgress || len(nrc.clusterCIDR) != 0 {
		nrc.enablePodEgress = true
	}

	if kubeRouterConfig.ClusterAsn != 0 {
		if !((kubeRouterConfig.ClusterAsn >= 64512 && kubeRouterConfig.ClusterAsn <= 65535) ||
			(kubeRouterConfig.ClusterAsn >= 4200000000 && kubeRouterConfig.ClusterAsn <= 4294967294)) {
			glog.Error("Invalid ASN number for cluster ASN")
			return nil
		}
		nrc.defaultNodeAsnNumber = uint32(kubeRouterConfig.ClusterAsn)
	} else {
		nrc.defaultNodeAsnNumber = 64512 // this magic number is first of the private ASN range, use it as default
	}

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
		if peerPasswords, err = stringSliceB64Decode(kubeRouterConfig.PeerPasswords); err != nil {
			glog.Errorf("Failed to parse CLI Peer Passwords flag: %s", err)
			return nil
		}
	}

	if nrc.globalPeerRouters, err = newGlobalPeers(kubeRouterConfig.PeerRouters, peerPorts,
		peerASNs, peerPasswords); err != nil {
		glog.Errorf("Error processing Global Peer Router configs: %s", err)
		return nil
	}

	bgpLocalAddressListAnnotation, ok := node.ObjectMeta.Annotations[bgpLocalAddressAnnotation]
	if !ok {
		glog.Infof("Could not find annotation `kube-router.io/bgp-local-addresses` on node object so BGP will listen on node IP: %s address.", nrc.GetConfig().GetNodeIP().IP.String())
		nrc.localAddressList = append(nrc.localAddressList, nrc.GetConfig().GetNodeIP().IP.String())
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
	svcInformer.AddEventHandler(nrc.ServiceEventHandler)

	nrc.epLister = epInformer.GetIndexer()
	nrc.EndpointsEventHandler = nrc.newEndpointsEventHandler()
	epInformer.AddEventHandler(nrc.EndpointsEventHandler)

	nrc.nodeLister = nodeInformer.GetIndexer()
	nrc.NodeEventHandler = nrc.newNodeEventHandler()
	nodeInformer.AddEventHandler(nrc.NodeEventHandler)

	nrc.Ipm = hostnet.NewIpTablesManager(nrc.GetConfig().GetNodeIP().IP, podEgressObsoleteChains)
	nrc.Ipm.RegisterPeriodicFunction(hostnet.CreateSnats)

	return &nrc
}
