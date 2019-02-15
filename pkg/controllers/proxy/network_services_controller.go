package proxy

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cloudnativelabs/kube-router/pkg/controllers"
	"github.com/cloudnativelabs/kube-router/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/cloudnativelabs/kube-router/pkg/utils/net-tools"
	"github.com/docker/docker/client"
	"github.com/golang/glog"
	"github.com/google/go-cmp/cmp"
	"github.com/mqliang/libipvs"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
	api "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	KUBE_DUMMY_IF       = "kube-dummy-if"
	KUBE_TUNNEL_IF      = "kube-tunnel-if"
	IFACE_NOT_FOUND     = "Link not found"
	IFACE_HAS_ADDR      = "file exists"
	IFACE_HAS_NO_ADDR   = "cannot assign requested address"
	IPVS_SERVER_EXISTS  = "file exists"
	IPVS_MAGLEV_HASHING = "mh"
	IPVS_SVC_F_SCHED1   = "flag-1"
	IPVS_SVC_F_SCHED2   = "flag-2"
	IPVS_SVC_F_SCHED3   = "flag-3"

	CHAIN_HAIRPIN = "KUBE-ROUTER-HAIRPIN"
	CHAIN_FWMARK  = "KUBE-ROUTER-FWMARK"

	svcDSRAnnotation        = "kube-router.io/service.dsr"
	svcSchedulerAnnotation  = "kube-router.io/service.scheduler"
	svcHairpinAnnotation    = "kube-router.io/service.hairpin"
	svcLocalAnnotation      = "kube-router.io/service.local"
	svcSkipLbIpsAnnotation  = "kube-router.io/service.skiplbips"
	svcSchedFlagsAnnotation = "kube-router.io/service.schedflags"

	LeaderElectionRecordAnnotationKey = "control-plane.alpha.kubernetes.io/leader"
	localIPsIPSetName                 = "kube-router-local-ips"
	ipvsServicesIPSetName             = "kube-router-ipvs-services"
	serviceIPsIPSetName               = "kube-router-service-ips"
	ipvsFirewallChainName             = "KUBE-ROUTER-SERVICES"
)

var (
	NodeIP net.IP
)

var CONTROLLER_NAME = []string{"Services controller", "NSC"}

type ipvsCalls interface {
	ipvsNewService(ks *KubeService) error
	ipvsAddService(ks *KubeService, create bool) (*libipvs.Service, error)
	ipvsDelService(ks *KubeService) error
	ipvsUpdateService(svc *libipvs.Service) error
	ipvsGetServices() ipvsServiceArrayType
	ipvsAddServer(ks *KubeService, ep *endpointInfo, update bool) (bool, error)
	ipvsNewDestination(ipvsSvc *libipvs.Service, ipvsDst *libipvs.Destination) error
	ipvsUpdateDestination(ipvsSvc *libipvs.Service, ipvsDst *libipvs.Destination) error
	ipvsGetDestinations(ipvsSvc *libipvs.Service, refresh ...bool) ipvsDestinationArrayType
	ipvsRefreshDestinations(ipvsSvc *libipvs.Service) ipvsDestinationArrayType
	ipvsDelDestination(ipvsSvc *libipvs.Service, ipvsDst *libipvs.Destination) error

	resetDestinations()
}

type netlinkCalls interface {
	ipAddrAdd(iface netlink.Link, ip *net.IPNet, addRoute bool) error
	ipAddrDel(iface netlink.Link, ip *net.IPNet) error
	prepareEndpointForDsr(containerId string, endpointIP net.IP, vip, svcPort, dstPort, proto string) error
	getKubeDummyInterface(refresh ...bool) (netlink.Link, error)
	setupRoutesForExternalIPForDSR(*serviceInfoMapType) error
	setupPolicyRoutingForDSR() error
}

// LinuxNetworking interface contains all linux networking subsystem calls
//go:generate moq -out network_services_controller_moq.go . LinuxNetworking
type LinuxNetworking interface {
	ipvsCalls
	netlinkCalls
}

type linuxNetworking struct {
	ipvsHandle     libipvs.IPVSHandle
	dummyInterface netlink.Link
	rtManager      *netutils.RouteTableManager
	lock           *utils.ChannelLockType
	dsts           map[infoMapsKeyType][]*libipvs.Destination
}

func (ln *linuxNetworking) ipAddrDel(iface netlink.Link, ip *net.IPNet) error {
	naddr := &netlink.Addr{IPNet: ip, Scope: syscall.RT_SCOPE_LINK}
	err := netlink.AddrDel(iface, naddr)
	if err != nil && err.Error() != IFACE_HAS_NO_ADDR {
		glog.Errorf("Failed to verify is external ip %s is assocated with dummy interface %s due to %s",
			naddr.IPNet.IP.String(), KUBE_DUMMY_IF, err.Error())
	}
	// Delete VIP addition to "local" rt table also, fail silently if not found (DSR special case)
	if err == nil {
		out, err := exec.Command(utils.GetPath("ip"), netutils.NewIP(ip).ProtocolCmdParam().Inet, "route", "delete", "local", ip.IP.String(), "dev", KUBE_DUMMY_IF, "table", "local", "proto", "kernel", "scope", "host", "src",
			NodeIP.String(), "table", "local").CombinedOutput()
		if err != nil && !strings.Contains(string(out), "No such process") {
			glog.Errorf("Failed to delete route to service VIP %s configured on %s. Error: %v, Output: %s", ip, KUBE_DUMMY_IF, err, out)
		}
	}
	return err
}

// utility method to assign an IP to an interface. Mainly used to assign service VIP's
// to kube-dummy-if. Also when DSR is used, used to assign VIP to dummy interface
// inside the container.
func (ln *linuxNetworking) ipAddrAdd(iface netlink.Link, ip *net.IPNet, addRoute bool) error {
	naddr := &netlink.Addr{IPNet: ip, Scope: syscall.RT_SCOPE_LINK}
	err := netlink.AddrAdd(iface, naddr)
	if err != nil && err.Error() != IFACE_HAS_ADDR {
		glog.Errorf("Failed to assign cluster ip %s to dummy interface: %s",
			naddr.IPNet.IP.String(), err.Error())
		return err
	}

	// When a service VIP is assigned to a dummy interface and accessed from host, in some of the
	// case Linux source IP selection logix selects VIP itself as source leading to problems
	// to avoid this an explicit entry is added to use node IP as source IP when accessing
	// VIP from the host. Please see https://github.com/cloudnativelabs/kube-router/issues/376

	if !addRoute {
		return nil
	}

	// TODO: netlink.RouteReplace which is replacement for below command is not working as expected. Call succeeds but
	// route is not replaced. For now do it with command.
	out, err := exec.Command(utils.GetPath("ip"), netutils.NewIP(ip).ProtocolCmdParam().Inet, "route", "replace", "local", ip.IP.String(), "dev", KUBE_DUMMY_IF, "table", "local", "proto", "kernel", "scope", "host", "src",
		NodeIP.String(), "metric", "0", "table", "local").CombinedOutput()
	if err != nil {
		glog.Errorf("Failed to replace route to service VIP %s configured on %s. Error: %v, Output: %s", ip, KUBE_DUMMY_IF, err, out)
	}
	return nil
}

func (ln *linuxNetworking) ipvsGetServices() (list ipvsServiceArrayType) {
	var err error
	if list, err = ln.ipvsHandle.ListServices(); err != nil {
		glog.Errorf("Error in ipvsGetServices: %s", err.Error())
	}
	return
}

func (ln *linuxNetworking) ipvsGetDestinations(ipvsSvc *libipvs.Service, forceUpdate ...bool) ipvsDestinationArrayType {
	ln.lock.Lock()
	defer ln.lock.Unlock()

	if len(forceUpdate) == 0 || forceUpdate[0] == false {
		if store := ln.dsts[generateFwmark(ipvsSvc)]; store != nil {
			return store
		}
	}
	return ln.ipvsRefreshDestinations(ipvsSvc)
}

func (ln *linuxNetworking) ipvsRefreshDestinations(ipvsSvc *libipvs.Service) ipvsDestinationArrayType {
	hash := generateFwmark(ipvsSvc)
	if list, err := ln.ipvsHandle.ListDestinations(ipvsSvc); err == nil {
		fmt.Println("updating for:", ipvsSvc)
		ln.dsts[hash] = list
		return list
	} else {
		delete(ln.dsts, hash)
		glog.Errorf("Error refreshing ipvsGetDestinations: %s", err.Error())
	}
	return nil
}

func (ln *linuxNetworking) wrapDestinationsChange(fn func(*libipvs.Service, *libipvs.Destination) error,
	ipvsSvc *libipvs.Service, ipvsDst *libipvs.Destination) (err error) {
	ln.lock.Lock()
	defer delete(ln.dsts, generateFwmark(ipvsSvc))
	defer ln.lock.Unlock()

	return fn(ipvsSvc, ipvsDst)
}

func (ln *linuxNetworking) ipvsDelDestination(ipvsSvc *libipvs.Service, ipvsDst *libipvs.Destination) (err error) {
	return ln.wrapDestinationsChange(ln.ipvsHandle.DelDestination, ipvsSvc, ipvsDst)
}

func (ln *linuxNetworking) ipvsNewDestination(ipvsSvc *libipvs.Service, ipvsDst *libipvs.Destination) (err error) {
	return ln.wrapDestinationsChange(ln.ipvsHandle.NewDestination, ipvsSvc, ipvsDst)
}

func (ln *linuxNetworking) ipvsUpdateDestination(ipvsSvc *libipvs.Service, ipvsDst *libipvs.Destination) (err error) {
	return ln.wrapDestinationsChange(ln.ipvsHandle.UpdateDestination, ipvsSvc, ipvsDst)
}

func (ln *linuxNetworking) ipvsDelService(ks *KubeService) (err error) {
	ln.lock.Lock()
	defer ln.lock.Unlock()

	if err = ln.ipvsHandle.DelService(ks.Service); err == nil {
		delete(ln.dsts, ks.ipvsHash)
	}
	return err
}

func (ln *linuxNetworking) ipvsUpdateService(svc *libipvs.Service) error {
	return ln.ipvsHandle.UpdateService(svc)
}

func (ln *linuxNetworking) ipvsNewService(ks *KubeService) error {
	return ln.ipvsHandle.NewService(ks.Service)
}

func (ln *linuxNetworking) resetDestinations() {
	ln.dsts = make(map[infoMapsKeyType][]*libipvs.Destination)
}

func newLinuxNetworking() (*linuxNetworking, error) {
	ln := &linuxNetworking{}
	ipvsHandle, err := libipvs.New()
	if err != nil {
		return nil, err
	}
	ln.ipvsHandle = ipvsHandle
	ln.lock = utils.NewChanLock(1)
	ln.resetDestinations()

	ln.getKubeDummyInterface(true)

	ln.rtManager = netutils.NewRouteTableManager(&customRouteTables)
	return ln, nil
}

// NetworkServicesController enables local node as network service proxy through IPVS/LVS.
// Support only Kubernetes network services of type NodePort, ClusterIP, and LoadBalancer. For each service a
// IPVS service is created and for each service endpoint a server is added to the IPVS service.
// As services and endpoints are updated, network service controller gets the updates from
// the kubernetes api server and syncs the ipvs configuration to reflect state of services
// and endpoints

// NetworkServicesController struct stores information needed by the controller
type NetworkServicesController struct {
	nodeIP              net.IP
	nodeHostName        string
	syncPeriod          time.Duration
	onUpdateChannel     *utils.ChannelLockType
	serviceMap          serviceInfoMapType
	podCidr             string
	masqueradeAll       bool
	globalHairpin       bool
	client              kubernetes.Interface
	nodeportBindOnAllIp bool
	MetricsEnabled      bool
	ln                  LinuxNetworking
	Ipm                 *netutils.IpTablesManager
	ipSet               *netutils.IPSet
	readyForUpdates     bool

	svcLister cache.Indexer
	epLister  cache.Indexer
	podLister cache.Indexer

	ServiceEventHandler   cache.ResourceEventHandler
	EndpointsEventHandler cache.ResourceEventHandler
}

type kubeServiceArrayType []*KubeService
type ipvsServiceArrayType []*libipvs.Service
type ipvsDestinationArrayType []*libipvs.Destination

// internal representation of kubernetes service
type serviceMeta struct {
	name      string
	namespace string
	portName  string

	change synchChangeType
}

type serviceInfo struct {
	Nodeport                 uint16
	HealthCheckPort          int
	DirectServerReturnMethod *libipvs.FwdMethod
	Hairpin                  bool
	SkipLbIps                bool
	ExternalIPs              []string
	LoadBalancerIPs          []string
	Local                    bool
}

type serviceObject struct {
	meta *serviceMeta
	info *serviceInfo
	ksvc *KubeService

	linkedServices linkedServiceListMapType

	endpoints *endpointInfoMapType
	nsc       *NetworkServicesController

	epLock *utils.ChannelLockType
}

type linkedServiceListMapType map[linkedServiceType]*kubeServiceArrayType

// map of all services, with unique service id(namespace name, service name, Port) as key
type serviceInfoMapType map[infoMapsKeyType]*serviceObject

type endpointInfo struct {
	*libipvs.Destination
	so *serviceObject

	*UsageLockType
	change    synchChangeType
	connTrack bool
	isLocal   bool
}

var activeReferences activeAddrsMapType

type infoMapsKeyType uint32

type activeAddrsMapType map[string]bool
type endpointInfoMapType map[infoMapsKeyType]*endpointInfo

func (nsc *NetworkServicesController) GetData() ([]string, time.Duration) {
	return CONTROLLER_NAME, nsc.syncPeriod
}

var data keyMetrics

// Run periodically sync ipvs configuration to reflect desired state of services and endpoints
func (nsc *NetworkServicesController) Run(healthChan chan *controllers.ControllerHeartbeat, stopCh <-chan struct{}, wg *sync.WaitGroup) error {

	t := time.NewTicker(nsc.syncPeriod)
	defer t.Stop()
	defer wg.Done()

	glog.Infof("Starting network services controller")

	// enable masquerad rule
	err := nsc.ensureMasqueradeIptablesRule(nsc.masqueradeAll, nsc.podCidr, nsc.nodeIP)
	if err != nil {
		return errors.New("Failed to do add masquerade rule in POSTROUTING chain of nat table due to: %s" + err.Error())
	}
	sysctlConfig := []utils.SysCtlConfigRuleType{
		// https://www.kernel.org/doc/Documentation/networking/ipvs-sysctl.txt
		// enable Ipvs connection tracking
		{"net/ipv4/vs/conntrack", 1},
		// LVS failover not working with UDP packets https://access.redhat.com/solutions/58653
		{"net/ipv4/vs/expire_nodest_conn", 1},
		// LVS failover not working with UDP packets https://access.redhat.com/solutions/58653
		{"net/ipv4/vs/expire_quiescent_template", 1},
		// https://github.com/kubernetes/kubernetes/pull/71114
		{"net/ipv4/vs/conn_reuse_mode", 2},
		// https://github.com/kubernetes/kubernetes/pull/70530/files
		{"net/ipv4/conf/all/arp_ignore", 1},
		// https://github.com/kubernetes/kubernetes/pull/70530/files
		{"net/ipv4/conf/all/arp_announce", 2},
	}

	for _, config := range sysctlConfig {
		if err := utils.SetSysctl(config); err != nil {
			return err
		}
	}

	// https://github.com/cloudnativelabs/kube-router/issues/282
	err = nsc.setupIpvsFirewall()
	if err != nil {
		return errors.New("Error setting up ipvs firewall: " + err.Error())
	}

	// loop forever unitl notified to stop on stopCh
	for {
		select {
		case <-stopCh:
			glog.Info("Shutting down network services controller")
			return nil
		default:
		}
		glog.V(1).Info("Performing periodic sync of Ipvs services")
		err := nsc.syncIpvsServices()
		if err != nil {
			fmt.Println("Error: ", err.Error())
		}
		if err != nil {
			glog.Errorf("Error during periodic Ipvs sync in network service controller. Error: " + err.Error())
			glog.Errorf("Skipping sending heartbeat from network service controller as periodic sync failed.")
		} else {
			dataCopy := data
			data = keyMetrics{}
			healthcheck.SendHeartBeat(healthChan, nsc, dataCopy)
		}
		nsc.readyForUpdates = true
		select {
		case <-stopCh:
			glog.Info("Shutting down network services controller")
			return nil
		case <-t.C:
		}
	}
}
func (nsc *NetworkServicesController) createIpSet() (*netutils.IPSet, error) {
	var err error

	ipset := netutils.NewIPSet()
	// Create ipset for local addresses.
	if _, err = ipset.Create(localIPsIPSetName, netutils.TypeHashIP, netutils.OptionTimeout, "0"); err != nil {
		return nil, fmt.Errorf("failed to create ipset: %s", err.Error())
	}

	// Create 2 ipsets for services. One for 'ip' and one for 'ip,port'
	if _, err = ipset.Create(serviceIPsIPSetName, netutils.TypeHashIP, netutils.OptionTimeout, "0"); err != nil {
		return nil, fmt.Errorf("failed to create ipset: %s", err.Error())
	}

	if _, err = ipset.Create(ipvsServicesIPSetName, netutils.TypeHashIPPort, netutils.OptionTimeout, "0"); err != nil {
		return nil, fmt.Errorf("failed to create ipset: %s", err.Error())
	}

	return ipset, nil
}

func getIpvsFirewallInputChainRule() []string {
	// The iptables rule for use in {setup,cleanup}IpvsFirewall.
	return []string{
		"-m", "comment", "--comment", "handle traffic to IPVS service IPs in custom chain",
		"-m", "set", "--match-set", serviceIPsIPSetName, "dst",
		"-j", ipvsFirewallChainName}
}

func (nsc *NetworkServicesController) ipvsFwBuildAux(p netutils.Proto) (err error) {
	helper := netutils.NewIP(p)

	commentAllow := "allow input traffic to ipvs services"
	commentEcho := "allow icmp echo requests to service IPs"
	commentReject := "reject all unexpected traffic to service IPs"

	//rules := []netutils.IpTablesPtrType{
	rules := netutils.NewRuleList("-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	rules.Add(netutils.NewRule("-m", "comment", "--comment", commentAllow, "-m", "set", "--match-set", ipvsServicesIPSetName, "dst,dst", "-j", "ACCEPT"))
	rules.Add(netutils.NewRule("-m", "comment", "--comment", commentEcho, "-p", helper.ProtocolCmdParam().IcmpStr,
		"--"+helper.ProtocolCmdParam().IcmpStr+"-type", "echo-request", "-j", "ACCEPT"))

	// We exclude the local addresses here as that would otherwise block all
	// traffic to local addresses if any NodePort service exists.
	rules.Add(netutils.NewRule("-m", "comment", "--comment", commentReject, "-m", "set", "!", "--match-set", localIPsIPSetName, "dst", "-j", "REJECT"))

	return nsc.Ipm.CreateIpTablesRuleWithChain(p, "filter", ipvsFirewallChainName, netutils.IPTABLES_FULL_CHAIN_SYNC, netutils.NoReferencedChains, true, rules)
}

func (nsc *NetworkServicesController) ipvsFwCreateRule(p netutils.Proto) (err error) {
	var exists bool

	// Pass incomming traffic into our custom chain.
	ipvsFirewallInputChainRule := getIpvsFirewallInputChainRule()
	if exists, err = nsc.Ipm.GetHandler(p).Exists("filter", "INPUT", ipvsFirewallInputChainRule...); err != nil {
		return fmt.Errorf("Failed to run iptables command: %s", err.Error())
	} else if !exists {
		if err = nsc.Ipm.GetHandler(p).Insert("filter", "INPUT", 1, ipvsFirewallInputChainRule...); err != nil {
			return fmt.Errorf("Failed to run iptables command: %s", err.Error())
		}
	}

	return nil
}

func (nsc *NetworkServicesController) setupIpvsFirewall() (err error) {
	/*
	   - create ipsets
	   - create firewall rules
	*/

	if nsc.ipSet == nil {
		if nsc.ipSet, err = nsc.createIpSet(); err != nil {
			return fmt.Errorf("failed to create ipset: %s", err.Error())
		}
	}

	err = netutils.UsedTcpProtocols.ForEach(nsc.ipvsFwBuildAux)

	if err == nil {
		err = netutils.UsedTcpProtocols.ForEachWithLock(nsc.ipvsFwCreateRule)
	}

	if err != nil {
		glog.Errorf("Error setting up ipvs firewall: %s", err.Error())
	}
	return err
}

func (nsc *NetworkServicesController) syncIpvsFirewall(svcs map[*KubeService]*serviceObject) error {
	/*
	   - update ipsets based on currently active IPVS services
	*/
	var err error

	if err = nsc.setupIpvsFirewall(); err != nil {
		return err
	}

	// Populate local addresses ipset.
	if addrs, err := getAllLocalIPs(true, "dummy", "kube", "docker"); err == nil {
		err = nsc.ipSet.Get(localIPsIPSetName).Refresh(addrs)
		if err != nil {
			return fmt.Errorf("failed to sync ipset: %s", err.Error())
		}
	}

	// Populate service ipsets.
	serviceIPsSets := make([]string, len(svcs))
	ipvsServicesSets := make([]string, len(svcs))

	i := 0
	for svc := range svcs {
		serviceIPsSets[i] = svc.Address.String()
		ipvsServicesSets[i] = fmt.Sprintf("%s,%s:%d", svc.Address.String(), svc.Protocol.String(), svc.Port)
		i++
	}

	if err = nsc.ipSet.Get(serviceIPsIPSetName).Refresh(serviceIPsSets); err != nil {
		glog.Errorf("failed to sync ipset: %s", err.Error())
	}

	if err = nsc.ipSet.Get(ipvsServicesIPSetName).Refresh(ipvsServicesSets); err != nil {
		glog.Errorf("failed to sync ipset: %s", err.Error())
	}

	return nil
}

func (nsc *NetworkServicesController) cleanupIpvsFirewall() {
	/*
	   - delete firewall rules
	   - delete ipsets
	*/
	netutils.UsedTcpProtocols.ForEach(func(p netutils.Proto) error {
		return nsc.Ipm.IptablesCleanUpChain(p, ipvsFirewallChainName, true)
	})

	ipset := netutils.NewIPSet()
	ipset.Save()
	ipset.DestroyAllWithin()
}

func (nsc *NetworkServicesController) pushMetrics(meta *serviceMeta, svc *libipvs.Service) {
	if svc == nil {
		return
	}
	glog.V(3).Infof("Publishing metrics for %s/%s (%s:%d/%s)", meta.namespace, meta.name, svc.Address.String(), svc.Port, svc.Protocol)
	metrics.ServiceBpsIn.WithLabelValues(meta.namespace, meta.name, svc.Address.String(), svc.Protocol.String(), fmt.Sprint(svc.Port)).Set(float64(svc.Stats.BPSIn))
	metrics.ServiceBpsOut.WithLabelValues(meta.namespace, meta.name, svc.Address.String(), svc.Protocol.String(), fmt.Sprint(svc.Port)).Set(float64(svc.Stats.BPSOut))
	metrics.ServiceBytesIn.WithLabelValues(meta.namespace, meta.name, svc.Address.String(), svc.Protocol.String(), fmt.Sprint(svc.Port)).Set(float64(svc.Stats.BytesIn))
	metrics.ServiceBytesOut.WithLabelValues(meta.namespace, meta.name, svc.Address.String(), svc.Protocol.String(), fmt.Sprint(svc.Port)).Set(float64(svc.Stats.BytesOut))
	metrics.ServiceCPS.WithLabelValues(meta.namespace, meta.name, svc.Address.String(), svc.Protocol.String(), fmt.Sprint(svc.Port)).Set(float64(svc.Stats.CPS))
	metrics.ServicePacketsIn.WithLabelValues(meta.namespace, meta.name, svc.Address.String(), svc.Protocol.String(), fmt.Sprint(svc.Port)).Set(float64(svc.Stats.PacketsIn))
	metrics.ServicePacketsOut.WithLabelValues(meta.namespace, meta.name, svc.Address.String(), svc.Protocol.String(), fmt.Sprint(svc.Port)).Set(float64(svc.Stats.PacketsOut))
	metrics.ServicePpsIn.WithLabelValues(meta.namespace, meta.name, svc.Address.String(), svc.Protocol.String(), fmt.Sprint(svc.Port)).Set(float64(svc.Stats.PPSIn))
	metrics.ServicePpsOut.WithLabelValues(meta.namespace, meta.name, svc.Address.String(), svc.Protocol.String(), fmt.Sprint(svc.Port)).Set(float64(svc.Stats.PPSOut))
	metrics.ServiceTotalConn.WithLabelValues(meta.namespace, meta.name, svc.Address.String(), svc.Protocol.String(), fmt.Sprint(svc.Port)).Set(float64(svc.Stats.Connections))
}

func (nsc *NetworkServicesController) OnUpdate(oldObj interface{}, newObj interface{}) {
	if isEndpointsForLeaderElection(newObj) {
		return
	}

	glog.V(1).Infof("Received update from watch API")
	if !nsc.readyForUpdates {
		glog.V(3).Infof("Skipping update to endpoint: controller still performing bootup full-sync")
		return
	}

	afterPickupOnce.Do(func() {
		nsc.onUpdateChannel.Lock()
		timer = time.AfterFunc(500*time.Millisecond, nsc.pickupQueue)
	})
	updatesQueue <- &utils.ApiTransaction{oldObj, newObj}
}

func (nsc *NetworkServicesController) pickupQueue() {
	afterPickupOnce = &sync.Once{}
	nrUpdates := 0

	defer func() {
		timer = nil
		nsc.onUpdateChannel.Unlock()
	}()

	for {
		select {
		case update := <-updatesQueue:
			nsc.updateObjects(update.Old, update.New)
			nrUpdates++
		default:
			if nrUpdates == 0 {
				return
			}

			nsc.syncRelatedInfrastructure()
			return
		}
	}
}

var timer *time.Timer
var afterPickupOnce *sync.Once
var updatesQueue chan *utils.ApiTransaction

func init() {
	timer = nil
	afterPickupOnce = &sync.Once{}
	updatesQueue = make(chan *utils.ApiTransaction, 10)
}

func (nsc *NetworkServicesController) updateObjects(oldObj interface{}, newObj interface{}) {
	switch newTyped := newObj.(type) {
	case *api.Service:
		nsc.deployChanges(nsc.buildServicesInfoFrom(&nsc.serviceMap, oldObj.(*api.Service), true), nsc.buildServicesInfoFrom(&nsc.serviceMap, newTyped, false), true)
	case *api.Endpoints:
		nsc.deployChanges(nsc.buildEndpointsInfoFrom(&nsc.serviceMap, oldObj.(*api.Endpoints), true), nsc.buildEndpointsInfoFrom(&nsc.serviceMap, newTyped, false), false)
	default:
	}
}

func (nsc *NetworkServicesController) deployChanges(oldMap map[infoMapsKeyType]bool, newMap map[infoMapsKeyType]bool, service bool) {
	start := time.Now()
	defer glog.V(0).Info("Transaction sync services controller took ", time.Since(start))

	for key := range oldMap {
		if !newMap[key] {
			nsc.serviceMap[key].updateIpvs(SYNCH_NOT_FOUND)
		}
	}

	for key := range newMap {
		if !nsc.serviceMap[key].meta.change.CheckFor(SYNCH_CHANGED) {
			continue
		}
		markEndpoints(nsc.serviceMap[key], SYNCH_NOT_FOUND)
	}

	keyMap := make(map[string]bool)
	for key := range newMap {
		if !nsc.serviceMap[key].meta.change.CheckFor(SYNCH_CHANGED) {
			continue
		}
		k := nsc.serviceMap[key].meta.namespace + "/" + nsc.serviceMap[key].meta.name
		if _, ok := keyMap[k]; ok {
			continue
		}
		eps, ok, _ := nsc.epLister.GetByKey(k)
		if !ok {
			continue
		}
		nsc.buildEndpointsInfoFrom(&nsc.serviceMap, eps.(*api.Endpoints), false)
	}

	for key := range newMap {
		nsc.serviceMap[key].deployService(SYNCH_CHANGED)
		nsc.serviceMap[key].updateIpvs()
	}

	if !service {
		return
	}

	// sync ipsets
	for key := range newMap {
		for _, ls := range nsc.serviceMap[key].linkedServices {
			ls.forEach(func(ks *KubeService) {
				nsc.ipSet.Get(serviceIPsIPSetName).Add(ks.Address.String())
				nsc.ipSet.Get(ipvsServicesIPSetName).Add(fmt.Sprintf("%s,%s:%d", ks.Address.String(), ks.Protocol.String(), ks.Port))
			})
		}
	}
}

// sync the Ipvs service and server details configured to reflect the desired state of services and endpoint
// as learned from services and endpoints information from the api server
func (nsc *NetworkServicesController) syncIpvsServices() (err error) {
	nsc.onUpdateChannel.Lock()

	start := time.Now()
	defer func() {
		nsc.onUpdateChannel.Unlock()
		endTime := time.Since(start)
		if nsc.MetricsEnabled {
			metrics.ControllerIpvsServicesSyncTime.Observe(endTime.Seconds())
		}
		glog.V(0).Infof("Sync Ipvs services took %v", endTime)
		data.lastSync = endTime
	}()

	dummyVipInterface, err := nsc.ln.getKubeDummyInterface(true)
	if err != nil {
		return errors.New("Failed creating dummy interface: " + err.Error())
	}

	nsc.ln.resetDestinations()

	if err = nsc.ln.setupPolicyRoutingForDSR(); err != nil {
		return err
	}

	nsc.serviceMap.ForEach(func(so *serviceObject) {
		so.meta.change = SYNCH_NOT_FOUND
		markEndpoints(so, SYNCH_NOT_FOUND)
	})

	nsc.buildServicesInfo(&nsc.serviceMap)
	nsc.buildEndpointsInfo(&nsc.serviceMap)

	activeReferences = make(activeAddrsMapType)

	glog.V(1).Infof("Full-Syncing IPVS services")

	for _, so := range nsc.serviceMap {
		so.deployService()
		so.updateIpvs()
	}

	nsc.syncRelatedInfrastructure()

	type destinationsMap map[infoMapsKeyType]*libipvs.Destination

	activeSvcList := make(map[*KubeService]*serviceObject, 0)
	activeNativeSvcList := make(map[infoMapsKeyType]*serviceObject)
	activeDstMap := make(map[infoMapsKeyType]destinationsMap)
	smRemove := make([]infoMapsKeyType, 0)

	for id, so := range nsc.serviceMap {
		if so.meta.change.CheckFor(SYNCH_NOT_FOUND) {
			smRemove = append(smRemove, id)
			continue
		}
		if so.getEps().Size() == 0 {
			continue
		}
		for _, ls := range so.linkedServices {
			ls.forEach(func(ks *KubeService) {
				activeSvcList[ks] = so

				activeNativeSvcList[ks.ipvsHash] = so

				if !ks.isFwMarkService() {
					activeReferences[ks.Address.String()] = true
				}

				activeDstMap[ks.ipvsHash] = make(destinationsMap)
				so.getEps().forEach(func(dst *endpointInfo) {
					activeDstMap[ks.ipvsHash][generateId(dst)] = dst.Destination
				})
			})
		}
		data.destinations += len(so.linkedServices) * so.getEps().Size()
		data.services += len(so.linkedServices)
	}

	for i := range smRemove {
		delete(nsc.serviceMap, smRemove[i])
	}

	go nsc.syncIpvsFirewall(activeSvcList)

	allSvcs := nsc.ln.ipvsGetServices()

	startMetrics := time.Now()
	metrics.ControllerIpvsServices.Set(float64(len(allSvcs)))

	for _, svc := range allSvcs {
		hash := svc.FWMark
		if hash == 0 {
			hash = uint32(generateFwmark(svc))
		}
		if activeNativeSvcList[infoMapsKeyType(hash)] != nil {
			if nsc.MetricsEnabled {
				nsc.pushMetrics(activeNativeSvcList[infoMapsKeyType(hash)].meta, svc)
			}
			continue
		}

		dsts := nsc.ln.ipvsGetDestinations(svc)
		sizeDestinations := len(dsts)
		for _, dst := range dsts {
			if dst.Weight == 1 {
				nsc.ln.ipvsDelDestination(svc, dst)
				sizeDestinations--
			}
		}
		if sizeDestinations == 0 {
			nsc.ln.ipvsDelService(&KubeService{Service: svc})
		}
	}

	if nsc.MetricsEnabled {
		endTimeMetrics := time.Since(startMetrics)
		metrics.ControllerIpvsMetricsExportTime.Observe(float64(endTimeMetrics.Seconds()))
	}

	for ks, so := range activeSvcList {
		dsts := nsc.ln.ipvsGetDestinations(ks.Service)

		so.epLock.Lock()
		if len(dsts) != so.getEps().Size() {
			so.meta.change |= SYNCH_NEW
			so.deployService()
			so.updateIpvs(SYNCH_NEW)
			dsts = nsc.ln.ipvsGetDestinations(ks.Service)
		}

		for _, dst := range dsts {
			id := generateId(&libipvs.Service{Address: dst.Address, Protocol: ks.Protocol, Port: dst.Port})
			if activeDstMap[ks.ipvsHash][id] == nil {
				nsc.ln.ipvsDelDestination(ks.Service, dst)
			}
		}
		so.epLock.Unlock()
	}

	nsc.syncIfAddress(dummyVipInterface, &activeReferences)
	return nil
}

func (nsc *NetworkServicesController) syncRelatedInfrastructure() {
	var err error

	glog.V(1).Infof("Setting up custom route table required to add routes for external IP's.")
	if err = nsc.ln.setupRoutesForExternalIPForDSR(&nsc.serviceMap); err != nil {
		glog.Error("Failed setup custom routing table required to add routes for external IP's due to: " + err.Error())
	}
	glog.V(1).Infof("Custom routing table " + customRouteTables[ROUTE_TABLE_EXTERNAL].Name + " required for Direct Server Return is setup as expected.")

	if err = nsc.ensureMasqueradeIptablesRule(nsc.masqueradeAll, nsc.podCidr, nsc.nodeIP); err != nil {
		glog.Errorf("Error masquerade iptable rules: %s", err.Error())
	}

	if err = nsc.syncHairpinIptablesRules(); err != nil {
		glog.Errorf("Error syncing Hairpin iptable rules: %s", err.Error())
	}

	if err = nsc.syncFwmarkIptablesRules(); err != nil {
		glog.Errorf("Error syncFwmarkIptablesRules iptable rules: %s", err.Error())
	}
}

func markEndpoints(so *serviceObject, mark synchChangeType) {
	so.getEps().forEach(func(ep *endpointInfo) {
		if ep.Weight == 0 {
			return
		}
		if mark == SYNCH_NOT_FOUND && ep.change.CheckFor(mark) {
			delete(*so.endpoints, generateId(ep))
			return
		}
		ep.change = mark
	})
}

func (nsc *NetworkServicesController) syncIfAddress(link netlink.Link, act *activeAddrsMapType) (err error) {
	var addrs []*net.IPNet
	addrs, err = getAllLocalIPs(false, KUBE_DUMMY_IF)
	if err != nil {
		return errors.New("Failed to list dummy interface IPs: " + err.Error())
	}
	for _, addr := range addrs {
		if !(*act)[addr.IP.String()] {
			glog.V(1).Infof("Found an IP %s which is no longer needed so cleaning up", addr.String())
			err = nsc.ln.ipAddrDel(link, addr)
			if err != nil {
				glog.Errorf("Failed to delete stale IP %s due to: %s",
					addr.IP.String(), err.Error())
				continue
			}
		}
	}

	return
}

func (nsc *NetworkServicesController) getPodObjectForEndpoint(endpointIP string) (*api.Pod, error) {
	for _, obj := range nsc.podLister.List() {
		pod := obj.(*api.Pod)
		if strings.Compare(pod.Status.PodIP, endpointIP) == 0 {
			return pod, nil
		}
	}
	return nil, errors.New("Failed to find pod with ip " + endpointIP)
}

// This function does the following
// - get the pod corresponding to the endpoint Ip
// - get the container id from pod spec
// - from the container id, use docker client to get the pid
// - enter process network namespace and create ipip tunnel
// - add VIP to the tunnel interface
// - disable rp_filter
func (ln *linuxNetworking) prepareEndpointForDsr(containerId string, ip net.IP, vip, svcPort, dstPort, proto string) error {

	endpointIP := ip.String()

	dockerClient, err := client.NewEnvClient()
	if err != nil {
		return errors.New("Failed to get docker client due to " + err.Error())
	}
	defer dockerClient.Close()

	containerSpec, err := dockerClient.ContainerInspect(context.Background(), containerId)
	if err != nil {
		return errors.New("Failed to get docker container spec due to " + err.Error())
	}

	pid := containerSpec.State.Pid

	var cmdParams = netutils.NewIP(ip).ProtocolCmdParam()
	if _, err = runInNetNS(pid, utils.GetPath("ip"), cmdParams.Inet, "l", "show", KUBE_TUNNEL_IF); err != nil {
		if !strings.Contains(err.Error(), "does not exist") {
			return errors.New("Failed to verify if ipip tunnel interface exists in endpoint " + endpointIP + " namespace due to " + err.Error())
		}

		glog.V(2).Infof("Could not find tunnel interface " + KUBE_TUNNEL_IF + " in endpoint " + endpointIP + " so creating one.")
		if _, err = runInNetNS(pid, utils.GetPath("ip"), cmdParams.Inet, "tunnel", "add", KUBE_TUNNEL_IF, "mode", cmdParams.Mode, "local", endpointIP); err != nil {
			return errors.New("Failed to add ipip tunnel interface in endpoint namespace due to " + err.Error())
		}

		if _, err = runInNetNS(pid, utils.GetPath("ip"), cmdParams.Inet, "l", "show", KUBE_TUNNEL_IF); err != nil {
			return errors.New("Failed to get " + KUBE_TUNNEL_IF + " tunnel interface handle due to " + err.Error())
		}
		glog.V(2).Infof("Successfully created tunnel interface " + KUBE_TUNNEL_IF + " in endpoint " + endpointIP + ".")
	}

	// set mtu - 1500 with LLC -> 1492 - 20(40 for ipv6) - 20(40 for ipv6) (twice, if we have overlays, because worst case we have tunnel in tunnel)
	if _, err = runInNetNS(pid, utils.GetPath("ip"), cmdParams.Inet, "l", "set", "mtu", fmt.Sprint(1492 - 2*cmdParams.ReduceMTU), KUBE_TUNNEL_IF); err != nil {
		return errors.New("Failed to bring up ipip tunnel interface in endpoint namespace due to " + err.Error())
	}

	// bring the tunnel interface up
	if _, err = runInNetNS(pid, utils.GetPath("ip"), cmdParams.Inet, "l", "set", "up", KUBE_TUNNEL_IF); err != nil {
		return errors.New("Failed to bring up ipip tunnel interface in endpoint namespace due to " + err.Error())
	}

	// assign VIP to the KUBE_TUNNEL_IF interface
	if _, err = runInNetNS(pid, utils.GetPath("ip"), cmdParams.Inet, "a", "replace", vip, "dev", KUBE_TUNNEL_IF); err != nil {
		return errors.New("Failed to bring up ipip tunnel interface in endpoint namespace due to " + err.Error())
	}
	glog.Infof("Successfully assinged VIP: " + vip + " in endpoint " + endpointIP + ".")

	if cmdParams.Inet == "-4" {
		_, err = runInNetNS(pid, utils.GetPath("sysctl"), "-w", "net.ipv4.conf.kube-tunnel-if.rp_filter=0")
		if err == nil {
			_, err = runInNetNS(pid, utils.GetPath("sysctl"), "-w", "net.ipv4.conf.eth0.rp_filter=0")
		}
		if err == nil {
			_, err = runInNetNS(pid, utils.GetPath("sysctl"), "-w", "net.ipv4.conf.all.rp_filter=0")
		}
		if err != nil {
			return errors.New("Failed to disable rp_filters " + err.Error())
		}
	}
	glog.Infof("Successfully disabled rp_filter in endpoint " + endpointIP + ".")

	nat := []string{"PREROUTING", "-t", "nat", "-p", proto, "-m", proto, "--dport", svcPort, "-j", "REDIRECT", "--to-port", dstPort, "-w"}
	if _, err = runInNetNS(pid, cmdParams.IptCmd, append([]string{"-C"}, nat...)...); err != nil {
		_, err = runInNetNS(pid, cmdParams.IptCmd, append([]string{"-I"}, nat...)...)
	}
	return err
}

var protocolParser = map[string]libipvs.Protocol{
	string(api.ProtocolTCP): libipvs.Protocol(syscall.IPPROTO_TCP),
	string(api.ProtocolUDP): libipvs.Protocol(syscall.IPPROTO_UDP),
}

func (nsc *NetworkServicesController) buildServicesInfo(serviceMap *serviceInfoMapType) {
	var svc *api.Service
	for _, obj := range nsc.svcLister.List() {
		svc = obj.(*api.Service)

		if svc.Spec.ClusterIP == "None" || svc.Spec.ClusterIP == "" {
			glog.V(2).Infof("Skipping service name:%s namespace:%s as there is no cluster IP", svc.Name, svc.Namespace)
			continue
		}

		if svc.Spec.Type == "ExternalName" {
			glog.V(2).Infof("Skipping service name:%s namespace:%s due to service Type=%s", svc.Name, svc.Namespace, svc.Spec.Type)
			continue
		}

		nsc.buildServicesInfoFrom(serviceMap, svc, false)
	}
}

func (nsc *NetworkServicesController) buildServicesInfoFrom(serviceMap *serviceInfoMapType, apiSvc *api.Service, remove bool) (keys map[infoMapsKeyType]bool) {
	keys = make(map[infoMapsKeyType]bool)
	if apiSvc.ObjectMeta.Name == "" && apiSvc.ObjectMeta.Namespace == "" {
		return
	}

	for _, port := range apiSvc.Spec.Ports {
		meta := &serviceMeta{
			name:      apiSvc.ObjectMeta.Name,
			namespace: apiSvc.ObjectMeta.Namespace,
			portName:  port.Name,
			change:    SYNCH_NEW,
		}

		svcId := generateId(meta)
		keys[svcId] = true

		if (*serviceMap)[svcId] == nil {
			(*serviceMap)[svcId] = nsc.newServiceObject(&serviceObject{meta: meta})
		}

		if remove {
			(*serviceMap)[svcId].meta.change = SYNCH_NOT_FOUND
			return
		}

		var so = (*serviceMap)[svcId]

		nsc.updateCheckChange(so, apiSvc, &port)

		if so.meta.change.CheckFor(SYNCH_NEW) {
			so.ksvc.ipvsHash = generateFwmark(so.ksvc.Service)
			for key := range *serviceMap {
				if cmp.Equal((*serviceMap)[key].ksvc, so.ksvc, ComparerKubeService) && key != svcId {
					(*serviceMap)[key].meta.change = SYNCH_NOT_FOUND
					*(*serviceMap)[key].endpoints = make(endpointInfoMapType)
				}
			}
		}

		so.nsc = nsc
	}
	return
}

func (nsc *NetworkServicesController) updateCheckChange(so *serviceObject, svc *api.Service, port *api.ServicePort) {
	var changed = SYNCH_NO_CHANGE

	for _, obj := range []interface{}{so.ksvc.Service, so.info} {
		var equal = true
		switch objTyped := obj.(type) {
		case *serviceInfo:
			old := *objTyped
			equal = cmp.Equal(&old, nsc.buildServiceInfo(objTyped, svc, port))
		case *libipvs.Service:
			old := *objTyped
			equal = cmp.Equal(&old, nsc.buildIpvsService(objTyped, svc, port))
		}
		if !equal {
			changed |= SYNCH_CHANGED
		}
	}

	if so.meta.change.CheckFor(SYNCH_NEW) {
		return
	}

	if changed.CheckFor(SYNCH_CHANGED) {
		so.meta.change = SYNCH_CHANGED
		return
	}

	so.meta.change = SYNCH_NO_CHANGE
}

func (nsc *NetworkServicesController) buildServiceInfo(svcInfo *serviceInfo, svc *api.Service, port *api.ServicePort) *serviceInfo {
	svcInfo.Nodeport = uint16(port.NodePort)
	svcInfo.ExternalIPs = append(svc.Spec.ExternalIPs)
	if dsrMethod, ok := svc.ObjectMeta.Annotations[svcDSRAnnotation]; ok {
		dsr, _ := libipvs.ParseFwdMethod(dsrMethod)
		svcInfo.DirectServerReturnMethod = &dsr
	}

	for _, lbIngress := range svc.Status.LoadBalancer.Ingress {
		if _, ok := svc.ObjectMeta.Annotations[svcSkipLbIpsAnnotation]; ok && len(lbIngress.IP) > 0 {
			svcInfo.LoadBalancerIPs = append(svcInfo.LoadBalancerIPs, lbIngress.IP)
		}
	}
	_, svcInfo.Hairpin = svc.ObjectMeta.Annotations[svcHairpinAnnotation]
	_, svcInfo.Local = svc.ObjectMeta.Annotations[svcLocalAnnotation]

	if svc.Spec.ExternalTrafficPolicy == api.ServiceExternalTrafficPolicyTypeLocal {
		svcInfo.Local = true
	}
	return svcInfo
}

func (nsc *NetworkServicesController) buildIpvsService(s *libipvs.Service, svc *api.Service, port *api.ServicePort) *libipvs.Service {
	iqip := netutils.NewIP(svc.Spec.ClusterIP)
	s.Address = iqip.ToIP()
	s.Protocol = protocolParser[string(port.Protocol)]
	s.Port = uint16(port.Port)
	s.SchedName = libipvs.RoundRobin
	s.Netmask = iqip.ToIpvsNetmask()
	s.AddressFamily = libipvs.AddressFamily(iqip.Family())
	s.Flags = libipvs.Flags{
		Flags: libipvs.IP_VS_SVC_F_HASHED,
		Mask:  ^uint32(libipvs.IP_VS_SVC_F_HASHED),
	}

	if schedulingMethod, ok := svc.ObjectMeta.Annotations[svcSchedulerAnnotation]; ok {
		s.SchedName = schedulingMethod
	}

	flags, ok := svc.ObjectMeta.Annotations[svcSchedFlagsAnnotation]
	if ok && s.SchedName == IPVS_MAGLEV_HASHING {
		s.Flags.Flags |= parseSchedFlags(flags)
	}
	if svc.Spec.SessionAffinity == "ClientIP" {
		s.Flags.Flags |= libipvs.IP_VS_SVC_F_PERSISTENT
		s.Timeout = 180 * 60
	}
	return s
}

var schedFlagsParser = map[string]uint32{
	IPVS_SVC_F_SCHED1: uint32(libipvs.IP_VS_SVC_F_SCHED1),
	IPVS_SVC_F_SCHED2: uint32(libipvs.IP_VS_SVC_F_SCHED2),
	IPVS_SVC_F_SCHED3: uint32(libipvs.IP_VS_SVC_F_SCHED3),
}

func parseSchedFlags(value string) (flags uint32) {
	parsedflags := strings.Split(value, ",")
	for _, flag := range parsedflags {
		flags |= schedFlagsParser[strings.Trim(flag, " ")]
	}
	return
}

func (nsc *NetworkServicesController) buildEndpointsInfo(serviceMap *serviceInfoMapType) {
	for _, obj := range nsc.epLister.List() {
		nsc.buildEndpointsInfoFrom(serviceMap, obj.(*api.Endpoints), false)
	}
}

func (nsc *NetworkServicesController) buildEndpointsInfoFrom(serviceMap *serviceInfoMapType, ep *api.Endpoints, remove bool) (keys map[infoMapsKeyType]bool) {
	keys = make(map[infoMapsKeyType]bool)

	for _, epSubset := range ep.Subsets {
		for _, port := range epSubset.Ports {
			svcId := generateId(&serviceMeta{namespace: ep.Namespace, name: ep.Name, portName: port.Name})
			keys[svcId] = true

			var so = (*serviceMap)[svcId]
			if so == nil {
				if svc, ok, _ := nsc.svcLister.GetByKey(ep.Namespace + "/" + ep.Name); ok {
					nsc.buildServicesInfoFrom(serviceMap, svc.(*api.Service), false)
					so = (*serviceMap)[svcId]
				} else {
					continue
				}
			}

			if so.meta.change.CheckFor(SYNCH_NOT_FOUND) {
				continue
			}

			so.epLock.Lock()
			for _, addr := range epSubset.Addresses {

				epLocal := addr.NodeName != nil && *addr.NodeName == nsc.nodeHostName

				if so.info.Local && !epLocal {
					continue
				}

				var used uint32 = 0
				dst := so.generateDestination(netutils.NewIP(addr.IP).ToIP(), uint16(port.Port))
				epNew := &endpointInfo{change: SYNCH_NEW, so: so, Destination: dst, isLocal: epLocal}
				epNew.UsageLockType = &UsageLockType{used: used, funcOnZero: func() {
					so.destroy(epNew)
				}}
				epId := generateId(epNew)

				var ep = (*so.endpoints)[epId]
				if ep == nil {
					(*so.endpoints)[epId] = epNew
				} else if remove {
					ep.change = SYNCH_NOT_FOUND
				} else {
					ep.change = SYNCH_NO_CHANGE
					if ep.Weight == 0 {
						continue
					}
					if !cmp.Equal(dst, ep.Destination, DeepComparerIpvsDestination) {
						ep.Destination = dst
						ep.change = SYNCH_CHANGED
					}
				}
			}
			so.epLock.Unlock()
		}
	}
	return
}

var CHAIN_KUBE_IPVS_SNAT_TARGET = "KUBE-ROUTER-POD-IPVS-SNAT"
var CHAIN_KUBE_MASQUERADE = "KUBE-ROUTER-POD-MASQUERADE"

// Add an iptables rule to masquerade outbound IPVS traffic. IPVS nat requires that reverse path traffic
// to go through the director for its functioning. So the masquerade rule ensures source IP is modifed
// to node Ip, so return traffic from real server (endpoint pods) hits the node/lvs director
func (nsc *NetworkServicesController) ensureMasqueradeIptablesRule(masqueradeAll bool, podCidr string, ip net.IP) (err error) {
	var args = &netutils.IpTablesRuleListType{}

	err = nsc.Ipm.CreateIpTablesRuleWithChain(netutils.NewIP(ip).Protocol(), "nat", CHAIN_KUBE_IPVS_SNAT_TARGET,
		netutils.IPTABLES_FULL_CHAIN_SYNC_NO_ORDER, netutils.NoReferencedChains, true,
		netutils.NewRuleList("-j", "SNAT", "--to", ip.String()))

	if err == nil && masqueradeAll {
		args.Add(netutils.NewRule("-m", "ipvs", "--ipvs", "--vdir", "ORIGINAL", "--vmethod", "MASQ", "-m", "comment", "--comment", "",
			"-j", CHAIN_KUBE_IPVS_SNAT_TARGET))
	}

	if err == nil && len(podCidr) > 0 {
		//TODO: ipset should be used for destination podCidr(s) match after multiple podCidr(s) per node get supported
		args.Add(netutils.NewRule("-m", "ipvs", "--ipvs", "--vdir", "ORIGINAL", "--vmethod", "MASQ", "-m", "comment", "--comment", "",
			"!", "-s", podCidr, "!", "-d", podCidr, "-j", CHAIN_KUBE_IPVS_SNAT_TARGET))
	}

	if err = nsc.Ipm.CreateIpTablesRuleWithChain(netutils.NewIP(podCidr).Protocol(), "nat", CHAIN_KUBE_MASQUERADE, netutils.IPTABLES_FULL_CHAIN_SYNC_NO_ORDER,
		[]string{"POSTROUTING"}, true, args); err != nil {
		return
	}
	glog.V(2).Info("Successfully synced iptables masquerade rule")
	return
}

// syncHairpinIptablesRules adds/removes iptables rules pertaining to traffic
// from an Endpoint (Pod) to its own service VIP. Rules are only applied if
// enabled globally via CLI argument or a service has an annotation requesting
// it.
func (nsc *NetworkServicesController) syncHairpinIptablesRules() (err error) {
	rulesNeeded := *netutils.NewPerProtoRuleList()

	// Generate the rules that we need
	nsc.serviceMap.ForEach(func(so *serviceObject) {
		if nsc.globalHairpin || so.info.Hairpin {
			for _, dst := range *so.getEps() {
				if !dst.isLocal {
					continue
				}
				// Handle ClusterIP Service
				eipStr := dst.Address.String()

				proto, rule := hairpinRuleFrom(so.ksvc.Address.String(), eipStr, so.ksvc.Protocol, so.ksvc.Port)
				rulesNeeded[proto].Add(netutils.NewRule(rule.Args...))

				// Handle NodePort Service
				if so.info.Nodeport != 0 {
					proto, rule := hairpinRuleFrom(nsc.nodeIP.String(), eipStr, so.ksvc.Protocol, so.info.Nodeport)
					rulesNeeded[proto].Add(netutils.NewRule(rule.Args...))
				}
			}
		}
	})

	if err = nsc.syncCustomChainRules("nat", CHAIN_HAIRPIN, netutils.NoReferencedChains, &rulesNeeded); err != nil {
		err = fmt.Errorf("syncHairpinIptablesRules: Error syncing rule %s", err.Error())
	}

	if err, _ = netutils.UsedTcpProtocols.ForEachCreateRulesWithChain(nsc.Ipm, "nat", "POSTROUTING",
		netutils.IPTABLES_APPEND_UNIQUE, netutils.NoReferencedChains, true, netutils.NewRuleList("-m", "ipvs", "--vdir", "ORIGINAL", "-j", CHAIN_HAIRPIN)); err != nil {
		err = fmt.Errorf("error updating reference to %s: %s", CHAIN_HAIRPIN, err.Error())
	}
	if err != nil {
		glog.Error(err)
	}
	return
}

func (nsc *NetworkServicesController) syncCustomChainRules(table, chain string, referenceIn []string, rulesNeeded *netutils.PerProtocolRuleListType) (err error) {
	if err, _ = netutils.UsedTcpProtocols.ForEachCreateRulesWithChain(nsc.Ipm, table, chain,
		netutils.IPTABLES_FULL_CHAIN_SYNC_NO_ORDER, referenceIn, true, rulesNeeded); err != nil {
		return
	}
	return
}

func hairpinRuleFrom(serviceIP, endpointIP string, proto libipvs.Protocol, servicePort uint16) (netutils.Proto, *netutils.IpTablesRuleType) {
	return netutils.NewIP(endpointIP).Protocol(),
		netutils.NewRule("-s", endpointIP, "-d", endpointIP, "-p", proto.String(),
			"-m", "ipvs", "--vaddr", serviceIP, "--vport", fmt.Sprint(servicePort),
			"-j", "SNAT", "--to-source", serviceIP)
}

func (nsc *NetworkServicesController) syncFwmarkIptablesRules() (err error) {
	rulesNeeded := netutils.NewPerProtoRuleList()

	for _, svc := range nsc.getFwmarkSourceData() {
		proto, rule := fwmarkRuleFrom(svc)
		(*rulesNeeded)[proto].Add(netutils.NewRule(rule.Args...))
	}

	if err = nsc.syncCustomChainRules("mangle", CHAIN_FWMARK, []string{"PREROUTING"}, rulesNeeded); err != nil {
		err = errors.New("syncFwmarkIptablesRules: Error syncing rule " + err.Error())
		return err
	}

	return netutils.UsedTcpProtocols.ForEach(routeVIPTrafficToDirector)
}

func (nsc *NetworkServicesController) _deleteHairpinIptablesRules(protocol netutils.Proto) error {
	return nsc.Ipm.IptablesCleanUpChain(protocol, CHAIN_HAIRPIN, true, "nat")
}

func (nsc *NetworkServicesController) _deleteFwmarkIptablesRules(protocol netutils.Proto) error {
	return nsc.Ipm.IptablesCleanUpChain(protocol, CHAIN_FWMARK, true, "mangle")
}

func (nsc *NetworkServicesController) _deleteMasqueradeIptablesRule(protocol netutils.Proto) (err error) {
	if err = nsc.Ipm.IptablesCleanUpChain(protocol, CHAIN_KUBE_MASQUERADE, true, "nat"); err == nil {
		err = nsc.Ipm.IptablesCleanUpChain(protocol, CHAIN_KUBE_IPVS_SNAT_TARGET, true, "nat")
	}
	return
}

var serviceFlagToStringMap = map[uint32]string{
	libipvs.IP_VS_SVC_F_PERSISTENT: "[persistent Port]",
	libipvs.IP_VS_SVC_F_HASHED:     "[hashed entry]",
	libipvs.IP_VS_SVC_F_ONEPACKET:  "[one-packet scheduling]",
	libipvs.IP_VS_SVC_F_SCHED1:     "[flag-1(fallback)]",
	libipvs.IP_VS_SVC_F_SCHED2:     "[flag-2(Port)]",
	libipvs.IP_VS_SVC_F_SCHED3:     "[flag-3]",
}

func ipvsDestinationString(d *libipvs.Destination) string {
	return fmt.Sprintf("%s %s (Weight: %v)", d.FwdMethod.String(), netutils.NewIP(d.Address).ToStringWithPort(fmt.Sprint(d.Port)), d.Weight)
}

func (ln *linuxNetworking) ipvsAddService(ks *KubeService, create bool) (*libipvs.Service, error) {
	var err error
	var update = !create

	if !update {
		if err = ln.ipvsNewService(ks); err != nil && !strings.Contains(err.Error(), IPVS_SERVER_EXISTS) {
			glog.Errorf("Failed adding service: %s", ks)
			return nil, err
		} else if err != nil {
			update = true
		}
	}

	if update {
		if err = ln.ipvsUpdateService(ks.Service); err != nil {
			glog.Errorf("Failed updating service: \n\t%v. Create: %v", ks, create == true)
			return ks.Service, err
		}
		glog.V(2).Infof("Successfully updated service: %s", ks)
		return ks.Service, nil
	}

	glog.V(1).Infof("Successfully added service: %s", ks)
	return ks.Service, nil
}

func (ln *linuxNetworking) ipvsAddServer(ks *KubeService, ep *endpointInfo, new bool) (upd bool, err error) {
	upd = false
	dest := ks.getDestination(ep)

	if ks.AddressFamily != dest.AddressFamily && !ks.isFwMarkService() {
		err = errors.New(fmt.Sprintf("Different address family is allowed only for tunneling servers\n\tvs: %s\n\trs: %s", ks.String(), ep.String()))
		glog.Error(err)
		return
	}
	// TODO: Make this debug output when we get log levels
	// glog.Infof("Ipvs destination %s already exists in the Ipvs service %s so not adding destination",
	// 	ipvsDestinationString(dest), ipvsServiceString(service))
	if !upd {
		if err = ln.ipvsNewDestination(ks.Service, dest); err != nil && !strings.Contains(err.Error(), IPVS_SERVER_EXISTS) {
			glog.Errorf("Failed to add Ipvs destination %s to the Ipvs service %s due to : %s", ep, ks, err.Error())
			return
		} else if err != nil {
			upd = true
		}
	}
	if upd {
		if err = ln.ipvsUpdateDestination(ks.Service, dest); err != nil {
			glog.Errorf("Failed to update Ipvs destination %s to the Ipvs service %s due to : %s", ep, ks, err.Error())
			return
		}
		glog.V(2).Infof("Successfully updated destination: %v", ipvsDestinationString(dest))
	} else {
		glog.V(1).Infof("Successfully added destination %s to the service %s", ep, ks)
	}

	return
}

// For DSR it is required that we dont assign the VIP to any interface to avoid martian packets
// http://www.austintek.com/LVS/LVS-HOWTO/HOWTO/LVS-HOWTO.routing_to_VIP-less_director.html
// setupPolicyRoutingForDSR: setups policy routing so that FWMARKed packets are deliverd locally
func (ln *linuxNetworking) setupPolicyRoutingForDSR() (err error) {
	return ln.rtManager.Setup(true)
}

// For DSR it is required that node needs to know how to route external IP. Otherwise when endpoint
// directly responds back with source IP as external IP kernel will treat as martian packet.
// To prevent martian packets add route to exteranl IP through the `kube-bridge` interface
// setupRoutesForExternalIPForDSR: setups routing so that kernel does not think return packets as martians
func (ln *linuxNetworking) setupRoutesForExternalIPForDSR(serviceInfoMap *serviceInfoMapType) (err error) {
	var out4, out6 []byte
	outByte := make(map[string]*[]byte)
	if out4, err = exec.Command(utils.GetPath("ip"), "-4", "route", "show", "table", ROUTE_TABLE_EXTERNAL).Output(); err == nil {
		outByte["-4"] = &out4
		if out6, err = exec.Command(utils.GetPath("ip"), "-6", "route", "show", "table", ROUTE_TABLE_EXTERNAL).Output(); err == nil {
			outByte["-6"] = &out6
		}
	}
	if err != nil {
		return errors.New("Failed to get routes in external_ip table due to: " + err.Error())
	}
	activeExternalIPs := make(map[string]bool)
	for _, so := range *serviceInfoMap {
		so.setupRoutesForExternalIPForDSR(&activeExternalIPs, outByte)
	}

	// check if there are any pbr in externalIPRouteTableId for external IP's
	for _, rtb := range outByte {
		rt := string(*rtb)
		if rt == "" {
			continue
		}
		// clean up stale external IPs
		for _, line := range strings.Split(strings.Trim(rt, "\n"), "\n") {
			route := strings.Fields(line)
			ip := route[0]
			if !activeExternalIPs[ip] {
				if err = exec.Command(utils.GetPath("ip"), netutils.NewIP(ip).ProtocolCmdParam().Inet, "r", "del", ip, "table", ROUTE_TABLE_EXTERNAL).Run(); err != nil {
					glog.Errorf("Failed to del route for %v in custom route table for external IP's due to: %s", ip, err)
					continue
				}
			}
		}
	}

	return nil
}

func isEndpointsForLeaderElection(obj interface{}) (isLeaderElection bool) {
	if ep, ok := obj.(*api.Endpoints); ok {
		_, isLeaderElection = ep.Annotations[LeaderElectionRecordAnnotationKey]
	}
	return
}

func generateId(input interface{}) infoMapsKeyType {
	switch in := input.(type) {
	case *serviceMeta:
		return generateServiceId(in)
	case *endpointInfo:
		return generateIpPortId(&libipvs.Service{Address: in.Address, Protocol: in.so.ksvc.Protocol, Port: in.Port})
	case *libipvs.Service:
		return generateIpPortId(in)
	}
	return 0
}

// unique identifier for a load-balanced service (namespace + name + portname)
func generateServiceId(svc *serviceMeta) infoMapsKeyType {
	return infoMapsKeyType(utils.DoHash(svc.namespace + ":" + svc.name + ":" + svc.portName))
}

// unique identifier for a load-balanced service
func generateIpPortId(ipvsSvc *libipvs.Service) infoMapsKeyType {
	return infoMapsKeyType(utils.DoHash(ipvsSvc.Address.String() + "," + ipvsSvc.Protocol.String() + ":" + fmt.Sprint(ipvsSvc.Port)))
}

const fwMarkTag = 1 << 16

// generateFwmark: generate a uint32 hash value using the IP address, Port, protocol information
// TODO: collision can rarely happen but still need to be ruled out
// bit 15 is used by k8s as a "drop traffic" identifier
// bit 14 is used by k8s as a "masq traffic" identifier
func generateFwmark(ipvsSvc *libipvs.Service) infoMapsKeyType {
	return (generateIpPortId(ipvsSvc) & 0x3FFF) | fwMarkTag
}

// returns all IP addresses found on any network address in the system, excluding dummy and docker interfaces
func getAllLocalIPs(neg bool, names ...string) (localAddrs []*net.IPNet, err error) {
	links, _ := net.Interfaces()
	for _, link := range links {

		doContinue := false
		for _, name := range names {
			if neg == strings.Contains(link.Name, name) {
				doContinue = true
				break
			}
		}

		if doContinue || !utils.FilterInterfaces(link) {
			continue
		}

		addrs, _ := link.Addrs()
		for _, addr := range addrs {
			ip := netutils.NewIP(addr)
			if ip.ToIP().IsLinkLocalUnicast() {
				continue
			}
			localAddrs = append(localAddrs, ip.ToIPNet())
		}
	}
	return
}

func (ln *linuxNetworking) getKubeDummyInterface(refresh ...bool) (netlink.Link, error) {
	var err error
	if ln.dummyInterface != nil && (len(refresh) == 0 || len(refresh) > 0 && !refresh[0]) {
		return ln.dummyInterface, nil
	}
	var dummyVipInterface netlink.Link
	dummyVipInterface, err = netlink.LinkByName(KUBE_DUMMY_IF)
	if err != nil && err.Error() == IFACE_NOT_FOUND {
		glog.V(1).Infof("Could not find dummy interface: " + KUBE_DUMMY_IF + " to assign cluster ip's, creating one")
		err = netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: KUBE_DUMMY_IF}})
		if err != nil {
			return nil, errors.New("Failed to add dummy interface:  " + err.Error())
		}
		dummyVipInterface, err = netlink.LinkByName(KUBE_DUMMY_IF)
		err = netlink.LinkSetUp(dummyVipInterface)
		if err != nil {
			return nil, errors.New("Failed to bring dummy interface up: " + err.Error())
		}
	}
	ln.dummyInterface = dummyVipInterface
	return dummyVipInterface, nil
}

// Cleanup cleans all the configurations (IPVS, iptables, links) done
func (nsc *NetworkServicesController) Cleanup() {
	// cleanup Ipvs rules by flush
	glog.Infof("Cleaning up IPVS configuration permanently")

	handle, err := libipvs.New()
	if err != nil {
		glog.Errorf("Failed to cleanup Ipvs rules: %s", err.Error())
		return
	}

	handle.Flush()

	// cleanup iptables masquerade rule
	err = nsc.deleteMasqueradeIptablesRule()
	if err != nil {
		glog.Errorf("Failed to cleanup iptablesmasquerade rule due to: %s", err.Error())
		return
	}

	// cleanup iptables hairpin rules
	err = nsc.deleteHairpinIptablesRules()
	if err != nil {
		glog.Errorf("Failed to cleanup iptable Hairpin rules: %s", err.Error())
		return
	}

	// cleanup iptables fwmark rules
	err = nsc.deleteFwmarkIptablesRules()
	if err != nil {
		glog.Errorf("Failed to cleanup iptable Hairpin rules: %s", err.Error())
		return
	}

	nsc.cleanupIpvsFirewall()

	// delete dummy interface used to assign cluster IP's
	dummyVipInterface, err := netlink.LinkByName(KUBE_DUMMY_IF)
	if err != nil {
		if err.Error() != IFACE_NOT_FOUND {
			glog.Infof("Dummy interface: " + KUBE_DUMMY_IF + " does not exist")
		}
	} else {
		err = netlink.LinkDel(dummyVipInterface)
		if err != nil {
			glog.Errorf("Could not delete dummy interface " + KUBE_DUMMY_IF + " due to " + err.Error())
			return
		}
	}
	glog.Infof("Successfully cleaned the Ipvs configuration done by kube-router")
}

func (nsc *NetworkServicesController) newEndpointsEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			nsc.OnUpdate(makeTypedEmptyObject(obj), obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			nsc.OnUpdate(oldObj, newObj)
		},
		DeleteFunc: func(obj interface{}) {
			nsc.OnUpdate(obj, makeTypedEmptyObject(obj))
		},
	}
}

func makeTypedEmptyObject(obj interface{}) interface{} {
	switch obj.(type) {
	case *api.Service:
		return &api.Service{}
	}
	return &api.Endpoints{}
}

// NewNetworkServicesController returns NetworkServicesController object
func NewNetworkServicesController(clientset kubernetes.Interface,
	config *options.KubeRouterConfig, svcInformer cache.SharedIndexInformer,
	epInformer cache.SharedIndexInformer, podInformer cache.SharedIndexInformer) (*NetworkServicesController, error) {

	var err error
	ln, err := newLinuxNetworking()
	if err != nil {
		return nil, err
	}
	nsc := NetworkServicesController{ln: ln}

	if config.MetricsEnabled {
		//GetData the metrics for this controller
		prometheus.MustRegister(metrics.ControllerIpvsServices)
		prometheus.MustRegister(metrics.ControllerIpvsServicesSyncTime)
		prometheus.MustRegister(metrics.ServiceBpsIn)
		prometheus.MustRegister(metrics.ServiceBpsOut)
		prometheus.MustRegister(metrics.ServiceBytesIn)
		prometheus.MustRegister(metrics.ServiceBytesOut)
		prometheus.MustRegister(metrics.ServiceCPS)
		prometheus.MustRegister(metrics.ServicePacketsIn)
		prometheus.MustRegister(metrics.ServicePacketsOut)
		prometheus.MustRegister(metrics.ServicePpsIn)
		prometheus.MustRegister(metrics.ServicePpsOut)
		prometheus.MustRegister(metrics.ServiceTotalConn)
		nsc.MetricsEnabled = true
	}

	nsc.syncPeriod = config.IpvsSyncPeriod
	nsc.globalHairpin = config.GlobalHairpinMode

	nsc.serviceMap = make(serviceInfoMapType)

	nsc.onUpdateChannel = utils.NewChanLock(1)

	nsc.client = clientset

	nsc.masqueradeAll = false
	if config.MasqueradeAll {
		nsc.masqueradeAll = true
	}

	if config.NodePortBindOnAllIp {
		nsc.nodeportBindOnAllIp = true
	}

	if config.RunRouter {
		cidr, err := utils.GetPodCidrFromNodeSpec(nsc.client, config.HostnameOverride)
		if err != nil {
			return nil, fmt.Errorf("failed to get pod CIDR details from Node.spec: %s", err.Error())
		}
		nsc.podCidr = cidr.String()
	}

	node, err := utils.GetNodeObject(clientset, config.HostnameOverride)
	if err != nil {
		return nil, err
	}

	nsc.nodeHostName = node.Name
	NodeIP, err = utils.GetNodeIP(node)
	if err != nil {
		return nil, err
	}

	nsc.nodeIP = NodeIP

	nsc.Ipm = netutils.NewIpTablesManager([]string{nsc.nodeIP.String()})

	nsc.podLister = podInformer.GetIndexer()

	nsc.svcLister = svcInformer.GetIndexer()
	nsc.ServiceEventHandler = nsc.newEndpointsEventHandler()

	nsc.epLister = epInformer.GetIndexer()
	nsc.EndpointsEventHandler = nsc.newEndpointsEventHandler()

	rand.Seed(time.Now().UnixNano())

	return &nsc, nil
}
