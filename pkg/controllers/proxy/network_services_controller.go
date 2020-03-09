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
	"github.com/cloudnativelabs/kube-router/pkg/helpers/api"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/async_worker"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/hostconf"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/hostnet"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/tools"
	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/docker/docker/client"
	"github.com/eapache/channels"
	"github.com/golang/glog"
	"github.com/google/go-cmp/cmp"
	"github.com/mqliang/libipvs"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
	k8sapi "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

const (
	KUBE_DUMMY_IF       = "kube-dummy-if"
	KUBE_TUNNEL_IF      = "kube-tunnel-if"
	IFACE_NOT_FOUND     = "Link not found"
	IFACE_HAS_ADDR      = "file exists"
	IFACE_HAS_NO_ADDR   = "cannot assign requested address"
	IPVS_SERVER_EXISTS  = "file exists"
	IPVS_SERVER_MISSING = "no such process"
	IPVS_MAGLEV_HASHING = "mh"
	IPVS_SVC_F_SCHED1   = "flag-1"
	IPVS_SVC_F_SCHED2   = "flag-2"
	IPVS_SVC_F_SCHED3   = "flag-3"

	CHAIN_HAIRPIN = "KUBE-ROUTER-HAIRPIN"
	CHAIN_FWMARK  = "KUBE-ROUTER-FWMARK"

	nodeMACAnnotation       = "kube-router.io/node.mac"
	svcDSRAnnotation        = "kube-router.io/service.dsr"
	svcSchedulerAnnotation  = "kube-router.io/service.scheduler"
	svcHairpinAnnotation    = "kube-router.io/service.hairpin"
	svcLocalAnnotation      = "kube-router.io/service.local"
	svcSkipLbIpsAnnotation  = "kube-router.io/service.skiplbips"
	svcSchedFlagsAnnotation = "kube-router.io/service.schedflags"

	LeaderElectionRecordAnnotationKey = "control-plane.alpha.kubernetes.io/leader"
	localIPsIPSetName                 = "kube-router-local-ips"
	ipvsServicesIPSetName             = "kube-router-ipvs-services"
	nodeMACIPSetName                  = "kube-router-node-mac"
	serviceIPsIPSetName               = "kube-router-service-ips"
	ipvsServicesLoadBalancerHealth    = "kube-router-ipvs-lb-health"
	ipvsFirewallChainName             = "KUBE-ROUTER-SERVICES"
)

type ipvsCalls interface {
	ipvsNewService(ks *KubeService) error
	ipvsAddService(ks *KubeService, create bool) (*libipvs.Service, error)
	ipvsDelService(ks *KubeService) error
	ipvsUpdateService(ks *KubeService) error
	ipvsGetServices() ipvsServiceArrayType
	ipvsAddServer(ks *KubeService, ep *endpointInfo) (bool, error)
	ipvsNewDestination(ipvsSvc *libipvs.Service, ipvsDst *libipvs.Destination) error
	ipvsUpdateDestination(ipvsSvc *libipvs.Service, ipvsDst *libipvs.Destination) error
	ipvsGetDestinations(ipvsSvc *libipvs.Service, force bool) ipvsDestinationArrayType
	ipvsDelDestination(ipvsSvc *libipvs.Service, ipvsDst *libipvs.Destination) error

	resetDestinations()
}

type netlinkCalls interface {
	ipAddrAdd(iface netlink.Link, ip *net.IPNet, addRoute bool) error
	ipAddrDel(iface netlink.Link, ip *net.IPNet, from string) error
	getDockerPid(containerId string) (int, error)
	prepareEndpointForDsrTunnel(pid int, endpointIP net.IP, vip, svcPort, dstPort, proto string) error
	prepareEndpointForDsrNat(pid int, endpointIP net.IP, vip, svcPort, dstPort, proto string) error
	prepareEndpointForDsr(pid int, endpointIP net.IP, vip, svcPort, dstPort, proto string, isTunnel bool) error
	getKubeDummyInterface(refresh ...bool) (netlink.Link, error)
	setupRoutesForExternalIPForDSR(*serviceInfoMapType) error
	setupPolicyRoutingForDSR() error
}

// LinuxNetworking interface contains all linux networking subsystem calls
//go:generate moq -out network_services_controller_moq.go . LinuxNetworking
type LinuxNetworking interface {
	ipvsCalls
	netlinkCalls
	options.NodeInfoType
	async_worker.WorkerType
}

type dstsMessageType struct {
	channel chan *ipvsDestinationArrayType
	svc     *libipvs.Service
	force   bool
}

type linuxNetworking struct {
	PerServiceLockType
	options.NodeInfoType

	ipvsHandle     libipvs.IPVSHandle
	dummyInterface netlink.Link

	rtManager       *hostnet.RouteTableManager
	dsts            map[infoMapsKeyType]*ipvsDestinationArrayType
	dstWriteChannel chan *dstsMessageType
	dstReadChannel  chan *dstsMessageType

	chanPool sync.Pool
	async_worker.Worker
}

func (ln *linuxNetworking) ipAddrDel(iface netlink.Link, ip *net.IPNet, from string) error {
	naddr := &netlink.Addr{IPNet: ip, Scope: syscall.RT_SCOPE_LINK}
	err := netlink.AddrDel(iface, naddr)
	if err != nil && err.Error() != IFACE_HAS_NO_ADDR {
		err = tools.NewErrorf("Failed to verify is external ip %s is assocated with dummy interface %s due to %s",
			naddr.IPNet.IP.String(), KUBE_DUMMY_IF, err.Error())
	}
	// Delete VIP addition to "local" rt table also, fail silently if not found (DSR special case)
	if err == nil {
		out, err := exec.Command(tools.GetExecPath("ip"), hostnet.NewIP(ip).ProtocolCmdParam().Inet, "route", "delete", "local", ip.IP.String(), "dev", KUBE_DUMMY_IF, "table", "local").CombinedOutput()
		if err != nil && !strings.Contains(string(out), "No such process") {
			err = tools.NewErrorf("Failed to delete route to service VIP %s configured on %s. Error: %v, Output: %s", ip, KUBE_DUMMY_IF, err, out)
		} else {
			glog.V(3).Infof("Removed local route for %s (dev %s)", ip.IP.String(), KUBE_DUMMY_IF)
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
	// TODO: with IPv6 even ip replace is not working as expected. new route is added with different metric. so let's try to remove the one without src specified
	out, err := exec.Command(tools.GetExecPath("ip"), hostnet.NewIP(ip).ProtocolCmdParam().Inet, "route", "replace", "local", ip.IP.String(), "dev", KUBE_DUMMY_IF, "table", "local", "proto", "17",
		"src", ln.GetNodeIP().IP.String()).CombinedOutput()
	if err != nil {
		glog.Errorf("Failed to replace route to service VIP %s configured on %s. Error: %v, Output: %s", ip, KUBE_DUMMY_IF, err, out)
	}

	glog.V(3).Infof("Updated local route for %s src %s (dev %s)", ip.IP.String(), ln.GetNodeIP().IP.String(), KUBE_DUMMY_IF)
	return exec.Command(tools.GetExecPath("ip"), hostnet.NewIP(ip).ProtocolCmdParam().Inet, "route", "del", "local", ip.IP.String(), "dev", KUBE_DUMMY_IF, "table", "local", "proto", "kernel", "metric", "0").Run()
}

func (ln *linuxNetworking) StartWorker() {
	go ln.dstReceiverLoop()
}

func (ln *linuxNetworking) dstReceiverLoop() {
	defer func() {
		glog.V(3).Infof("%s done", ln.GetName())
		ln.Done()
	}()

	for {
		select {
		case dst, ok := <-ln.dstWriteChannel:
			if !ok {
				return
			}
			if dst.svc != nil {
				delete(ln.dsts, generateId(dst.svc))
			} else {
				ln.dsts = make(map[infoMapsKeyType]*ipvsDestinationArrayType)
				dst.channel <- &ipvsDestinationArrayType{}
			}
		case req, ok := <-ln.dstReadChannel:
			if !ok {
				return
			}
			hash := generateId(req.svc)
			if req.force || ln.dsts[hash] == nil {
				ln.dsts[hash] = ln.ipvsRefreshDestinations(req.svc)
			}
			req.channel <- ln.dsts[hash]
		}
	}
}

func (ln *linuxNetworking) StopWorker() {
	close(ln.dstReadChannel)
	close(ln.dstWriteChannel)
}

func (ln *linuxNetworking) ipvsGetServices() (list ipvsServiceArrayType) {
	var err error
	if list, err = ln.ipvsHandle.ListServices(); err != nil {
		glog.Errorf("Error in ipvsGetServices: %s", err.Error())
	}
	return
}

func (ln *linuxNetworking) ipvsGetDestinations(ipvsSvc *libipvs.Service, force bool) (out ipvsDestinationArrayType) {
	request := &dstsMessageType{channel: ln.chanPool.Get().(chan *ipvsDestinationArrayType), svc: ipvsSvc, force: force}
	ln.dstReadChannel <- request
	out = *<-request.channel
	ln.chanPool.Put(request.channel)
	return
}

func (ln *linuxNetworking) ipvsRefreshDestinations(ipvsSvc *libipvs.Service) *ipvsDestinationArrayType {
	list, err := ln.ipvsHandle.ListDestinations(ipvsSvc)
	if err != nil {
		glog.Errorf("Error refreshing ipvsGetDestinations: %s", err.Error())
	}
	var at ipvsDestinationArrayType = list
	return &at
}

func (ln *linuxNetworking) wrapChangeOnDestination(action string, fn func(*libipvs.Service, *libipvs.Destination) error,
	ipvsSvc *libipvs.Service, ipvsDst *libipvs.Destination, triggerUpdate bool) (err error) {

	hsh := generateId(ipvsSvc)
	ln.Lock(hsh)
	defer ln.Unlock(hsh)

	if err = fn(ipvsSvc, ipvsDst); err == nil {
		glog.V(4).Infof("Success operation %s on %s/%s", action, ipvsServiceString(ipvsSvc, 4), ipvsDestinationString(ipvsDst, 4))
	} else {
		glog.V(4).Infof("Failed operation %s on %s/%s", action, ipvsServiceString(ipvsSvc, 4), ipvsDestinationString(ipvsDst, 4))
	}
	if err == nil && triggerUpdate {
		ln.dstWriteChannel <- &dstsMessageType{channel: nil, svc: ipvsSvc}
	}
	return
}

func (ln *linuxNetworking) ipvsDelDestination(ipvsSvc *libipvs.Service, ipvsDst *libipvs.Destination) (err error) {
	return ln.wrapChangeOnDestination("delete", ln.ipvsHandle.DelDestination, ipvsSvc, ipvsDst, true)
}

func (ln *linuxNetworking) ipvsNewDestination(ipvsSvc *libipvs.Service, ipvsDst *libipvs.Destination) (err error) {
	return ln.wrapChangeOnDestination("create", ln.ipvsHandle.NewDestination, ipvsSvc, ipvsDst, true)
}

func (ln *linuxNetworking) ipvsUpdateDestination(ipvsSvc *libipvs.Service, ipvsDst *libipvs.Destination) (err error) {
	return ln.wrapChangeOnDestination("update", ln.ipvsHandle.UpdateDestination, ipvsSvc, ipvsDst, false)
}

func (ln *linuxNetworking) ipvsServiceCommon(fn func(*libipvs.Service) error, ks *KubeService) (err error) {
	ln.Lock(0)
	defer ln.Unlock(0)
	if err = fn(ks.Service); err == nil {
		ln.dstWriteChannel <- &dstsMessageType{channel: nil, svc: ks.Service}
	}
	return
}

func (ln *linuxNetworking) ipvsDelService(ks *KubeService) (err error) {
	if err = ln.ipvsServiceCommon(ln.ipvsHandle.DelService, ks); err == nil {
		delete(ln.PerServiceLockType, ks.getHash())
	}
	return
}

func (ln *linuxNetworking) ipvsUpdateService(ks *KubeService) (err error) {
	return ln.ipvsServiceCommon(ln.ipvsHandle.UpdateService, ks)
}

func (ln *linuxNetworking) ipvsNewService(ks *KubeService) error {
	return ln.ipvsServiceCommon(ln.ipvsHandle.NewService, ks)
}

func (ln *linuxNetworking) resetDestinations() {
	ch := ln.chanPool.Get().(chan *ipvsDestinationArrayType)
	ln.dstWriteChannel <- &dstsMessageType{channel: ch, svc: nil}
	<-ch
}

func newLinuxNetworking(commons options.NodeInfoType) (*linuxNetworking, error) {
	ln := &linuxNetworking{NodeInfoType: commons}
	ipvsHandle, err := libipvs.New()
	if err != nil {
		return nil, err
	}
	ln.ipvsHandle = ipvsHandle
	ln.PerServiceLockType = make(PerServiceLockType)
	ln.dsts = make(map[infoMapsKeyType]*ipvsDestinationArrayType)

	ln.chanPool = sync.Pool{
		New: func() interface{} {
			return make(chan *ipvsDestinationArrayType)
		},
	}
	ln.dstWriteChannel = make(chan *dstsMessageType, 1)
	ln.dstReadChannel = make(chan *dstsMessageType)

	ln.getKubeDummyInterface(true)

	ln.rtManager = hostnet.NewRouteTableManager(&customRouteTables)
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
	controllers.Controller

	syncLock                sync.Mutex
	serviceMap              serviceInfoMapType
	configuredDsrContainers configuredDsrContainerType
	lbHealthChecks          lbHealthChecksListType
	excludedCidrs           []*net.IPNet
	podCidr                 string
	masqueradeAll           bool
	globalHairpin           bool
	nodeportBindOnAllIp     bool
	MetricsEnabled          bool
	ln                      LinuxNetworking
	Ipm                     *hostnet.IpTablesManager
	ipSet                   *hostnet.IPSet
	readyForUpdates         bool
	epPurgeBacklogChannel   chan *epPurgeBacklogDataType

	rejectTargets []string

	svcLister  cache.Indexer
	epLister   cache.Indexer
	podLister  cache.Indexer
	nodeLister cache.Indexer

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
	dsr       string

	change synchChangeType
}

type serviceInfo struct {
	Nodeport                 uint16
	HealthCheckPort          int32
	DirectServerReturnMethod libipvs.FwdMethod
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

	endpoints endpointInfoMapType
	nsc       *NetworkServicesController

	epLock sync.Mutex
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

	hash        infoMapsKeyType
	containerID string
}

var activeReferences activeAddrsMapType

type infoMapsKeyType uint32

type activeAddrsMapType map[string]bool
type endpointInfoMapType map[infoMapsKeyType]*endpointInfo

type enabledLBHealthCheckType map[*serviceObject]bool

type lbHealthChecksListType struct {
	healthPort string
	healthIP   string
	*hostnet.Set
	enabledLBHealthCheckType
}

var metricsData keyMetrics

var afterPickupOnce = &sync.Once{}
var updatesQueue = channels.NewBatchingChannel(updateQueueLen)

const updateQueueLen = 10

// Run periodically sync ipvs configuration to reflect desired state of services and endpoints
func (nsc *NetworkServicesController) run(stopCh <-chan struct{}) error {

	t := time.NewTicker(nsc.GetSyncPeriod())
	defer func() {
		glog.Infof("Shutting down %s", nsc.GetControllerName())
		nsc.readyForUpdates = false
	}()

	nsc.epPurgeBacklogChannel = make(chan *epPurgeBacklogDataType)
	nsc.AddWorkerRoutine(&endpointPurgerType{epPurgeBacklogChannel: nsc.epPurgeBacklogChannel, graceDownPeriod: 15},
		"Service endpoints purger")
	nsc.AddWorkerRoutine(nsc.ln, "IPVS handler")

	// enable masquerad rule
	err := nsc.ensureMasqueradeIptablesRule(nsc.masqueradeAll, nsc.podCidr, nsc.ln.GetNodeIP())
	if err != nil {
		return errors.New("Failed to do add masquerade rule in POSTROUTING chain of nat table due to: %s" + err.Error())
	}
	sysctlConfig := &hostconf.SysCtlConfigRuleListType{
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
		// for conn reuse
		{"net/ipv4/vs/sloppy_tcp", 1},
		{"net/ipv4/vs/snat_reroute", 0},
	}
	sysctlConfig.Apply()

	// https://github.com/cloudnativelabs/kube-router/issues/282
	if err = nsc.syncIpvsFirewall(make(map[*KubeService]*serviceObject, 0)); err != nil {
		return errors.New("Error setting up ipvs firewall: " + err.Error())
	}

	glog.Infof("Started %s", nsc.GetControllerName())
	// loop forever unitl notified to stop on stopCh
	for {
		glog.V(1).Info("Performing periodic sync of Ipvs services")
		if updatesQueue.Len() == 0 {
			if err = nsc.syncIpvsServices(); err != nil {
				glog.Errorf("Error during periodic Ipvs sync in network service controller. Error: " + err.Error())
				glog.Errorf("Skipping sending heartbeat from network service controller as periodic sync failed.")
			} else {
				dataCopy := metricsData
				metricsData = keyMetrics{}
				healthcheck.SendHeartBeat(nsc, dataCopy)
			}
		}
		nsc.readyForUpdates = true
		select {
		case <-stopCh:
			return nil
		case <-t.C:
		}
	}
}

func (nsc *NetworkServicesController) ipvsServiceLBHealthChecksRule(ipm *hostnet.IpTablesManager) {
	var err error
	if nsc.lbHealthChecks.Set == nil {
		if nsc.lbHealthChecks.Set, err = nsc.ipSet.Create(ipvsServicesLoadBalancerHealth, hostnet.TypeHashIPPort); err != nil {
			glog.Errorf("failed to create ipset: %s", err.Error())
			return
		}
		nsc.lbHealthChecks.Set.Flush()
	}

	ipm.CreateLBHealthChecksEnsureRule("nat", "KUBE-ROUTER-LB-PRERT", "PREROUTING",
		[]string{"-m", "set", "--match-set", ipvsServicesLoadBalancerHealth, "dst,dst", "-j", "REDIRECT", "-p", "tcp", "--to", fmt.Sprint(nsc.lbHealthChecks.healthPort)})
	ipm.CreateLBHealthChecksEnsureRule("mangle", "KUBE-ROUTER-LB-OUT", "OUTPUT",
		[]string{"-m", "set", "--match-set", ipvsServicesLoadBalancerHealth, "src,src", "-p", "tcp", "-j", "MARK", "--set-xmark", fmt.Sprintf("0x%x", ExternalRouteDirectMark)})
	return
}

func (nsc *NetworkServicesController) createIpSet() error {

	// Create ipset for local addresses.
	if _, err := nsc.ipSet.Create(localIPsIPSetName, hostnet.TypeHashIP, hostnet.OptionTimeout, "0"); err != nil {
		return fmt.Errorf("failed to create ipset: %s", err.Error())
	}

	// Create 2 ipsets for services. One for 'ip' and one for 'ip,port'
	if _, err := nsc.ipSet.Create(serviceIPsIPSetName, hostnet.TypeHashIP, hostnet.OptionTimeout, "0"); err != nil {
		return fmt.Errorf("failed to create ipset: %s", err.Error())
	}

	if _, err := nsc.ipSet.Create(ipvsServicesIPSetName, hostnet.TypeHashIPPort, hostnet.OptionTimeout, "0"); err != nil {
		return fmt.Errorf("failed to create ipset: %s", err.Error())
	}

	return nil
}

func getIpvsFirewallInputChainRule() []string {
	// The iptables rule for use in {setup,cleanup}IpvsFirewall.
	return []string{
		"-m", "comment", "--comment", "handle traffic to IPVS service IPs in custom chain",
		"-m", "set", "--match-set", serviceIPsIPSetName, "dst"}
}

func (nsc *NetworkServicesController) ipvsFwBuildAux(p hostnet.Proto) (err error) {
	helper := hostnet.NewIP(p)

	commentAllow := "allow input traffic to ipvs services"
	commentEcho := "allow icmp echo requests to service IPs"
	commentReject := "reject all unexpected traffic to service IPs"

	//rules := []netutils.IpTablesPtrType{
	rules := hostnet.NewRuleList("-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	rules.Add(hostnet.NewRule("-m", "comment", "--comment", commentAllow, "-m", "set", "--match-set", ipvsServicesIPSetName, "dst,dst", "-j", "ACCEPT"))
	rules.Add(hostnet.NewRule("-m", "comment", "--comment", commentEcho, "-p", helper.ProtocolCmdParam().IcmpStr,
		"--"+helper.ProtocolCmdParam().IcmpStr+"-type", "echo-request", "-j", "ACCEPT"))

	// We exclude the local addresses here as that would otherwise block all
	// traffic to local addresses if any NodePort service exists.
	for _, target := range nsc.rejectTargets {
		rules.Add(hostnet.NewRule("-m", "comment", "--comment", commentReject, "-m", "set", "!", "--match-set", localIPsIPSetName, "dst", "-j", target))
	}

	ref := hostnet.ReferenceFromType{In: "INPUT", Pos: 0, Rule: getIpvsFirewallInputChainRule()}
	return nsc.Ipm.CreateRuleChain(p, "filter", ipvsFirewallChainName, hostnet.IPTABLES_FULL_CHAIN_SYNC, true, rules, ref)
}

func (nsc *NetworkServicesController) syncIpvsFirewall(svcs map[*KubeService]*serviceObject) error {
	/*
	   - create ipsets
	   - create firewall rules
	   - update ipsets based on currently active IPVS services
	*/
	var err error
	var set *hostnet.Set
	var addrs []*net.IPNet

	// Populate local addresses ipset.
	if addrs, err = hostnet.GetAllLocalIPs(hostnet.ExcludePattern, "dummy", "kube", "docker"); err == nil {
		if set, err = nsc.ipSet.GetOrCreate(localIPsIPSetName, hostnet.TypeHashIP, hostnet.OptionTimeout, "0"); err == nil {
			set.RefreshAsync(addrs)
		}
	}

	if err != nil {
		return tools.NewError(err.Error())
	}

	if err = nsc.syncMacIpSet(); err != nil {
		return tools.NewError(err.Error())
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

	if set, err = nsc.ipSet.GetOrCreate(serviceIPsIPSetName, hostnet.TypeHashIP, hostnet.OptionTimeout, "0"); err != nil {
		return tools.NewError(err.Error())
	}
	set.RefreshAsync(serviceIPsSets)

	if set, err = nsc.ipSet.GetOrCreate(ipvsServicesIPSetName, hostnet.TypeHashIPPort, hostnet.OptionTimeout, "0"); err != nil {
		return tools.NewError(err.Error())
	}
	set.RefreshAsync(ipvsServicesSets)

	// config.IpvsPermitAll: true then create INPUT/KUBE-ROUTER-SERVICE Chain creation else return
	if !nsc.GetConfig().IpvsPermitAll {
		return nil
	}

	if err = hostnet.UsedTcpProtocols.ForEach(nsc.ipvsFwBuildAux); err != nil {
		return tools.NewErrorf("Error setting up ipvs firewall: %s", err.Error())
	}

	return nil
}

func (nsc *NetworkServicesController) syncMacIpSet() (err error) {
	var macIpSet *hostnet.Set
	if macIpSet, err = nsc.ipSet.GetOrCreate(nodeMACIPSetName, hostnet.TypeHashMac, hostnet.TypeManual); err != nil {
		return
	}

	nodeMACs := make(hostnet.PerProtoEntryMapType)
	for _, obj := range nsc.nodeLister.List() {
		if obj.(*k8sapi.Node).Annotations[nodeMACAnnotation] == "" {
			continue
		}
		nodeMACs.Add(hostnet.VRaw, &hostnet.Entry{
			Set:     macIpSet,
			Options: []string{obj.(*k8sapi.Node).Annotations[nodeMACAnnotation]},
		})
	}
	return macIpSet.RefreshWithEntries(nodeMACs)
}

func (nsc *NetworkServicesController) cleanupIpvsFirewall() {
	/*
		- delete firewall rules
		- delete ipsets
	*/
	hostnet.UsedTcpProtocols.ForEach(func(p hostnet.Proto) error {
		return nsc.Ipm.IptablesCleanUpChain(p, ipvsFirewallChainName, true)
	})

	ipset := hostnet.NewIPSet()
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

func (nsc *NetworkServicesController) OnUpdate(t *tools.ApiTransaction) {
	if isEndpointsForLeaderElection(t.New) {
		return
	}

	glog.V(1).Infof("Received update from watch API")
	if !nsc.readyForUpdates {
		glog.V(3).Infof("Skipping update to endpoint: controller not ready")
		return
	}

	updatesQueue.In() <- t
	nsc.schedulePickupQueue(500 * time.Millisecond)
}

func (nsc *NetworkServicesController) schedulePickupQueue(after time.Duration) {
	afterPickupOnce.Do(func() {
		nsc.syncLock.Lock()
		time.AfterFunc(after, nsc.pickupQueue)
	})
}

func (nsc *NetworkServicesController) pickupQueue() {

	start := time.Now()
	defer func() {
		nsc.syncLock.Unlock()
		if updatesQueue.Len() != 0 {
			nsc.schedulePickupQueue(100 * time.Millisecond)
		}
	}()

	grouped := 0
	transactions := (<-updatesQueue.Out()).([]interface{})
	total := len(transactions)
	changes := make(map[string]*tools.ApiTransaction)

	for _, val := range transactions {
		update := val.(*tools.ApiTransaction)
		kind := fmt.Sprintf("%T", update.Old)
		key := update.ObjMeta.GetNamespace() + update.ObjMeta.GetName() + kind
		if changes[key] == nil {
			changes[key] = update
		} else {
			changes[key].New = update.New
		}
	}

	for _, update := range changes {
		nsc.updateObjects(update.Old, update.New)
		grouped++
	}

	changes = nil
	afterPickupOnce = &sync.Once{}

	nsc.syncRelatedInfrastructure()
	tools.Eval(nsc.ipSet.Get(serviceIPsIPSetName).Commit())
	tools.Eval(nsc.ipSet.Get(ipvsServicesIPSetName).Commit())

	healthcheck.SendHeartBeat(nsc, metricsData)
	glog.Infof("Transaction sync services controller took %v (merged %d change(s) into %d)", time.Since(start), total, grouped)
}

func (nsc *NetworkServicesController) updateObjects(oldObj interface{}, newObj interface{}) {
	switch newTyped := newObj.(type) {
	case *k8sapi.Service:
		nsc.deployChangesSvc(nsc.buildServicesInfoFrom(nsc.serviceMap, oldObj.(*k8sapi.Service), true), nsc.buildServicesInfoFrom(nsc.serviceMap, newTyped, false))
	case *k8sapi.Endpoints:
		nsc.deployChangesEp(nsc.buildEndpointsInfoFrom(nsc.serviceMap, oldObj.(*k8sapi.Endpoints), true), nsc.buildEndpointsInfoFrom(nsc.serviceMap, newTyped, false))
	default:
	}
}

func (nsc *NetworkServicesController) removeEps(oldMap map[infoMapsKeyType]bool, newMap map[infoMapsKeyType]bool) {
	for key := range oldMap {
		if !newMap[key] {
			nsc.serviceMap[key].refreshEndpoints(SynchNotFound)
		}
	}
}

func (nsc *NetworkServicesController) deployChangesSvc(oldMap map[infoMapsKeyType]bool, newMap map[infoMapsKeyType]bool) {
	nsc.removeEps(oldMap, newMap)

	for key := range newMap {
		if !nsc.serviceMap[key].meta.change.CheckFor(SynchChanged) {
			continue
		}
		nsc.serviceMap[key].markEndpoints(SynchNotFound)
	}

	for key := range newMap {
		so := nsc.serviceMap[key]
		if so.meta.change & ^SynchNoChange == 0 {
			continue
		}
		eps, ok, _ := nsc.epLister.GetByKey(so.meta.namespace + "/" + so.meta.name)
		if !ok {
			continue
		}

		glog.V(3).Infoln("Building new endpoint map, because service changed: ", so.String(3))
		nsc.buildEndpointsInfoFrom(nsc.serviceMap, eps.(*k8sapi.Endpoints), false)
		so.activate()
		so.refreshEndpoints()

		nsc.addToIpSet(so.ksvc)
	}

}

func (nsc *NetworkServicesController) addToIpSet(ks *KubeService) {
	nsc.ipSet.Get(serviceIPsIPSetName).Append(ks.Address.String())
	nsc.ipSet.Get(ipvsServicesIPSetName).Append(fmt.Sprintf("%s,%s:%d", ks.Address.String(), ks.Protocol.String(), ks.Port))
}

func (nsc *NetworkServicesController) deployChangesEp(oldMap map[infoMapsKeyType]bool, newMap map[infoMapsKeyType]bool) {
	nsc.removeEps(oldMap, newMap)

	for key := range newMap {
		nsc.serviceMap[key].activate(SynchChanged)
		nsc.serviceMap[key].refreshEndpoints() //SynchChanged
	}
}

type destinationsMap map[infoMapsKeyType]*libipvs.Destination
type activeDstMapType map[infoMapsKeyType]destinationsMap

// sync the Ipvs service and server details configured to reflect the desired state of services and endpoint
// as learned from services and endpoints information from the api server
func (nsc *NetworkServicesController) syncIpvsServices() (err error) {
	nsc.syncLock.Lock()

	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		if nsc.MetricsEnabled {
			metrics.ControllerIpvsServicesSyncTime.Observe(endTime.Seconds())
		}
		nsc.syncLock.Unlock()
		glog.Infof("Sync Ipvs services took %v", endTime)
		metricsData.lastSync = endTime
	}()

	dummyVipInterface, err := nsc.ln.getKubeDummyInterface(true)
	if err != nil {
		return errors.New("Failed creating dummy interface: " + err.Error())
	}

	nsc.ln.resetDestinations()
	allSvcs := nsc.ln.ipvsGetServices()

	nsc.configuredDsrContainers = make(configuredDsrContainerType)

	if err = nsc.ln.setupPolicyRoutingForDSR(); err != nil {
		return err
	}

	nsc.serviceMap.ForEach(func(key infoMapsKeyType, so *serviceObject) {
		so.meta.change = SynchNotFound
		so.markEndpoints(SynchNotFound)
	})

	nsc.buildServicesInfo(nsc.serviceMap)
	nsc.buildEndpointsInfo(nsc.serviceMap)

	activeReferences = make(activeAddrsMapType)

	glog.V(1).Infof("Full-Syncing IPVS services")

	nsc.serviceMap.ForEach(func(key infoMapsKeyType, so *serviceObject) {
		so.activate()
		so.refreshEndpoints()
	})

	nsc.syncRelatedInfrastructure()

	activeSvcList := make(map[*KubeService]*serviceObject, 0)
	activeNativeSvcList := make(map[infoMapsKeyType]*serviceObject)
	activeDstMap := make(activeDstMapType)
	smRemove := make([]infoMapsKeyType, 0)

	for key, so := range nsc.serviceMap {
		if so.meta.change.CheckFor(SynchNotFound) {
			smRemove = append(smRemove, key)
			continue
		}
		if !so.hasEndpoints() {
			continue
		}
		for lt, ls := range so.linkedServices {
			ls.forEach(func(ks *KubeService) {
				activeSvcList[ks] = so

				activeNativeSvcList[ks.getHash()] = so

				if lt != LinkedServiceNodeport && !ks.isDSR() {
					activeReferences[ks.Address.String()] = true
				}

				so.updateActiveDstMap(activeDstMap, ks)

				metricsData.endpoints += so.GetEps().Size()
				metricsData.services++
			})
		}
	}

	for i := range smRemove {
		nsc.serviceMap[smRemove[i]] = nil
		delete(nsc.serviceMap, smRemove[i])
	}

	if err = nsc.syncIpvsFirewall(activeSvcList); err != nil {
		return err
	}

	startMetrics := time.Now()
	metrics.ControllerIpvsServices.Set(float64(len(allSvcs)))

	for _, svc := range allSvcs {
		hash := infoMapsKeyType(svc.FWMark)
		if hash == 0 {
			hash = generateId(svc)
		}
		if activeNativeSvcList[hash] != nil {
			if nsc.MetricsEnabled {
				nsc.pushMetrics(activeNativeSvcList[hash].meta, svc)
			}
			continue
		}

		if tools.CheckElementInArrayByFunction(svc.Address, nsc.excludedCidrs, comparerIPNet) {
			continue
		}

		tools.Eval(nsc.ln.ipvsDelService(&KubeService{Service: svc}))
	}

	if nsc.MetricsEnabled {
		metrics.ControllerIpvsMetricsExportTime.Observe(time.Since(startMetrics).Seconds())
	}

	for ks, so := range activeSvcList {
		so.epLock.Lock()
		dsts := nsc.ln.ipvsGetDestinations(ks.Service, false)
		eps := so.GetEps()
		epsSizeActive := so.GetEps().SizeActive()
		so.epLock.Unlock()

		if dsts.Size() < eps.Size() && dsts.Size() < epsSizeActive {
			glog.Warningf("Nr of svcs in state doesn't match machine state. Trying to fix (%d vs %d)",
				dsts.Size(), epsSizeActive)
			so.meta.change.add(SynchChanged)
			so.activate()
			so.refreshEndpoints(SynchNew)

			dsts = nsc.ln.ipvsGetDestinations(ks.Service, true)
			so.updateActiveDstMap(activeDstMap, ks)
		}

		if dsts.Size() > eps.Size() && dsts.Size() > epsSizeActive {
			glog.Warningf("Removing obsolete Destinations from %s", ks.String())
			for _, dst := range dsts {
				if !activeDstMap.contains(ks.getHash(), dst) {
					tools.Eval(nsc.ln.ipvsDelDestination(ks.Service, dst))
				}
			}
		}
		*(&dsts) = nil
	}

	nsc.lbHealthChecks.refreshSet()

	if err = nsc.syncIfAddress(dummyVipInterface, &activeReferences); err != nil {
		glog.Error(err)
	}

	return nil
}

func (so *serviceObject) updateActiveDstMap(activeDstMap activeDstMapType, ks *KubeService) {
	ipvsHash := ks.getHash()
	so.forEachEndpoint(func(ep *endpointInfo) error {
		if activeDstMap[ipvsHash] == nil {
			activeDstMap[ipvsHash] = make(destinationsMap)
		}
		var dst = ks.getDestination(ep)
		activeDstMap[ipvsHash][generateId(dst)] = dst
		return nil
	})
}

func (self *activeDstMapType) contains(svc infoMapsKeyType, dst *libipvs.Destination) bool {
	return (*self)[svc][generateId(dst)] != nil
}

func (nsc *NetworkServicesController) syncRelatedInfrastructure() {
	var err error

	glog.V(1).Infof("Setting up custom route table required to add routes for external IP's.")
	if err = nsc.ln.setupRoutesForExternalIPForDSR(&nsc.serviceMap); err != nil {
		glog.Error("Failed setup custom routing table required to add routes for external IP's due to: " + err.Error())
	}
	glog.V(1).Infof("Custom routing table " + customRouteTables[RouteTableExternal].Name + " required for Direct Server Return is setup as expected.")

	if err = nsc.ensureMasqueradeIptablesRule(nsc.masqueradeAll, nsc.podCidr, nsc.ln.GetNodeIP()); err != nil {
		glog.Errorf("Error masquerade iptable rules: %s", err.Error())
	}

	if err = nsc.syncHairpinIptablesRules(); err != nil {
		glog.Errorf("Error syncing Hairpin iptable rules: %s", err.Error())
	}

	if err = nsc.syncFwmarkIptablesRules(); err != nil {
		glog.Errorf("Error syncFwmarkIptablesRules iptable rules: %s", err.Error())
	}
}

func (nsc *NetworkServicesController) syncIfAddress(link netlink.Link, act *activeAddrsMapType) (errOut error) {
	var addrs []*net.IPNet
	var err error
	if addrs, err = hostnet.GetAllLocalIPs(hostnet.MatchPattern, link.Attrs().Name); err != nil {
		return errors.New("Failed to list dummy interface IPs: " + err.Error())
	}
	for _, addr := range addrs {
		if !(*act)[addr.IP.String()] {
			glog.V(1).Infof("Found an IP %s which is no longer needed so cleaning up", addr.String())
			if err = nsc.ln.ipAddrDel(link, addr, "syncIfAddress"); err != nil {
				errOut = tools.AppendErrorf(errOut, "Failed to delete stale IP %s due to: %s", addr.IP.String(), err.Error())
			}
		}
		// remove matched IPs. finally, the leftover addresses we put back to dummyIF
		// (as they should be present)
		delete(*act, addr.IP.String())
	}
	for addr := range *act {
		tools.Eval(nsc.ln.ipAddrAdd(link, hostnet.NewIP(addr).ToIPNet(), true))
	}

	return
}

func (nsc *NetworkServicesController) getPodObjectForEndpoint(endpointIP string) (*k8sapi.Pod, error) {
	for _, obj := range nsc.podLister.List() {
		pod := obj.(*k8sapi.Pod)
		if pod.Status.PodIP == endpointIP {
			return pod, nil
		}
	}
	return nil, tools.NewError("Failed to find pod with ip " + endpointIP)
}

func (ln *linuxNetworking) getDockerPid(containerId string) (int, error) {

	dockerClient, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return 0, tools.NewError("Failed to get docker client due to " + err.Error())
	}
	defer dockerClient.Close()

	containerSpec, err := dockerClient.ContainerInspect(context.Background(), containerId)
	if err != nil {
		return 0, tools.NewError("Failed to get docker container spec due to " + err.Error())
	}

	return containerSpec.State.Pid, nil
}

// This function does the following
// - get the pod corresponding to the endpoint Ip
// - get the container id from pod spec
// - from the container id, use docker client to get the pid
// - enter process network namespace and create ipip tunnel
// - add VIP to the tunnel interface
// - disable rp_filter
func (ln *linuxNetworking) prepareEndpointForDsrTunnel(pid int, ip net.IP, vip, svcPort, dstPort, proto string) (err error) {
	endpointIP := ip.String()

	var cmdParams = hostnet.NewIP(ip).ProtocolCmdParam()
	if _, err = runInNetNS(pid, tools.GetExecPath("ip"), cmdParams.Inet, "l", "show", KUBE_TUNNEL_IF); err != nil {
		if !strings.Contains(err.Error(), "does not exist") {
			return tools.NewError("Failed to verify if ipip tunnel interface exists in endpoint " + endpointIP + " namespace due to " + err.Error())
		}

		glog.V(2).Infof("Could not find tunnel interface " + KUBE_TUNNEL_IF + " in endpoint " + endpointIP + " so creating one.")
		if _, err = runInNetNS(pid, tools.GetExecPath("ip"), cmdParams.Inet, "tunnel", "add", KUBE_TUNNEL_IF, "mode", cmdParams.Mode, "local", endpointIP); err != nil {
			return tools.NewError("Failed to add ipip tunnel interface in endpoint namespace due to " + err.Error())
		}

		if _, err = runInNetNS(pid, tools.GetExecPath("ip"), cmdParams.Inet, "l", "show", KUBE_TUNNEL_IF); err != nil {
			return tools.NewError("Failed to get " + KUBE_TUNNEL_IF + " tunnel interface handle due to " + err.Error())
		}
		glog.V(2).Infof("Successfully created tunnel interface " + KUBE_TUNNEL_IF + " in endpoint " + endpointIP + ".")
	}

	// set mtu - count for Gre6tap (-48) ((
	ifMTU := hostnet.GetInterfaceMTU(options.KUBE_BRIDGE_IF)
	if _, err = runInNetNS(pid, tools.GetExecPath("ip"), cmdParams.Inet, "l", "set", "mtu", fmt.Sprint(ifMTU-cmdParams.ReduceMTU), KUBE_TUNNEL_IF); err != nil {
		return tools.NewError("Failed to bring up ipip tunnel interface in endpoint namespace due to " + err.Error())
	}

	// bring the tunnel interface up
	runInNetNS(pid, tools.GetExecPath("ip"), cmdParams.Inet, "l", "set", "up", KUBE_TUNNEL_IF)
	return
}

func getDsrIFName(isTunnel bool) string {
	if isTunnel {
		return KUBE_TUNNEL_IF
	}
	return KUBE_DUMMY_IF
}

func (ln *linuxNetworking) prepareEndpointForDsr(pid int, ip net.IP, vip, svcPort, dstPort, proto string, isTunnel bool) (errOut error) {
	var err error

	var ipCmds = hostnet.NewIP(ip).ProtocolCmdParam()

	runInNetNS(pid, tools.GetExecPath("ip"), "l", "del", "dev", getDsrIFName(!isTunnel))

	if !isTunnel {
		if _, err := runInNetNS(pid, tools.GetExecPath("ip"), "l", "add", KUBE_DUMMY_IF, "type", "dummy"); err != nil &&
			!strings.Contains(strings.ToLower(err.Error()), IFACE_HAS_ADDR) {
			glog.Error(err)
		} else {
			_, err = runInNetNS(pid, tools.GetExecPath("ip"), "l", "set", KUBE_DUMMY_IF, "mtu",
				fmt.Sprint(hostnet.GetInterfaceMTU(options.KUBE_BRIDGE_IF)), "up")
		}

		gw, _ := hostnet.GetAllLocalIPs(hostnet.MatchPattern, options.KUBE_BRIDGE_IF)
		_, err = runInNetNS(pid, tools.GetExecPath("ip"), ipCmds.Inet, "r", "replace", "default", "via", gw[0].IP.String(), "src", ip.String(),
			"dev", "eth0")
	}

	if err != nil {
		return tools.NewError("Failed to remove dsr interface" + err.Error())
	}

	_, err = runInNetNS(pid, tools.GetExecPath("sysctl"), "-w", "net.ipv4.conf."+getDsrIFName(isTunnel)+".rp_filter=0")
	if err == nil {
		_, err = runInNetNS(pid, tools.GetExecPath("sysctl"), "-w", "net.ipv4.conf.eth0.rp_filter=0")
	}
	if err == nil {
		_, err = runInNetNS(pid, tools.GetExecPath("sysctl"), "-w", "net.ipv4.conf."+ln.GetNodeIF()+".rp_filter=0")
	}
	if err == nil {
		_, err = runInNetNS(pid, tools.GetExecPath("sysctl"), "-w", "net.ipv4.conf.all.rp_filter=0")
	}
	if err != nil {
		return tools.NewError("Failed to disable rp_filters " + err.Error())
	}
	glog.V(2).Infof("Successfully disabled rp_filter in endpoint " + ip.String() + ".")

	// assign VIP to the KUBE_TUNNEL_IF interface
	ipCmds = hostnet.NewIP(vip).ProtocolCmdParam()

	if _, err = runInNetNS(pid, tools.GetExecPath("ip"), ipCmds.Inet, "a", "replace", vip, "dev", getDsrIFName(isTunnel), "scope", "host"); err != nil {
		errOut = tools.AppendErrorf(errOut, "Failed command: %s", fmt.Sprint(pid, tools.GetExecPath("ip"), ipCmds.Inet, "a", "replace", vip, "dev", getDsrIFName(isTunnel)))
	}
	glog.V(2).Infof("Successfully assigned VIP: " + vip + " in endpoint " + ip.String() + ".")

	return
}

func (ln *linuxNetworking) prepareEndpointForDsrNat(pid int, ip net.IP, vip, svcPort, dstPort, proto string) (errOut error) {
	var err error

	ipCmds := hostnet.NewIP(vip).ProtocolCmdParam()

	nat := []string{"PREROUTING", "-t", "nat", "-p", proto, "-m", proto, "--dport", svcPort, "-j", "REDIRECT", "--to-ports", dstPort, "-w"}
	if _, err = runInNetNS(pid, ipCmds.IptCmd, append([]string{ipCmds.Inet, "-C"}, nat...)...); err != nil {
		if out, err2 := runInNetNS(pid, ipCmds.IptCmd, append([]string{ipCmds.Inet, "-I"}, nat...)...); err2 != nil {
			errOut = tools.AppendErrorf(errOut, "Error creating port redirection in container:\n%s", err.Error(), string(out))
		}
	}

	return
}

var protocolParser = map[string]libipvs.Protocol{
	string(k8sapi.ProtocolTCP): libipvs.Protocol(syscall.IPPROTO_TCP),
	string(k8sapi.ProtocolUDP): libipvs.Protocol(syscall.IPPROTO_UDP),
}

func checkNopService(svc *k8sapi.Service) (ok bool) {
	if (svc.Spec.ClusterIP == "None" || svc.Spec.ClusterIP == "") && svc.Spec.Type == k8sapi.ServiceTypeClusterIP {
		glog.V(2).Infof("Skipping service name:%s namespace:%s as there is no cluster IP", svc.Name, svc.Namespace)
		return
	}

	if svc.Spec.Type == "ExternalName" {
		glog.V(2).Infof("Skipping service name:%s namespace:%s due to service Type=%s", svc.Name, svc.Namespace, svc.Spec.Type)
		return
	}

	if svc.ObjectMeta.Name == "" && svc.ObjectMeta.Namespace == "" {
		return
	}
	return true
}

func (nsc *NetworkServicesController) buildServicesInfo(serviceMap serviceInfoMapType) {
	var svc *k8sapi.Service
	for _, obj := range nsc.svcLister.List() {
		svc = obj.(*k8sapi.Service)
		nsc.buildServicesInfoFrom(serviceMap, svc, false)
	}
}

func (nsc *NetworkServicesController) buildServicesInfoFrom(serviceMap serviceInfoMapType, apiSvc *k8sapi.Service, remove bool) (keys map[infoMapsKeyType]bool) {
	keys = make(map[infoMapsKeyType]bool)
	if !checkNopService(apiSvc) {
		return
	}

	for _, port := range apiSvc.Spec.Ports {
		meta := &serviceMeta{
			name:      apiSvc.ObjectMeta.Name,
			namespace: apiSvc.ObjectMeta.Namespace,
			portName:  port.Name,
			change:    SynchNew,
			dsr:       getDsrMethod(apiSvc).String(),
		}

		svcId := generateId(meta)
		keys[svcId] = true

		if serviceMap[svcId] == nil {
			serviceMap[svcId] = nsc.newServiceObject(&serviceObject{meta: meta})
		}

		if remove {
			serviceMap[svcId].meta.change = SynchNotFound
			return
		}

		var so = serviceMap[svcId]

		nsc.updateCheckChange(so, apiSvc, &port)

		if so.meta.change.CheckFor(SynchNew) {
			so.ksvc.FWMark = 0
			so.ksvc.ipvsHash = generateId(so.ksvc.Service)
			serviceMap.ForEach(func(key infoMapsKeyType, soi *serviceObject) {
				if cmp.Equal(serviceMap[key].ksvc, so.ksvc, MatchKubeService) && key != svcId {
					serviceMap[key].meta.change = SynchNotFound
					serviceMap[key].endpoints = make(endpointInfoMapType)
				}
			})
		}

		so.nsc = nsc
	}
	return
}

func (nsc *NetworkServicesController) updateCheckChange(so *serviceObject, svc *k8sapi.Service, port *k8sapi.ServicePort) {
	var changed = SynchNoChange

	for _, obj := range []interface{}{so.ksvc.Service, so.info} {
		var equal = true
		switch objTyped := obj.(type) {
		case *serviceInfo:
			old := *objTyped
			if equal = cmp.Equal(&old, nsc.buildServiceInfo(objTyped, svc, port)); !equal && bool(glog.V(3)) {
				glog.V(3).Infof("Changed serviceInfo: %v\n", cmp.Diff(&old, objTyped))
			}
		case *libipvs.Service:
			old := *objTyped
			if equal = cmp.Equal(&old, nsc.buildIpvsService(objTyped, svc, port)); !equal && bool(glog.V(3)) {
				glog.V(3).Infof("Changed libipvs.Service: %v\n", cmp.Diff(&old, objTyped))
			}
		}
		if !equal {
			changed |= SynchChanged
		}
	}

	if so.meta.change.CheckFor(SynchNew) {
		return
	}

	if changed.CheckFor(SynchChanged) {
		so.meta.change = SynchChanged
		return
	}

	so.meta.change = SynchNoChange
}

func (nsc *NetworkServicesController) buildServiceInfo(svcInfo *serviceInfo, svc *k8sapi.Service, port *k8sapi.ServicePort) *serviceInfo {
	svcInfo.Nodeport = uint16(port.NodePort)
	svcInfo.ExternalIPs = append(svc.Spec.ExternalIPs)
	svcInfo.DirectServerReturnMethod = getDsrMethod(svc)

	for _, lbIngress := range svc.Status.LoadBalancer.Ingress {
		if _, ok := svc.ObjectMeta.Annotations[svcSkipLbIpsAnnotation]; ok && len(lbIngress.IP) > 0 {
			svcInfo.LoadBalancerIPs = append(svcInfo.LoadBalancerIPs, lbIngress.IP)
		}
	}
	_, svcInfo.Hairpin = svc.ObjectMeta.Annotations[svcHairpinAnnotation]
	_, svcInfo.Local = svc.ObjectMeta.Annotations[svcLocalAnnotation]

	if svc.Spec.ExternalTrafficPolicy == k8sapi.ServiceExternalTrafficPolicyTypeLocal {
		svcInfo.Local = true
		svcInfo.HealthCheckPort = svc.Spec.HealthCheckNodePort
	}
	return svcInfo
}

func getDsrMethod(svc *k8sapi.Service) libipvs.FwdMethod {
	if dsrMethod, ok := svc.ObjectMeta.Annotations[svcDSRAnnotation]; ok {
		if method, ok := libipvs.ParseFwdMethod(dsrMethod); ok == nil {
			return method
		}
	}
	return 1 << 31
}

func (nsc *NetworkServicesController) buildIpvsService(s *libipvs.Service, svc *k8sapi.Service, port *k8sapi.ServicePort) *libipvs.Service {
	iqip := hostnet.NewIP(svc.Spec.ClusterIP)
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
	for _, flag := range strings.Split(value, ",") {
		flags |= schedFlagsParser[strings.Trim(flag, " ")]
	}
	return
}

func (nsc *NetworkServicesController) buildEndpointsInfo(serviceMap serviceInfoMapType) {
	for _, obj := range nsc.epLister.List() {
		nsc.buildEndpointsInfoFrom(serviceMap, obj.(*k8sapi.Endpoints), false)
	}
}

func (nsc *NetworkServicesController) buildEndpointsInfoFrom(serviceMap serviceInfoMapType, ep *k8sapi.Endpoints, remove bool) (keys map[infoMapsKeyType]bool) {
	keys = make(map[infoMapsKeyType]bool)

	for _, epSubset := range ep.Subsets {
		for _, port := range epSubset.Ports {
			dsr := ""
			if svcObj, ok, _ := nsc.svcLister.GetByKey(ep.Namespace + "/" + ep.Name); ok {
				dsr = getDsrMethod(svcObj.(*k8sapi.Service)).String()
			}
			svcId := generateId(&serviceMeta{namespace: ep.Namespace, name: ep.Name, portName: port.Name, dsr: dsr})

			var so = serviceMap[svcId]
			if so == nil {
				if svc, ok, _ := nsc.svcLister.GetByKey(ep.Namespace + "/" + ep.Name); ok {
					nsc.buildServicesInfoFrom(serviceMap, svc.(*k8sapi.Service), false)
					so = serviceMap[svcId]
				}
			}

			if so == nil || so.meta.change.CheckFor(SynchNotFound) {
				continue
			}

			for _, addr := range epSubset.Addresses {

				epLocal := addr.NodeName != nil && *addr.NodeName == nsc.GetConfig().GetNodeName()

				if so.info.Local && !epLocal { //&& so.info.HealthCheckPort == 0 {
					continue
				}

				keys[svcId] = true

				so.epLock.Lock()

				dst := so.generateDestination(hostnet.NewIP(addr.IP).ToIP(), uint16(port.Port))
				ep := &endpointInfo{change: SynchNew, so: so, Destination: dst, isLocal: epLocal}

				_, ep = so.endpoints.Add(ep)
				if addr.TargetRef != nil && ep.containerID == "" {
					ep.containerID = refToContainerID(nsc, addr, ep)
				}
				if remove {
					ep.change = SynchNotFound
				}

				so.epLock.Unlock()
			}
		}
	}
	return
}

func refToContainerID(nsc *NetworkServicesController, addr k8sapi.EndpointAddress, ep *endpointInfo) (cid string) {
	if pod, ok, _ := nsc.podLister.GetByKey(addr.TargetRef.Namespace + "/" + addr.TargetRef.Name); ok {
		cid = strings.TrimPrefix(pod.(*k8sapi.Pod).Status.ContainerStatuses[0].ContainerID, "docker://")
	}
	return
}

const (
	CHAIN_KUBE_IPVS_SNAT_TARGET = "KUBE-ROUTER-POD-IPVS-SNAT"
	CHAIN_KUBE_MASQUERADE       = "KUBE-ROUTER-POD-MASQUERADE"
)

// Add an iptables rule to masquerade outbound IPVS traffic. IPVS nat requires that reverse path traffic
// to go through the director for its functioning. So the masquerade rule ensures source IP is modifed
// to node Ip, so return traffic from real server (endpoint pods) hits the node/lvs director
func (nsc *NetworkServicesController) ensureMasqueradeIptablesRule(masqueradeAll bool, podCidr string, ip *net.IPNet) (err error) {
	var args = &hostnet.IpTablesRuleListType{}

	err = nsc.Ipm.CreateRuleChain(hostnet.NewIP(ip).Protocol(), "nat", CHAIN_KUBE_IPVS_SNAT_TARGET,
		hostnet.IPTABLES_FULL_CHAIN_SYNC_NO_ORDER, true, hostnet.NewRuleList("-j", "SNAT", "--to", ip.IP.String()))

	if err == nil && masqueradeAll {
		args.Add(hostnet.NewRule("-m", "ipvs", "--ipvs", "--vdir", "ORIGINAL", "--vmethod", "MASQ", "-m", "comment", "--comment", "",
			"-j", CHAIN_KUBE_IPVS_SNAT_TARGET))
	}

	if err == nil && len(podCidr) > 0 {
		//TODO: ipset should be used for destination podCidr(s) match after multiple podCidr(s) per node get supported
		args.Add(hostnet.NewRule("-m", "ipvs", "--ipvs", "--vdir", "ORIGINAL", "--vmethod", "MASQ", "-m", "comment", "--comment", "",
			"!", "-s", podCidr, "!", "-d", podCidr, "-j", CHAIN_KUBE_IPVS_SNAT_TARGET))
	}

	if err = nsc.Ipm.CreateRuleChain(hostnet.NewIP(podCidr).Protocol(), "nat", CHAIN_KUBE_MASQUERADE, hostnet.IPTABLES_FULL_CHAIN_SYNC_NO_ORDER,
		true, args, hostnet.ReferenceFromType{In: "POSTROUTING"}); err != nil {
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
	rulesNeeded := hostnet.NewPerProtoRuleList()

	// Generate the rules that we need
	nsc.serviceMap.ForEach(func(key infoMapsKeyType, so *serviceObject) {
		if nsc.globalHairpin || so.info.Hairpin {
			for _, dst := range so.GetEps() {
				if !dst.isLocal {
					continue
				}
				// Handle ClusterIP Service
				eipStr := dst.Address.String()

				proto, rule := hairpinRuleFrom(so.ksvc.Address.String(), eipStr, so.ksvc.Protocol, so.ksvc.Port)
				rulesNeeded[proto].Add(hostnet.NewRule(rule.Args...))

				// Handle NodePort Service
				if so.info.Nodeport != 0 {
					proto, rule := hairpinRuleFrom(nsc.ln.GetNodeIP().IP.String(), eipStr, so.ksvc.Protocol, so.info.Nodeport)
					rulesNeeded[proto].Add(hostnet.NewRule(rule.Args...))
				}
			}
		}
	})

	if err = nsc.syncCustomChainRules("nat", CHAIN_HAIRPIN, rulesNeeded); err != nil {
		err = fmt.Errorf("syncHairpinIptablesRules: Error syncing rule %s", err.Error())
	}

	if err, _ = hostnet.UsedTcpProtocols.ForEachCreateRulesWithChain(nsc.Ipm, "nat", "POSTROUTING",
		hostnet.IPTABLES_APPEND_UNIQUE, true, hostnet.NewRuleList("-m", "ipvs", "--vdir", "ORIGINAL", "-j", CHAIN_HAIRPIN)); err != nil {
		err = fmt.Errorf("error updating reference to %s: %s", CHAIN_HAIRPIN, err.Error())
	}
	if err != nil {
		glog.Error(err)
	}
	return
}

func (nsc *NetworkServicesController) syncCustomChainRules(table, chain string, rulesNeeded hostnet.PerProtocolRuleListType, rin ...hostnet.ReferenceFromType) (err error) {
	if err, _ = hostnet.UsedTcpProtocols.ForEachCreateRulesWithChain(nsc.Ipm, table, chain,
		hostnet.IPTABLES_FULL_CHAIN_SYNC, true, rulesNeeded, rin...); err != nil {
		return
	}
	return
}

func hairpinRuleFrom(serviceIP, endpointIP string, proto libipvs.Protocol, servicePort uint16) (hostnet.Proto, *hostnet.IpTablesRuleType) {
	return hostnet.NewIP(endpointIP).Protocol(),
		hostnet.NewRule("-s", endpointIP, "-d", endpointIP, "-p", proto.String(),
			"-m", "ipvs", "--vaddr", serviceIP, "--vport", fmt.Sprint(servicePort),
			"-j", "SNAT", "--to-source", serviceIP)
}

func (nsc *NetworkServicesController) syncFwmarkIptablesRules() (err error) {
	rl := hostnet.NewPerProtoRuleList()
	nsc.computeFwMarkChain(rl)
	hostnet.UsedTcpProtocols.ForEach(func(p hostnet.Proto) error {
		rl[p].Add(hostnet.NewRuleWithOrder("-j", "MARK", "--set-mark", "0x800001", "-m", "set", "--match-set", nodeMACIPSetName, "src",
			"-m", "mark", "!", "--mark", "0"))
		return nil
	})
	if err = nsc.syncCustomChainRules("mangle", CHAIN_FWMARK, rl,
		hostnet.ReferenceFromType{In: "PREROUTING", Rule: []string{"-m", "set", "--match-set", ipvsServicesIPSetName, "dst,dst"}}, hostnet.ReferenceFromType{In: "OUTPUT", Rule: []string{"-m", "set", "--match-set", ipvsServicesIPSetName, "dst,dst", "-m", "mark", "--mark", "0"}, Pos: 2}); err != nil {
		return errors.New("syncFwmarkIptablesRules: Error syncing rule " + err.Error())
	}

	return hostnet.UsedTcpProtocols.ForEach(routeVIPTrafficToDirector)
}

func (nsc *NetworkServicesController) computeFwMarkChain(rn hostnet.PerProtocolRuleListType) hostnet.PerProtocolRuleListType {
	nsc.serviceMap.getDsrSvcData().forEach(func(ks *KubeService) {
		p, r := ks.getFwMarkRule()
		rn[p].Add(hostnet.NewRule(r.Args...))
	})
	return rn
}

func (nsc *NetworkServicesController) _deleteHairpinIptablesRules(protocol hostnet.Proto) error {
	return nsc.Ipm.IptablesCleanUpChain(protocol, CHAIN_HAIRPIN, true, "nat")
}

func (nsc *NetworkServicesController) _deleteFwmarkIptablesRules(protocol hostnet.Proto) error {
	return nsc.Ipm.IptablesCleanUpChain(protocol, CHAIN_FWMARK, true, "mangle")
}

func (nsc *NetworkServicesController) _deleteMasqueradeIptablesRule(protocol hostnet.Proto) (err error) {
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

func ipvsDestinationString(d *libipvs.Destination, v ...glog.Level) string {
	if d == nil || len(v) > 0 && !glog.V(v[0]) {
		return ""
	}
	return fmt.Sprintf("{%s} %s (Weight: %v)", d.FwdMethod.String(), hostnet.NewIP(d.Address).ToStringWithPort(d.Port), d.Weight)
}

func ipvsDeestinationArrayString(a []*libipvs.Destination) (out string) {
	for _, d := range a {
		out += "\t" + ipvsDestinationString(d) + "\n"
	}
	if out == "" {
		return "<nil>"
	}
	return
}

func (ln *linuxNetworking) ipvsAddOrUpdate(f, g func() error, checkErr string, ks *KubeService,
	dest *libipvs.Destination, update bool) (bool, error) {

	var err error
	if err = f(); err != nil && strings.Contains(strings.ToLower(err.Error()), checkErr) {
		return !update, g()
	} else if err != nil {
		glog.Errorf("Failed on service: %s\n%s", ks, ipvsDestinationString(dest))
	} else {
		glog.V(2).Infof("Successfully processed service: %s\n%s", ks, ipvsDestinationString(dest, 2))
	}
	return update, err
}

func (ln *linuxNetworking) ipvsAddService(ks *KubeService, create bool) (*libipvs.Service, error) {
	var err error
	var update = !create

	var createFn = func() error { return ln.ipvsNewService(ks) }
	var updateFn = func() error { return ln.ipvsUpdateService(ks) }

	if !update {
		_, err = ln.ipvsAddOrUpdate(createFn, updateFn, IPVS_SERVER_EXISTS, ks, nil, update)
	} else {
		_, err = ln.ipvsAddOrUpdate(updateFn, createFn, IPVS_SERVER_MISSING, ks, nil, update)
	}

	return ks.Service, err
}

func (ln *linuxNetworking) ipvsAddServer(ks *KubeService, ep *endpointInfo) (update bool, err error) {
	dest := ks.getDestination(ep)
	update = !ep.change.CheckFor(SynchNew)

	if ks.AddressFamily != dest.AddressFamily && !ep.isTunnelEp() {
		err = errors.New(fmt.Sprintf("Different address family is allowed only for tunneling servers\n\tvs: %s\n\trs: %s", ks.String(), ep.String()))
		glog.Error(err)
		return
	}

	var createFn = func() error { return ln.ipvsNewDestination(ks.Service, dest) }
	var updateFn = func() error { return ln.ipvsUpdateDestination(ks.Service, dest) }

	if !update {
		return ln.ipvsAddOrUpdate(createFn, updateFn, IPVS_SERVER_EXISTS, ks, dest, update)
	}
	return ln.ipvsAddOrUpdate(updateFn, createFn, "no such file", ks, dest, update)
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
	if out4, err = exec.Command(tools.GetExecPath("ip"), "-4", "route", "show", "table", RouteTableExternal).Output(); err == nil {
		outByte["-4"] = &out4
		if out6, err = exec.Command(tools.GetExecPath("ip"), "-6", "route", "show", "table", RouteTableExternal).Output(); err == nil {
			outByte["-6"] = &out6
		}
	}
	if err != nil {
		return errors.New("Failed to get routes in external_ip table due to: " + err.Error())
	}
	activeExternalIPs := make(map[string][]string)
	activeExternalIPs["nexthop"] = []string{}
	for _, so := range *serviceInfoMap {
		so.setupRoutesForExternalIPForDSR(&activeExternalIPs) //, outByte)
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
			if _, ok := activeExternalIPs[ip]; !ok || len(activeExternalIPs[ip]) > 0 {
				params := []string{hostnet.NewIP(ip).ProtocolCmdParam().Inet, "r", "del", ip, "table", RouteTableExternal}
				if ok {
					if !strings.Contains(line, strings.Join(activeExternalIPs[ip], " ")) {
						continue
					}
					params = append(params, activeExternalIPs[ip]...)
				}
				if err = exec.Command(tools.GetExecPath("ip"), params...).Run(); err != nil {
					glog.Errorf("Failed to del route for %v in custom route table for external IP's due to: %s", ip, err)
					continue
				}
			}
		}
	}

	return nil
}

func isEndpointsForLeaderElection(obj interface{}) (isLeaderElection bool) {
	if ep, ok := obj.(*k8sapi.Endpoints); ok {
		_, isLeaderElection = ep.Annotations[LeaderElectionRecordAnnotationKey]
	}
	return
}

func generateId(input interface{}) infoMapsKeyType {
	switch in := input.(type) {
	case *serviceMeta:
		return generateServiceId(in)
	case *endpointInfo:
		return generateEpPortId(in.Destination)
	case *libipvs.Destination:
		return generateEpPortId(in)
	case *libipvs.Service:
		return generateIpPortId(in)
	}
	glog.Errorf("Couldn't generate Id. Unknown type %T", input)
	return 0
}

// unique identifier for a load-balanced service (namespace + name + portname)
func generateServiceId(svc *serviceMeta) infoMapsKeyType {
	return infoMapsKeyType(tools.GetHash(svc.namespace + ":" + svc.name + ":" + svc.portName + ":" + svc.dsr))
}

func generateEpPortId(ipvsDst *libipvs.Destination) infoMapsKeyType {
	return infoMapsKeyType(tools.GetHash(ipvsDst.Address.String() + ":" + fmt.Sprint(ipvsDst.Port)))
}

// unique identifier for a load-balanced service
func generateIpPortId(ipvsSvc *libipvs.Service) infoMapsKeyType {
	if ipvsSvc.FWMark != 0 {
		return infoMapsKeyType(ipvsSvc.FWMark)
	}
	str := ipvsSvc.Address.String() + "," + ipvsSvc.Protocol.String() + ":" + fmt.Sprint(ipvsSvc.Port)
	return infoMapsKeyType(tools.GetHash(str))
}

const fwMarkTag = 1 << 18
const k8sUsed = 1<<15 | 1<<14

// generateFwmark: generate a uint32 hash value using the IP address, Port, protocol information
// TODO: collision can rarely happen but still need to be ruled out
// bit 15 is used by k8s as a "drop traffic" identifier
// bit 14 is used by k8s as a "masq traffic" identifier
func generateFwmark(ipvsSvc *libipvs.Service) uint32 {
	if ipvsSvc.FWMark != 0 {
		return ipvsSvc.FWMark
	}
	mark := uint32(generateIpPortId(ipvsSvc) & 0xffff)
	return (mark&k8sUsed)<<2 | mark & ^(uint32(k8sUsed)) | fwMarkTag
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
	}

	if err = netlink.LinkSetUp(dummyVipInterface); err != nil {
		return nil, errors.New("Failed to bring dummy interface up: " + err.Error())
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
	} else if err = hostnet.DelNetlinkInterface(dummyVipInterface); err != nil {
		return
	}
	glog.Infof("Successfully cleaned the Ipvs configuration done by kube-router")
}

func (nsc *NetworkServicesController) newEndpointsEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			nsc.OnUpdate(&tools.ApiTransaction{getMeta(obj), makeTypedEmptyObject(obj), obj})
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			nsc.OnUpdate(&tools.ApiTransaction{getMeta(oldObj), oldObj, newObj})
		},
		DeleteFunc: func(obj interface{}) {
			nsc.OnUpdate(&tools.ApiTransaction{getMeta(obj), obj, makeTypedEmptyObject(obj)})
		},
	}
}

func getMeta(obj interface{}) v1.Object {
	if svc, ok := obj.(*k8sapi.Service); ok {
		return svc.GetObjectMeta()
	}
	return obj.(*k8sapi.Endpoints).GetObjectMeta()
}

func makeTypedEmptyObject(obj interface{}) interface{} {
	switch obj.(type) {
	case *k8sapi.Service:
		return &k8sapi.Service{}
	}
	return &k8sapi.Endpoints{}
}

// NewNetworkServicesController returns NetworkServicesController object
func NewNetworkServicesController(config *options.KubeRouterConfig,
	svcInformer cache.SharedIndexInformer,
	epInformer cache.SharedIndexInformer, podInformer cache.SharedIndexInformer,
	nodeInformer cache.SharedIndexInformer) controllers.ControllerType {

	var err error

	ln, err := newLinuxNetworking(&config.NodeInfo)
	if err != nil {
		glog.Error(err.Error())
		return nil
	}
	nsc := NetworkServicesController{
		ln: ln,
	}
	nsc.Init("Services controller", config.IpvsSyncPeriod, config, nsc.run)

	nsc.ipSet = hostnet.NewIPSet()

	nsc.rejectTargets = []string{"REJECT"}
	if config.LogRejects {
		nsc.rejectTargets = []string{"LOG", "REJECT"}
	}

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

	nsc.globalHairpin = config.GlobalHairpinMode

	nsc.serviceMap = make(serviceInfoMapType)
	nsc.configuredDsrContainers = make(configuredDsrContainerType)

	nsc.lbHealthChecks.healthPort = fmt.Sprint(config.HealthPort)
	nsc.lbHealthChecks.enabledLBHealthCheckType = make(enabledLBHealthCheckType)

	nsc.masqueradeAll = config.MasqueradeAll

	nsc.nodeportBindOnAllIp = config.NodePortBindOnAllIp

	if config.RunRouter {
		if cidr, err := api.GetPodCidrFromNodeSpec(nsc.GetConfig().ClientSet, config.HostnameOverride); err != nil {
			glog.Errorf("failed to get pod CIDR details from Node.spec: %s", err.Error())
			return nil
		} else {
			nsc.podCidr = cidr.String()
		}
	}

	nsc.Ipm = hostnet.NewIpTablesManager(nsc.ln.GetNodeIP().IP)
	nsc.lbHealthChecks.healthIP = nsc.ln.GetNodeIP().IP.String()
	nsc.excludedCidrs = hostnet.NewIPNetList(config.ExcludedCidrs)

	nsc.Ipm.RegisterPeriodicFunction(nsc.ipvsServiceLBHealthChecksRule)

	nsc.podLister = podInformer.GetIndexer()
	nsc.nodeLister = nodeInformer.GetIndexer()

	nsc.svcLister = svcInformer.GetIndexer()
	nsc.ServiceEventHandler = nsc.newEndpointsEventHandler()
	svcInformer.AddEventHandler(nsc.ServiceEventHandler)

	nsc.epLister = epInformer.GetIndexer()
	nsc.EndpointsEventHandler = nsc.newEndpointsEventHandler()
	epInformer.AddEventHandler(nsc.EndpointsEventHandler)

	rand.Seed(time.Now().UnixNano())
	return &nsc
}
