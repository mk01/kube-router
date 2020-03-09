package proxy

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/mqliang/libipvs"

	"container/list"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/async_worker"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/hostnet"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/tools"
	"github.com/golang/glog"
	"github.com/google/go-cmp/cmp"
	"sync"
)

type (
	KubeService struct {
		*libipvs.Service
		lt       linkedServiceType
		so       *serviceObject
		ln       LinuxNetworking
		ipvsHash infoMapsKeyType

		*UsageLockType
	}

	keyMetrics struct {
		services  int
		endpoints int

		lastSync time.Duration
		fmt.Stringer
	}

	PerServiceLockType map[infoMapsKeyType]*sync.Mutex

	configuredDsrContainerType map[string]bool

	epActionType bool

	linkedServiceListType []linkedServiceType

	postActionFunctionType func(*endpointInfo, *KubeService, epActionType)

	endpointInfoActionType func(*KubeService, synchChangeType, ...postActionFunctionType) error

	epPurgeBacklogDataType struct {
		ks *KubeService
		ep *endpointInfo
		ts syscall.Time_t
	}
)

const (
	NL_ADDR_ADD    epActionType = false
	NL_ADDR_REMOVE epActionType = true

	RouteTableDsr      = "kube-router-dsr"
	RouteTableExternal = "external_ip"
)

type linkedServiceType byte

const (
	LinkedServiceNodeport linkedServiceType = 1 << iota
	LinkedServiceExternalip
	LinkedServiceNotlinked
)

type synchChangeType byte

const (
	SynchNoChange synchChangeType = 1 << iota
	SynchChanged
	SynchNotFound
	SynchNew
)

var (
	ExternalRouteDirectMark = 1 << 27
	ExternalRouteDirect     = fmt.Sprintf("0x%x/0x%x", ExternalRouteDirectMark, ExternalRouteDirectMark)

	customRouteTables = hostnet.RouteTableMapType{
		RouteTableDsr: hostnet.RouteTableType{
			Desc:        "Setting up policy routing required for Direct Server Return functionality.",
			Id:          "78",
			Name:        RouteTableDsr,
			ForChecking: hostnet.RouteTableCheck{Cmd: []string{"route", "list", "table", RouteTableDsr}, Output: "dev lo"},
			Cmd:         []string{"route", "replace", "local", "default", "dev", "lo", "table", RouteTableDsr},
		},
		RouteTableExternal: hostnet.RouteTableType{
			Desc:        "Setting up custom route table required to add routes for external IP's.",
			Id:          "79",
			Name:        RouteTableExternal,
			ForChecking: hostnet.RouteTableCheck{Cmd: []string{"rule", "list", "prio", "32765"}, Output: "not from all fwmark " + ExternalRouteDirect + " lookup " + RouteTableExternal},
			Cmd:         []string{"rule", "add", "prio", "32765", "not", "fwmark", ExternalRouteDirect, "lookup", RouteTableExternal},
			CmdDisable:  []string{"rule", "del", "prio", "32765"},
		},
	}

	synchChangeTypeToString = map[synchChangeType]string{
		SynchNoChange: "UNCHANGED",
		SynchChanged:  "CHANGED",
		SynchNew:      "NEW",
		SynchNotFound: "DELETED",
	}

	linkedServiceTypeToString = map[linkedServiceType]string{
		LinkedServiceNodeport:   "LINKED_SERVICE_NODEPORT",
		LinkedServiceExternalip: "LINKED_SERVICE_EXTERNALIP",
		LinkedServiceNotlinked:  "LINKED_SERVICE_NOTLINKED",
	}
)

var allServicesTypes = linkedServiceListType{LinkedServiceExternalip, LinkedServiceNodeport, LinkedServiceNotlinked}

var MatchIpvsDestination = cmp.Comparer(CompareEndpointDestination)
var MatchKubeService = cmp.Comparer(compareKubeService)
var DeepMatchEndpoint = cmp.Comparer(DeepCompareEndpoint)

func (sl PerServiceLockType) Lock(hash infoMapsKeyType) {
	if sl[hash] == nil {
		sl[hash] = &sync.Mutex{}
	}
	sl[hash].Lock()
}

func (sl PerServiceLockType) Unlock(hash infoMapsKeyType) {
	sl[hash].Unlock()
}

func (da ipvsDestinationArrayType) Size() int {
	return len(da)
}

func (sm *serviceMeta) String() string {
	return fmt.Sprintf("s	vc: %s/%s, port: %s (%s) - %s\n", sm.name,
		sm.namespace, sm.portName, sm.dsr, sm.change.String())
}

func (so *serviceObject) String(v ...glog.Level) string {
	if len(v) > 0 && !glog.V(v[0]) {
		return ""
	}
	out := fmt.Sprintf("\nmeta: %v\n", *so.meta)
	out += fmt.Sprintf("info: %v\n", *so.info)
	out += fmt.Sprintf("ipvs: %v\n", (*so).ksvc.String())
	out += fmt.Sprintf("svcs: %v\n", (*so).linkedServices.String())
	return out + fmt.Sprintf("endpoints:\n%s", (*so).endpoints.String())
}

func (ksa *kubeServiceArrayType) String() (out string) {
	c := 0
	for _, s := range *ksa {
		out += fmt.Sprintf("\n    #%d: %s", c, s.String())
		c++
	}
	return
}

func (ls *linkedServiceListMapType) String() (out string) {
	allServicesTypes.ForEach(func(lt linkedServiceType) {
		out += fmt.Sprintf("\n%s: %s", lt, (*ls)[lt].String())
	})
	return
}

func (lt linkedServiceType) String() string {
	return linkedServiceTypeToString[lt]
}

func ipvsServiceString(ipvs *libipvs.Service, v ...glog.Level) string {
	if len(v) > 0 && !glog.V(v[0]) {
		return ""
	}
	return (&KubeService{Service: ipvs}).String()
}

func (ks *KubeService) String() string {
	var flags string
	for i, str := range serviceFlagToStringMap {
		if ks.Flags.Flags&i == i {
			flags += str
		}
	}
	return fmt.Sprintf("%s:%s {%s} fwm:0x%x (Flags: %s)", ks.Protocol.String(),
		hostnet.NewIP(ks.Address).ToStringWithPort(ks.Port), ks.getDSR(), ks.FWMark, flags)
}

func (eps *endpointInfoMapType) String() string {
	var out string
	for i := range *eps {
		out += fmt.Sprintf("    id:0x%x %s\n", i, (*eps)[i].String())
		_ = i
	}
	return out
}

func (sc synchChangeType) String() string {
	out := make([]string, 0)
	var i uint = 0
	for range fmt.Sprintf("%b", byte(sc)) {
		if sc.CheckFor(synchChangeType(1 << i)) {
			out = append(out, synchChangeTypeToString[synchChangeType(1<<i)])
		}
		i++
	}
	return fmt.Sprint(out)
}

func (ep *endpointInfo) String(v ...glog.Level) string {
	if len(v) > 0 && !glog.V(v[0]) {
		return ""
	}
	return fmt.Sprintf("addr: %s, fwd: %s, locks: %d, change: %s",
		hostnet.NewIP(ep.Address).ToStringWithPort(ep.Port), ep.FwdMethod.String(), len(ep.used), ep.change.String())
}

func (km keyMetrics) String() string {
	return "= Services: " + fmt.Sprint(km.services) + ", Endpoints: " + fmt.Sprint(km.endpoints) +
		", LastSync took: " + km.lastSync.String()
}

func (sm serviceInfoMapType) ForEach(f func(infoMapsKeyType, *serviceObject)) {
	for key, so := range sm {
		f(key, so)
	}
}

func (sc synchChangeType) CheckFor(t synchChangeType) bool {
	return sc&t == t
}

func (sc synchChangeType) add(chng ...synchChangeType) synchChangeType {
	if len(chng) > 0 {
		return sc | chng[0]
	}
	return sc
}

func (ksa *kubeServiceArrayType) isPresent(ks *KubeService) (i int) {
	var ok bool
	if ok, i = tools.FindElementInArray(ks, ksa, MatchKubeService); !ok {
		return -1
	}
	return i
}

func (ksa *kubeServiceArrayType) add(ks *KubeService) {
	*ksa = append(*ksa, ks)
}

func (ksa *kubeServiceArrayType) forEach(f func(*KubeService)) {
	for _, ks := range *ksa {
		f(ks)
	}
}

func (ksa *kubeServiceArrayType) remove(ks *KubeService) {
	if i := ksa.isPresent(ks); i != -1 {
		copy((*ksa)[i:], (*ksa)[i+1:])
		(*ksa)[len(*ksa)-1] = nil
		*ksa = (*ksa)[:len(*ksa)-1]
	}
}

func (lsl *linkedServiceListType) ForEach(f func(linkedServiceType)) {
	for _, lt := range *lsl {
		f(lt)
	}
}

func (ls linkedServiceListMapType) clear(lt linkedServiceType) {
	ls[lt] = &kubeServiceArrayType{}
}

func (ls linkedServiceListMapType) init() {
	allServicesTypes.ForEach(ls.clear)
}

func (ep *endpointInfo) isTunnelEp() bool {
	return ep.FwdMethod == libipvs.IP_VS_CONN_F_TUNNEL
}

func (ks *KubeService) isDSR(fwType ...libipvs.FwdMethod) bool {
	return ks.lt == LinkedServiceExternalip && ks.so.isDSR(fwType...)
}

func (ks *KubeService) getDSR() libipvs.FwdMethod {
	if ks.isDSR() {
		return ks.so.getDSR()
	}
	return libipvs.IP_VS_CONN_F_MASQ
}

func (ks *KubeService) isTunnelService() bool {
	return ks.so.isDSR(libipvs.IP_VS_CONN_F_TUNNEL)
}

func (ks *KubeService) getHash() infoMapsKeyType {
	if ks.FWMark != 0 {
		return infoMapsKeyType(ks.FWMark)
	}
	return ks.ipvsHash
}

func (ks *KubeService) clone(ip *net.IPNet, isFWMark bool, lt linkedServiceType, so *serviceObject) *KubeService {
	clonedKs := &KubeService{ln: ks.ln, lt: lt, so: so}
	ipvsSvc := *ks.Service
	clonedKs.Service = &ipvsSvc
	clonedKs.FWMark = 0

	if ip != nil {
		clonedKs.Address = ip.IP
	}

	if lt == LinkedServiceNodeport {
		clonedKs.Port = so.info.Nodeport
	}

	clonedKs.FWMark = 0
	clonedKs.ipvsHash = generateId(clonedKs.Service)
	if isFWMark {
		clonedKs.FWMark = generateFwmark(clonedKs.Service)
	}

	clonedKs.UsageLockType = &UsageLockType{used: make(map[infoMapsKeyType]bool), gc: func() {
		so.linkedServices[lt].remove(clonedKs)
		clonedKs.destroy()
	}}

	return clonedKs
}

func (ks *KubeService) deploy(new bool) error {
	_, err := ks.ln.ipvsAddService(ks, new || len(ks.used) == 0)

	return err
}

func (ks *KubeService) destroy() (err error) {
	if err = ks.ln.ipvsDelService(ks); err == nil {
		ks.updateLinkAddr(NL_ADDR_REMOVE)
	} else {
		glog.Errorf("failed to delete %v", ks)
	}
	return err
}

func (ks *KubeService) getDestination(ep *endpointInfo) *libipvs.Destination {
	var out = ep.Destination
	if ks.lt != LinkedServiceExternalip {
		var dst = *ep.Destination
		dst.FwdMethod = libipvs.IP_VS_CONN_F_MASQ
		out = &dst
	}
	glog.V(3).Infof("Returning destination %s (%s)", ipvsDestinationString(out, 3), ks.lt.String())
	return out
}

func (ks *KubeService) attachDestination(ep *endpointInfo) (upd bool, err error) {
	upd, err = ks.ln.ipvsAddServer(ks, ep)
	if ks.Protocol == syscall.IPPROTO_UDP {
		ep.connTrack = true
	}
	if err != nil {
		err = fmt.Errorf(" Error attaching destination: %s - %s", ep.String(), err.Error())
		glog.Error(err)
	}
	return
}

func (ks *KubeService) detachDestination(ep *endpointInfo) (err error) {
	if _, dst := ks.refreshEp(ep, false, nil); dst != nil && dst.Weight != 0 {
		ks.so.nsc.epPurgeBacklogChannel <- &epPurgeBacklogDataType{ks: ks, ep: ep}
	} else if dst == nil && !ep.change.CheckFor(SynchChanged) {
		err = fmt.Errorf(" Error delete destination: %s", ep.String())
		glog.Error(err)
	}
	return
}

func (ks *KubeService) purgeDestination(ep *endpointInfo) (err error) {
	if err = ks.ln.ipvsDelDestination(ks.Service, ks.getDestination(ep)); err != nil &&
		!strings.Contains(err.Error(), "NlMsgerr no such") {
		glog.Errorf("Can't remove destination due to: %s", err.Error())
		return
	}
	glog.V(1).Infof("Successfully removed destination %s from the service %s", ep.String(1), ks.String())

	var so = ep.so
	var count = ep.Unlock(ks.getHash())

	ks.Unlock(ep.hash)
	if count == 0 {
		so.epLock.Unlock()
	}
	if !so.hasEndpoints() {
		so.meta.change = SynchNotFound
	}
	return nil
}

func (ks *KubeService) softPurgeDestination(ep *endpointInfo) (err error) {
	ep.Weight = 0
	if err = ks.ln.ipvsUpdateDestination(ks.Service, ks.getDestination(ep)); err == nil {
		glog.V(1).Infof("Successfully deconfigured destination %s from service %s", ep.String(1), ks)
	} else {
		glog.Errorf("Error deconfiguring destination %s from service %s", ep.String(), ks)
	}
	return
}

func (ks *KubeService) refreshEp(ep *endpointInfo, force bool, rrTime *syscall.Time_t) (bool, *libipvs.Destination) {
	dsts := ks.ln.ipvsGetDestinations(ks.Service, force)
	if force && rrTime != nil {
		syscall.Time(rrTime)
	}
	if ok, i := tools.FindElementInArray(ks.getDestination(ep), dsts, MatchIpvsDestination); ok {
		return ep.Weight == 0, dsts[i]
	}
	return false, nil
}

func (ks *KubeService) updateLinkAddr(action epActionType, addRoute ...bool) (err error) {
	var ip = hostnet.NewIP(ks.Address).ToIPNet()
	glog.V(3).Infof("updateLinkAddr called, action remove: %v, addr: %s, tunnel: %v", action, ip, ks.isTunnelService())

	dummyIf, _ := ks.ln.getKubeDummyInterface()
	switch {
	case action == NL_ADDR_REMOVE || ks.isDSR():
		err = ks.ln.ipAddrDel(dummyIf, ip, "updateLinkAddr")
	case action == NL_ADDR_ADD:
		err = ks.ln.ipAddrAdd(dummyIf, ip, len(addRoute) > 0 && addRoute[0] == true)
	}
	return
}

func (ks *KubeService) getFwMarkRule() (hostnet.Proto, *hostnet.IpTablesRuleType) {
	return hostnet.NewIP(ks.Address).Protocol(), &hostnet.IpTablesRuleType{Args: []string{"-d", ks.Address.String(), "-p", ks.Protocol.String(), "-m", ks.Protocol.String(),
		"--dport", fmt.Sprint(ks.Port), "-j", "MARK", "--set-mark", fmt.Sprintf("0x%x", generateFwmark(ks.Service))}}
}

func (so *serviceObject) activateHealthCkeck(hc *lbHealthChecksListType) {
	if !so.hasLocalEndepoints() || so.info.HealthCheckPort == 0 || hc.enabledLBHealthCheckType[so] {
		return
	}
	glog.V(3).Infof("Activating healthCheck adding %s", so.String(3))
	hc.enabledLBHealthCheckType[so] = true
	hc.refreshSet()
}

func (so *serviceObject) deactivateHealthCkeck(hc *lbHealthChecksListType) {
	if so.hasLocalEndepoints() && so.info.HealthCheckPort != 0 || !hc.enabledLBHealthCheckType[so] {
		return
	}
	glog.V(3).Infof("Deactivating healthCheck for %s", so.String(3))
	delete(hc.enabledLBHealthCheckType, so)
	hc.refreshSet()
}

func (hc *lbHealthChecksListType) refreshSet() {
	var ports []string
	for so := range hc.enabledLBHealthCheckType {
		ports = append(ports, fmt.Sprint(so.nsc.ln.GetNodeIP().IP.String()+","+fmt.Sprint(so.info.HealthCheckPort)))
	}
	ports = append(ports, hc.healthIP+","+hc.healthPort)
	hc.Set.RefreshAsync(ports)
}

type endpointPurgerType struct {
	async_worker.Worker
	epPurgeBacklogChannel chan *epPurgeBacklogDataType
	graceDownPeriod       uint64
}

func (epw *endpointPurgerType) StartWorker() {
	go epw.loop()
}

func (epw *endpointPurgerType) StopWorker() {
	close(epw.epPurgeBacklogChannel)
}

func (epw *endpointPurgerType) loop() {
	var wos = list.New()
	var w *list.Element
	var ttime, refreshTime syscall.Time_t

	go func() {
		for wo := range epw.epPurgeBacklogChannel {
			wo.ks.softPurgeDestination(wo.ep)

			syscall.Time(&wo.ts)
			wos.PushBack(wo)
		}
		glog.V(3).Infof("%s - epPurgeBacklogChannel consumer done", epw.GetName())
	}()

	syscall.Time(&refreshTime)
	for !epw.IsStopped() {
		if w == nil {
			time.Sleep(time.Second)
			w = wos.Front()
			if w != nil {
				w.Value.(*epPurgeBacklogDataType).ks.ln.resetDestinations()
			}
		}

		if epw.IsStopped() || w == nil {
			continue
		}

		syscall.Time(&ttime)
		wo := w.Value.(*epPurgeBacklogDataType)
		if ttime < wo.ts+syscall.Time_t(epw.graceDownPeriod) {
			w = w.Next()
			continue
		}
		if ok, dst := wo.ks.refreshEp(wo.ep, (ttime-refreshTime) > 1, &refreshTime); !ok || ok && dst.ActiveConns == 0 && dst.InactConns == 0 {
			ok = true
			if dst != nil && dst.Weight == 0 {
				ok = nil == wo.ks.purgeDestination(wo.ep)
			}
			if ok {
				rmw := w
				w = w.Next()
				wos.Remove(rmw)
				continue
			}
		}
		w = w.Next()
	}
	glog.V(3).Infof("%s done", epw.GetName())
	epw.Done()
}

// For DSR it is required that we dont assign the VIP to any interface to avoid martian packets
// http://www.austintek.com/LVS/LVS-HOWTO/HOWTO/LVS-HOWTO.routing_to_VIP-less_director.html
// routeVIPTrafficToDirector: setups policy routing so that FWMARKed packets are deliverd locally
func routeVIPTrafficToDirector(p hostnet.Proto) (err error) {
	var out []byte

	inet := hostnet.NewIP(p).ProtocolCmdParam().Inet

	fwMarkStr := fmt.Sprintf("0x%x/0x%x", fwMarkTag, fwMarkTag)

	if out, err = exec.Command(tools.GetExecPath("ip"), inet, "rule", "list").Output(); err != nil {
		return tools.AppendErrorf(err, "Failed to verify if `Ip rule` exists")
	}

	output := string(out)
	if strings.Contains(output, "fwmark "+fwMarkStr) {
		return
	}

	if err = exec.Command(tools.GetExecPath("ip"), inet, "rule", "add", "prio", "32764", "fwmark", fwMarkStr, "table", RouteTableDsr).Run(); err != nil {
		err = tools.AppendErrorf(err, "Failed to add policy rule to lookup traffic to VIP through the custom routing table")
	}
	return
}

func runInNetNS(pid int, cmd string, args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer

	c := exec.Command("nsenter", append([]string{"-t", fmt.Sprint(pid), "-n", cmd}, args...)...)
	c.Stdout = &stdout
	c.Stderr = &stderr
	if err := c.Run(); err != nil {
		glog.V(3).Infoln("Failed cmd: "+c.Path, c.Args, ", error: ", err.Error())
		return nil, tools.NewErrorf("%s: %s", string(stderr.Bytes()), err.Error())
	}

	return stdout.Bytes(), nil
}

func (sm serviceInfoMapType) getDsrSvcData(fwType ...libipvs.FwdMethod) *kubeServiceArrayType {
	dsrSvcs := kubeServiceArrayType{}
	sm.ForEach(func(key infoMapsKeyType, so *serviceObject) {
		if !so.isDSR(fwType...) {
			return
		}
		so.linkedServices[LinkedServiceExternalip].forEach(func(ks *KubeService) {
			dsrSvcs = append(dsrSvcs, ks)
		})
	})

	return &dsrSvcs
}

/* functions refactored using above wrapper. original  functions got "_" as prefix eg _deleteMasqueradeIptablesRule() */
func (nsc *NetworkServicesController) deleteMasqueradeIptablesRule() error {
	return hostnet.UsedTcpProtocols.ForEach(nsc._deleteMasqueradeIptablesRule)
}

func (nsc *NetworkServicesController) deleteHairpinIptablesRules() error {
	return hostnet.UsedTcpProtocols.ForEach(nsc._deleteHairpinIptablesRules)
}

func (nsc *NetworkServicesController) deleteFwmarkIptablesRules() error {
	return hostnet.UsedTcpProtocols.ForEach(nsc._deleteFwmarkIptablesRules)
}

func CompareEndpointDestination(a, b *libipvs.Destination) bool {
	return a.Address.Equal(b.Address) && a.Port == b.Port && a.FwdMethod == b.FwdMethod
}

func DeepCompareEndpoint(a, b *endpointInfo) bool {
	return CompareEndpointDestination(a.Destination, b.Destination) &&
		a.isLocal == b.isLocal
}

func compareKubeService(a, b *KubeService) bool {
	return a.ipvsHash == b.ipvsHash && a.lt == b.lt && a.Flags == b.Flags &&
		a.SchedName == b.SchedName && a.FWMark == b.FWMark
}

func (ks *KubeService) Equals(eqTo *KubeService) bool {
	return compareKubeService(ks, eqTo)
}

func comparerIPNet(a, b interface{}) bool {
	tb, okb := b.(*net.IPNet)
	ta, oka := a.(net.IP)
	if !(oka && okb) {
		return false
	}
	return tb.Contains(ta)
}

type UsageLockType struct {
	sync.Mutex
	used map[infoMapsKeyType]bool
	gc   func()
}

func (lk *UsageLockType) Lock(key infoMapsKeyType) (diff int) {
	lk.Mutex.Lock()
	diff = len(lk.used)
	lk.used[key] = true
	diff -= len(lk.used)
	lk.Mutex.Unlock()
	return
}

func (lk *UsageLockType) Unlock(key infoMapsKeyType) (count int) {
	lk.Mutex.Lock()
	delete(lk.used, key)
	if count = len(lk.used); count == 0 && lk.gc != nil {
		lk.gc()
	}
	lk.Mutex.Unlock()
	return
}
