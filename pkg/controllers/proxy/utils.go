package proxy

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/mqliang/libipvs"

	"github.com/pkg/errors"

	"github.com/cloudnativelabs/kube-router/pkg/utils/net-tools"
	"github.com/golang/glog"
	"github.com/google/go-cmp/cmp"
	"sync/atomic"
)

const (
	NL_ADDR_ADD    epActionType = false
	NL_ADDR_REMOVE epActionType = true
)

const (
	LINKED_SERVICE_NODEPORT linkedServiceType = 1 << iota
	LINKED_SERVICE_EXTERNALIP
	LINKED_SERVICE_NOTLINKED
)

const (
	SYNCH_NO_CHANGE synchChangeType = 1 << iota
	SYNCH_CHANGED
	SYNCH_NOT_FOUND
	SYNCH_NEW
)

const (
	ROUTE_TABLE_DSR      = "kube-router-dsr"
	ROUTE_TABLE_EXTERNAL = "external_ip"
)

var customRouteTables = netutils.RouteTableMapType{
	ROUTE_TABLE_DSR: netutils.RouteTableType{
		Desc:        "Setting up policy routing required for Direct Server Return functionality.",
		Id:          "78",
		Name:        ROUTE_TABLE_DSR,
		ForChecking: netutils.RouteTableCheck{Cmd: []string{"route", "list", "table", ROUTE_TABLE_DSR}, Output: "dev lo"},
		Cmd:         []string{"route", "replace", "local", "default", "dev", "lo", "table", ROUTE_TABLE_DSR},
	},
	ROUTE_TABLE_EXTERNAL: netutils.RouteTableType{
		Desc:        "Setting up custom route table required to add routes for external IP's.",
		Id:          "79",
		Name:        ROUTE_TABLE_EXTERNAL,
		ForChecking: netutils.RouteTableCheck{Cmd: []string{"rule", "list"}, Output: "lookup " + ROUTE_TABLE_EXTERNAL},
		Cmd:         []string{"rule", "add", "prio", "32765", "from", "all", "lookup", ROUTE_TABLE_EXTERNAL},
	},
}

var synchChangeTypeToString = map[synchChangeType]string{
	SYNCH_NO_CHANGE: "UNCHANGED",
	SYNCH_CHANGED:   "CHANGED",
	SYNCH_NEW:       "NEW",
	SYNCH_NOT_FOUND: "DELETED",
}

var linkedServiceTypeToString = map[linkedServiceType]string{
	LINKED_SERVICE_NODEPORT:   "LINKED_SERVICE_NODEPORT",
	LINKED_SERVICE_EXTERNALIP: "LINKED_SERVICE_EXTERNALIP",
	LINKED_SERVICE_NOTLINKED:  "LINKED_SERVICE_NOTLINKED",
}

type KubeService struct {
	*libipvs.Service
	lt       linkedServiceType
	ln       LinuxNetworking
	ipvsHash infoMapsKeyType

	*UsageLockType
}

type keyMetrics struct {
	services     int
	destinations int

	lastSync time.Duration
	fmt.Stringer
}

type synchChangeType byte

type epActionType bool

type linkedServiceType int

type linkedServiceListType []linkedServiceType

var allEndpointTypes = linkedServiceListType{LINKED_SERVICE_EXTERNALIP, LINKED_SERVICE_NODEPORT, LINKED_SERVICE_NOTLINKED}

var DeepComparerIpvsDestination = cmp.Comparer(DeepCompareDestination)
var ComparerIpvsDestination = cmp.Comparer(CompareEndpointDestination)
var ComparerKubeService = cmp.Comparer(CompareKubeService)

func init() {
	go watcher()
}

func (so *serviceObject) String() string {
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
	allEndpointTypes.ForEach(func(lt linkedServiceType) {
		out += fmt.Sprintf("\n%s: %s", lt, (*ls)[lt].String())
	})
	return
}

func (lt linkedServiceType) String() string {
	return linkedServiceTypeToString[lt]
}

func (ks *KubeService) String() string {
	var flags string
	for i, str := range serviceFlagToStringMap {
		if ks.Flags.Flags&i == i {
			flags += str
		}
	}
	return fmt.Sprintf("%s:%s (Flags: %s)", ks.Protocol.String(),
		netutils.NewIP(ks.Address).ToStringWithPort(fmt.Sprint(ks.Port)), flags)
}

func (eps *endpointInfoMapType) String() string {
	var out string
	for i := range *eps {
		out += fmt.Sprintf("    id:0x%x %s\n", i, (*eps)[i].String())
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

func (ep *endpointInfo) String() string {
	return fmt.Sprintf("addr: %s, locks: %d, change: %s",
		netutils.NewIP(ep.Address).ToStringWithPort(fmt.Sprint(ep.Port)), atomic.LoadUint32(&ep.used), ep.change.String())
}

func (km keyMetrics) String() string {
	return "= Services: " + fmt.Sprint(km.services) + ", Destinations: " + fmt.Sprint(km.destinations) +
		", LastSync took: " + km.lastSync.String()
}

func (sm *serviceInfoMapType) ForEach(f func(*serviceObject)) {
	for _, so := range *sm {
		f(so)
	}
}

func (sc synchChangeType) CheckFor(t synchChangeType) bool {
	return sc&t == t
}

func (sc synchChangeType) mergeChange(chng ...synchChangeType) synchChangeType {
	if len(chng) > 0 {
		return sc | chng[0]
	}
	return sc
}

func (ksa *kubeServiceArrayType) isPresent(ks *KubeService) (i int) {
	var ok bool
	if ok, i = utils.FindElementInArray(ks, ksa, ComparerKubeService); !ok {
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

func (ls *linkedServiceListMapType) clear(lt linkedServiceType) {
	(*ls)[lt] = &kubeServiceArrayType{}
}

func (ls *linkedServiceListMapType) init() {
	allEndpointTypes.ForEach((*ls).clear)
}

func (ks *KubeService) isFwMarkService() bool {
	return ks.FWMark != 0
}

func (ks *KubeService) clone(ip *net.IPNet, isFWMark bool, lt linkedServiceType, so *serviceObject) *KubeService {
	var used uint32 = 0
	clonedKs := &KubeService{Service: &libipvs.Service{}, ln: ks.ln, lt: lt, UsageLockType: &UsageLockType{used:used}}
	ipvsSvc := *ks.Service
	clonedKs.Service = &ipvsSvc

	if ip != nil {
		clonedKs.Address = ip.IP
	}

	if lt == LINKED_SERVICE_NODEPORT {
		clonedKs.Port = so.info.Nodeport
	}

	clonedKs.ipvsHash = generateFwmark(clonedKs.Service)
	if isFWMark {
		clonedKs.FWMark = uint32(clonedKs.ipvsHash)
	}

	clonedKs.UsageLockType.funcOnZero = func() {
		so.linkedServices[lt].remove(clonedKs)
		clonedKs.destroy()
	}

	return clonedKs
}

func (ks *KubeService) deploy(new bool) error {
	_, err := ks.ln.ipvsAddService(ks, new || atomic.LoadUint32(&ks.used) == 0)
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
	if ks.lt == LINKED_SERVICE_EXTERNALIP && ks.isFwMarkService() {
		var dst = *ep.Destination
		dst.FwdMethod = ep.so.getDSR()
		return &dst
	}
	return ep.Destination
}

func (ks *KubeService) attachDestination(ep *endpointInfo) (upd bool, err error) {
	upd, err = ks.ln.ipvsAddServer(ks, ep, ep.change.CheckFor(SYNCH_CHANGED))
	if ks.Protocol == syscall.IPPROTO_UDP {
		ep.connTrack = true
	}
	if err != nil {
		glog.Errorf(" Error attaching destination: %s - %s", ep.String(), err.Error())
	}
	return
}

func (ks *KubeService) detachDestination(ep *endpointInfo) (err error) {
	if _, dst := ks.refreshEp(ep); dst != nil && dst.Weight != 0 {
		ks.softDeregister(ep)
	} else {
		glog.Errorf(" Error delete destination:: %s - %s", ep.String(), err.Error())
	}
	return
}

func (ks *KubeService) purgeDestination(ep *endpointInfo) (err error) {
	if err = ks.ln.ipvsDelDestination(ks.Service, ks.getDestination(ep)); err != nil &&
		!strings.Contains(err.Error(), "NlMsgerr no such") {
		glog.Errorf("Can't remove destination due to: %s", err.Error())
		return
	}
	var so = ep.so
	count := ep.Unlock(ep.String())
	ks.Unlock(ks.String())
	if count == 0 {
		so.epLock.Unlock()
	}
	return
}

func (ks *KubeService) softDeregister(ep *endpointInfo) {
	ks.putStandbyEp(ep)
	epPurgeBacklogChannel <- &epPurgeBacklogDataType{ks: ks, ep: ep, ts: time.Now()}
}

func (ks *KubeService) putStandbyEp(ep *endpointInfo) (err error) {
	ep.so.epLock.Lock()
	defer ep.so.epLock.Unlock()
	ep.Weight = 0
	return ks.ln.ipvsUpdateDestination(ks.Service, ks.getDestination(ep))
}

func (ks *KubeService) refreshEp(ep *endpointInfo) (bool, *libipvs.Destination) {
	dsts := ks.ln.ipvsGetDestinations(ks.Service, true)
	if ok, i := utils.FindElementInArray(ks.getDestination(ep), dsts, ComparerIpvsDestination); ok {
		return true, dsts[i]
	}
	return false, nil
}

func (ks *KubeService) updateLinkAddr(action epActionType, addRoute ...bool) (err error) {
	if ks.isFwMarkService() {
		return
	}
	dummyIf, _ := ks.ln.getKubeDummyInterface()
	switch action {
	case NL_ADDR_REMOVE:
		err = ks.ln.ipAddrDel(dummyIf, netutils.NewIP(ks.Address).ToIPNet())
	case NL_ADDR_ADD:
		err = ks.ln.ipAddrAdd(dummyIf, netutils.NewIP(ks.Address).ToIPNet(), len(addRoute) > 0 && addRoute[0] == true)
	}
	return
}

type epPurgeBacklogDataType struct {
	ks *KubeService
	ep *endpointInfo
	ts time.Time
}

var epPurgeBacklogChannel = make(chan *epPurgeBacklogDataType, 50)

var graceDownPeriod = 15 * time.Second

func watcher() {
	var wos = make(map[*epPurgeBacklogDataType]bool)
	var wo *epPurgeBacklogDataType

	for {
		wo = &epPurgeBacklogDataType{}
		for wo != nil {
			select {
			case wo = <-epPurgeBacklogChannel:
				wos[wo] = true
			default:
				time.Sleep(time.Second)
				wo = nil
			}
		}
		for wo := range wos {
			if time.Since(wo.ts) < graceDownPeriod {
				continue
			}
			if ok, dst := wo.ks.refreshEp(wo.ep); ok && dst.ActiveConns == 0 && dst.InactConns == 0 {
				if nil == wo.ks.purgeDestination(wo.ep) {
					delete(wos, wo)
				}
			} else if !ok {
				delete(wos, wo)
			}
		}
	}
}

// For DSR it is required that we dont assign the VIP to any interface to avoid martian packets
// http://www.austintek.com/LVS/LVS-HOWTO/HOWTO/LVS-HOWTO.routing_to_VIP-less_director.html
// routeVIPTrafficToDirector: setups policy routing so that FWMARKed packets are deliverd locally
func routeVIPTrafficToDirector(p netutils.Proto) (err error) {
	var out []byte

	inet := netutils.NewIP(p).ProtocolCmdParam().Inet

	fwMarkStr := fmt.Sprintf("0x%x/0x%x", fwMarkTag, fwMarkTag)

	if out, err = exec.Command(utils.GetPath("ip"), inet, "rule", "list").Output(); err != nil {
		return errors.New("Failed to verify if `Ip rule` exists due to: " + err.Error())
	}

	output := string(out)
	if !strings.Contains(output, "fwmark "+fwMarkStr) {
		if err = exec.Command(utils.GetPath("ip"), inet, "rule", "add", "prio", "32764", "fwmark", fwMarkStr, "table", ROUTE_TABLE_DSR).Run(); err != nil {
			return errors.New("Failed to add policy rule to lookup traffic to VIP through the custom " +
				" routing table due to " + err.Error())
		}
	}

	return nil
}

func fwmarkRuleFrom(ks *KubeService) (netutils.Proto, *netutils.IpTablesRuleType) {
	return netutils.NewIP(ks.Address).Protocol(), &netutils.IpTablesRuleType{Args: []string{"-d", ks.Address.String(), "-p", ks.Protocol.String(), "-m", ks.Protocol.String(),
		"--dport", fmt.Sprint(ks.Port), "-j", "MARK", "--set-mark", fmt.Sprintf("0x%x", ks.FWMark)}}
}

func runInNetNS(pid int, cmd string, args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer

	args = append([]string{"-t", fmt.Sprint(pid), "-n", cmd}, args...)
	c := exec.Command("nsenter", args...)
	c.Stdout = &stdout
	c.Stderr = &stderr
	if err := c.Run(); err != nil {
		return nil, fmt.Errorf("%s: %s", string(stderr.Bytes()), err)
	}

	return stdout.Bytes(), nil
}

func (nsc *NetworkServicesController) getFwmarkSourceData() (fwmarkData kubeServiceArrayType) {
	nsc.serviceMap.ForEach(func(so *serviceObject) {
		if !so.isFwMarkService() {
			return
		}
		so.linkedServices[LINKED_SERVICE_EXTERNALIP].forEach(func(ks *KubeService) {
			fwmarkData = append(fwmarkData, ks)
		})
	})

	return fwmarkData
}

/* functions refactored using above wrapper. original  functions got "_" as prefix eg _deleteMasqueradeIptablesRule() */
func (nsc *NetworkServicesController) deleteMasqueradeIptablesRule() error {
	return netutils.UsedTcpProtocols.ForEach(nsc._deleteMasqueradeIptablesRule)
}

func (nsc *NetworkServicesController) deleteHairpinIptablesRules() error {
	return netutils.UsedTcpProtocols.ForEach(nsc._deleteHairpinIptablesRules)
}

func (nsc *NetworkServicesController) deleteFwmarkIptablesRules() error {
	return netutils.UsedTcpProtocols.ForEach(nsc._deleteFwmarkIptablesRules)
}

func CompareEndpointDestination(a, b *libipvs.Destination) bool {
	return a.Address.Equal(b.Address) && a.Port == b.Port
}

func DeepCompareDestination(a, b *libipvs.Destination) bool {
	return CompareEndpointDestination(a, b) && a.FwdMethod == b.FwdMethod
}

func CompareService(a, b *libipvs.Service) bool {
	if (a.FWMark | b.FWMark) != 0 {
		return a.FWMark == b.FWMark
	}
	return a.Address.Equal(b.Address) && a.Port == b.Port && a.Protocol == b.Protocol
}

func CompareKubeService(a, b *KubeService) bool {
	//return a.ipvsHash == b.ipvsHash
	return CompareService(a.Service, b.Service)
}

type UsageLockType struct {
	used        uint32
	funcOnZero  func()
}

func (lk *UsageLockType) Lock(id string) uint32 {
	count := atomic.AddUint32(&lk.used, uint32(1))
	fmt.Println("Lock: ", id, " ==", count)
	return count
}

func (lk *UsageLockType) Unlock(id string) uint32 {
	count := atomic.AddUint32(&lk.used, ^uint32(0))
	if count == 0 && lk.funcOnZero != nil {
		lk.funcOnZero()
	}
	fmt.Println("unlock: ", id, " ==", count)
	return count
}
