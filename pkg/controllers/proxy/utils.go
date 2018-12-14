package proxy

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/mqliang/libipvs"

	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"

	"github.com/cloudnativelabs/kube-router/pkg/utils/net-tools"
	"github.com/coreos/go-iptables/iptables"
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

var customRouteTables = map[string]routeTableType{
	ROUTE_TABLE_DSR: {
		desc:        "Setting up policy routing required for Direct Server Return functionality.",
		id:          "78",
		name:        ROUTE_TABLE_DSR,
		forChecking: routeTableCheck{cmd: []string{"route", "list", "table", ROUTE_TABLE_DSR}, output: "dev lo"},
		cmd:         []string{"route", "replace", "local", "default", "dev", "lo", "table", ROUTE_TABLE_DSR},
	},
	ROUTE_TABLE_EXTERNAL: {
		desc:        "Setting up custom route table required to add routes for external IP's.",
		id:          "79",
		name:        ROUTE_TABLE_EXTERNAL,
		forChecking: routeTableCheck{cmd: []string{"rule", "list"}, output: "lookup " + ROUTE_TABLE_EXTERNAL},
		cmd:         []string{"rule", "add", "prio", "32765", "from", "all", "lookup", ROUTE_TABLE_EXTERNAL},
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
	lt   linkedServiceType
	ln   LinuxNetworking
	used *map[*endpointInfo]bool
}

type routeTableCheck struct {
	cmd    []string
	output string
}

type routeTableType struct {
	desc        string
	id          string
	name        string
	cmd         []string
	forChecking routeTableCheck
}

type synchChangeType byte

type perProtocolRuleType map[netutils.Proto]netutils.IpTablesRuleListType

type epActionType bool

type linkedServiceType int

var allEndpointTypes = []linkedServiceType{LINKED_SERVICE_EXTERNALIP, LINKED_SERVICE_NODEPORT, LINKED_SERVICE_NOTLINKED}

var DeepComparerIpvsDestination = cmp.Comparer(DeepCompareDestination)
var ComparerIpvsDestination = cmp.Comparer(CompareEndpointDestination)
var ComparerIpvsService = cmp.Comparer(CompareService)
var ComparerKubeService = cmp.Comparer(CompareKubeService)

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
	for _, lt := range allEndpointTypes {
		out += fmt.Sprintf("\n%s: %s", lt, (*ls)[lt].String())
	}
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
	return fmt.Sprintf("%s:%s (Flags: %s), used %d", ks.Protocol.String(),
		netutils.NewIP(ks.Address).ToStringWithPort(fmt.Sprint(ks.Port)), flags, len(*ks.used))
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
	return fmt.Sprintf("addr: %s, port: %s, locks: %d, change: %s", ep.Address,
		fmt.Sprint(ep.Port), ep.used, ep.change.String())
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

func (ksa *kubeServiceArrayType) remove(ks *KubeService) {
	i := ksa.isPresent(ks)
	copy((*ksa)[i:], (*ksa)[i+1:])
	(*ksa)[len(*ksa)-1] = nil
	*ksa = (*ksa)[:len(*ksa)-1]
}

func (ls *linkedServiceListMapType) clear(lt linkedServiceType) {
	(*ls)[lt] = new(kubeServiceArrayType)
}

func (ls *linkedServiceListMapType) init() {
	for _, lt := range allEndpointTypes {
		(*ls).clear(lt)
	}
}

func (ks *KubeService) isFwMarkService() bool {
	return ks.FWMark != 0
}

func (ks *KubeService) clone(ip *net.IPNet, isFWMark bool, lt linkedServiceType, info *serviceInfo) *KubeService {
	newKs := KubeService{ln: ks.ln, lt: lt, used: ks.used}
	ipvs := *ks.Service
	newKs.Service = &ipvs

	if ip != nil {
		newKs.Address = ip.IP
	}
	if lt == LINKED_SERVICE_NODEPORT {
		newKs.Port = info.Nodeport
	}
	if isFWMark {
		newKs.FWMark = uint32(generateFwmark(newKs.Service))
	}
	return &newKs
}

func (ks *KubeService) deploy(update bool) error {
	_, err := ks.ln.ipvsAddService(ks, update)
	return err
}

func (ks *KubeService) destroy() (err error) {
	if err = ks.ln.ipvsDelService(ks); err == nil {
		ks.updateLinkAddr(NL_ADDR_REMOVE)
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
	if err == nil {
		ks.lock(ep)
	}
	return
}

func (ks *KubeService) lock(ep *endpointInfo) {
	(*ks.used)[ep] = true
}

func (ks *KubeService) release(ep *endpointInfo) {
	delete(*ks.used, ep)
	if len(*ks.used) == 0 {
		ep.so.linkedServices[ks.lt].remove(ks)
		ks.destroy()
	}
}

func (ks *KubeService) detachDestination(ep *endpointInfo) (err error) {
	if _, dst := ks.refreshEp(ep); dst != nil && dst.Weight != 0 {
		ks.softDeregister(ep, dst)
		ep.Weight = 0
		return
	}
	if err = ks.ln.ipvsDelDestination(ks.Service, ep.Destination); err == nil {
		ks.release(ep)
		ep.release()
	}
	return
}

func (ks *KubeService) softDeregister(ep *endpointInfo, dst *libipvs.Destination) {
	ks.putStandbyEp(ep, dst)
	epPurgeBacklogChannel <- &epPurgeBacklogDataType{ks: ks, ep: ep}
	if atomic.CompareAndSwapInt32(&running, 0, 1) {
		go watcher()
	}
}

func (ks *KubeService) putStandbyEp(ep *endpointInfo, dst *libipvs.Destination) (err error) {
	dst.Weight = 0
	return ks.ln.ipvsUpdateDestination(ks.Service, dst)
}

func (ks *KubeService) refreshEp(ep *endpointInfo) (bool, *libipvs.Destination) {
	dsts := ks.ln.ipvsGetDestinations(ks.Service)
	if ok, i := utils.FindElementInArray(ep.Destination, dsts, ComparerIpvsDestination); ok {
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
}

var epPurgeBacklogChannel = make(chan *epPurgeBacklogDataType, 50)

var running int32 = 0

func watcher() {
	defer atomic.StoreInt32(&running, 0)

	var wos = make(map[*epPurgeBacklogDataType]bool)
	var length = -1

	for length != 0 {
		time.Sleep(10 * time.Second)

		for length != 0 {
			select {
			case wo := <-epPurgeBacklogChannel:
				wos[wo] = true
			default:
				length = 0
			}
		}

		for wo := range wos {
			if ok, dst := wo.ks.refreshEp(wo.ep); ok && dst.ActiveConns == 0 && dst.InactConns == 0 {
				wo.ks.detachDestination(wo.ep)
				delete(wos, wo)
			} else if !ok {
				delete(wos, wo)
			}
		}
		length = len(wos)
	}
}

// For DSR it is required that we dont assign the VIP to any interface to avoid martian packets
// http://www.austintek.com/LVS/LVS-HOWTO/HOWTO/LVS-HOWTO.routing_to_VIP-less_director.html
// routeVIPTrafficToDirector: setups policy routing so that FWMARKed packets are deliverd locally
func routeVIPTrafficToDirector(h *iptables.IPTables, p netutils.Proto) (err error) {
	var out []byte

	inet := netutils.NewIP(p).ProtocolCmdParam().Inet

	fwMarkStr := fmt.Sprintf("0x%x/0x%x", fwMarkTag, fwMarkTag)

	if out, err = exec.Command("ip", inet, "rule", "list").Output(); err != nil {
		return errors.New("Failed to verify if `Ip rule` exists due to: " + err.Error())
	}

	output := string(out)
	if !strings.Contains(output, "fwmark "+fwMarkStr) {
		if err = exec.Command("ip", inet, "rule", "add", "prio", "32764", "fwmark", fwMarkStr, "table", ROUTE_TABLE_DSR).Run(); err != nil {
			return errors.New("Failed to add policy rule to lookup traffic to VIP through the custom " +
				" routing table due to " + err.Error())
		}
	}

	return nil
}

func fwmarkRuleFrom(ks *KubeService) (netutils.Proto, *netutils.IpTablesRuleType) {
	return netutils.NewIP(ks.Address).Protocol(),
		&netutils.IpTablesRuleType{"-d", ks.Address.String(), "-p", ks.Protocol.String(), "-m", ks.Protocol.String(),
			"--dport", fmt.Sprint(ks.Port), "-j", "MARK", "--set-mark", fmt.Sprintf("0x%x", ks.FWMark)}
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
	for _, so := range nsc.serviceMap {
		if !so.isFwMarkService() {
			continue
		}
		for _, ks := range *so.linkedServices[LINKED_SERVICE_EXTERNALIP] {
			fwmarkData = append(fwmarkData, ks)
		}
	}

	return fwmarkData
}

/* functions refactored using above wrapper. original  functions got "_" as prefix eg _deleteMasqueradeIptablesRule() */
func (nsc *NetworkServicesController) deleteMasqueradeIptablesRule() error {
	return nsc.ipm.BothTCPProtocolsWrapperNoArg(netutils.FunctionNoArgsType(nsc._deleteMasqueradeIptablesRule))
}

func (nsc *NetworkServicesController) deleteHairpinIptablesRules() error {
	return nsc.ipm.BothTCPProtocolsWrapperNoArg(netutils.FunctionNoArgsType(nsc._deleteHairpinIptablesRules))
}

func (nsc *NetworkServicesController) deleteFwmarkIptablesRules() error {
	return nsc.ipm.BothTCPProtocolsWrapperNoArg(netutils.FunctionNoArgsType(nsc._deleteFwmarkIptablesRules))
}

func CompareEndpointDestination(a, b *libipvs.Destination) bool {
	return a.Address.Equal(b.Address) && a.Port == b.Port
}

func DeepCompareDestination(a, b *libipvs.Destination) bool {
	return CompareEndpointDestination(a, b) && a.FwdMethod == b.FwdMethod
}

func CompareService(a, b *libipvs.Service) bool {
	if a.FWMark != 0 || b.FWMark != 0 {
		return a.FWMark == b.FWMark
	}
	return a.Address.Equal(b.Address) && a.Port == b.Port && a.Protocol == b.Protocol
}

func CompareKubeService(a, b *KubeService) bool {
	return CompareService(a.Service, b.Service)
}

func setupRouteTable() error {
	b, err := ioutil.ReadFile("/etc/iproute2/rt_tables")
	if err != nil {
		return errors.New("Failed to list kernel route tables: " + err.Error())
	}

	rts := string(b)
	toAdd := make([]*routeTableType, 0)
	for _, rt := range customRouteTables {
		if !strings.Contains(rts, rt.name) {
			toAdd = append(toAdd, &rt)
		}
	}
	if len(toAdd) == 0 {
		return nil
	}

	f, err := os.OpenFile("/etc/iproute2/rt_tables", os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("Failed to open kernel route table file for writing " + err.Error())
	}
	defer f.Close()

	for _, rt := range toAdd {
		if _, err = f.WriteString(rt.id + " " + rt.name + "\n"); err != nil {
			return errors.New("Failed add route table " + rt.name + ": " + err.Error())
		}
	}
	return nil
}

func setupCustomRouteTable(rt routeTableType) error {
	for _, inet := range [][]string{{"-4"}, {"-6"}} {
		args := append(inet, rt.forChecking.cmd...)
		out, err := exec.Command("ip", args...).Output()
		if err != nil {
			if err = setupRouteTable(); err == nil {
				out, err = exec.Command("ip", args...).Output()
			}
		}
		if err != nil {
			return errors.New("Failed to create " + rt.name + " route table: " + err.Error())
		}
		if !strings.Contains(string(out), rt.forChecking.output) {
			args = append(inet, rt.cmd...)
			if err = exec.Command("ip", args...).Run(); err != nil {
				return errors.New("Failed to run: " + strings.Join(args, " ") + ": " + err.Error())
			}
		}
	}
	return nil
}
