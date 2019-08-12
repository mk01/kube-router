package proxy

import (
	"bytes"
	"fmt"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/hostnet"
	"github.com/mqliang/libipvs"
	"net"
	"os/exec"

	"github.com/cloudnativelabs/kube-router/pkg/helpers/tools"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/golang/glog"
	"github.com/google/go-cmp/cmp"
	"regexp"
)

func (nsc *NetworkServicesController) newServiceObject(oso *serviceObject) *serviceObject {
	var so = new(serviceObject)
	so.meta = oso.meta
	so.ksvc = &KubeService{Service: &libipvs.Service{}, ln: nsc.ln, so: so}
	so.linkedServices = make(linkedServiceListMapType)
	so.linkedServices.init()
	so.info = new(serviceInfo)
	so.endpoints = make(endpointInfoMapType)
	return so
}

func (so *serviceObject) getEmptyIPs() (addrs []*net.IPNet) {
	return nil
}

func (so *serviceObject) getVIP() (addrs []*net.IPNet) {
	return []*net.IPNet{hostnet.NewIP(so.ksvc.Address).ToIPNet()}
}

func (so *serviceObject) getNodeportIPs() (addrs []*net.IPNet) {
	var err error

	if !so.nsc.nodeportBindOnAllIp {
		addrs = []*net.IPNet{so.nsc.ln.GetNodeIP()}
	} else if addrs, err = hostnet.GetAllLocalIPs(hostnet.ExcludePattern, "dummy", "kube", "docker"); err != nil {
		glog.Errorf("Could not get list of system addresses for Ipvs services: %s", err.Error())
	}
	return
}

func (so *serviceObject) getExternalIPs() []*net.IPNet {
	extIPSet := so.info.ExternalIPs
	if !so.info.SkipLbIps {
		extIPSet = append(extIPSet, so.info.LoadBalancerIPs...)
	}
	return hostnet.NewIPNetList(extIPSet)
}

func (so *serviceObject) deployNodePortService(old *kubeServiceArrayType, ip *net.IPNet) {
	so.linkService(old, ip, false, LinkedServiceNodeport)
}

func (so *serviceObject) deployCoreService(old *kubeServiceArrayType, ip *net.IPNet) {
	so.linkService(old, ip, false, LinkedServiceNotlinked)
}

func (so *serviceObject) deployExternalService(old *kubeServiceArrayType, ip *net.IPNet) {
	so.linkService(old, ip, so.isFwMarkService(), LinkedServiceExternalip)
}

func (so *serviceObject) deployLinkedService(deployF func(*kubeServiceArrayType, *net.IPNet), getIpF func() []*net.IPNet, lt linkedServiceType) {
	old := *so.linkedServices[lt]
	so.linkedServices.clear(lt)
	for _, ip := range getIpF() {
		deployF(&old, ip)
	}

	old.forEach(func(ks *KubeService) {
		if so.linkedServices[lt].isPresent(ks) == -1 {
			so.forEachEndpoint(func(ep *endpointInfo) error {
				return ep.detach(ks, SynchNotFound)
			})
		}
	})
}

func (so *serviceObject) forEachEndpoint(f func(*endpointInfo) error) (err error) {
	so.epLock.Lock()
	defer so.epLock.Unlock()
	return so.GetEps().forEach(f)
}

func (eps endpointInfoMapType) forEach(f func(*endpointInfo) error) (err error) {
	for _, ep := range eps {
		if err = f(ep); err != nil {
			err = fmt.Errorf("error traversing endpoints %s", err.Error())
			return
		}
	}
	return
}

func (eps endpointInfoMapType) Size() int {
	return len(eps)
}

func (eps endpointInfoMapType) SizeActive() int {
	size := 0
	eps.forEach(func(ep *endpointInfo) error {
		if ep.Weight != 0 {
			size++
		}
		return nil
	})
	return size
}

func (eps endpointInfoMapType) Add(ep *endpointInfo) (bool, *endpointInfo) {
	var id = generateId(ep)

	defer ep.so.activateHealthCkeck(&ep.so.nsc.lbHealthChecks)

	if eps[id] != nil {
		currentEp := eps[id]
		if !cmp.Equal(currentEp, ep, DeepMatchEndpoint) {
			currentEp.change = SynchChanged
		} else {
			currentEp.change = ep.so.meta.change
		}
		currentEp.Destination = ep.Destination
		return true, currentEp
	}

	ep.UsageLockType = &UsageLockType{used: make(map[infoMapsKeyType]bool), gc: func() {
		glog.V(3).Infof("GC called on %s", ep.String(3))
		so := ep.so
		so.deactivateEndpoint(ep)
		so.deactivateHealthCkeck(&so.nsc.lbHealthChecks)
	}}

	eps[id] = ep
	eps[id].hash = id

	return false, eps[id]
}

func (so *serviceObject) refreshEndpoints(changed ...synchChangeType) {
	so.forEachEndpoint(func(ep *endpointInfo) (err error) {
		if ep.Weight == 0 {
			return
		}
		ch := ep.change.add(changed...)

		if ch.CheckFor(SynchNotFound) {
			glog.V(3).Infoln("Indicated EP for deletion, diving in: ", ep.String(3))
			so.forAllEndpointTypes(ep.detach, ch)
		} else if ep.change.CheckFor(SynchNew) || ep.change.CheckFor(SynchChanged) ||
			so.meta.change.CheckFor(SynchChanged) {

			glog.V(3).Infoln("Indicated new/changed EP, diving in: ", ep.String(3))
			so.forAllEndpointTypes(ep.attach, ch)
		}
		return
	})
}

func (so *serviceObject) hasEndpoints() bool {
	return so.GetEps().Size() != 0
}

func (so *serviceObject) hasLocalEndepoints() bool {
	noerror := fmt.Errorf("")
	return nil != so.GetEps().forEach(func(info *endpointInfo) error {
		if info.isLocal == false {
			return nil
		}
		return noerror
	})
}

func (so *serviceObject) GetEps() (eps endpointInfoMapType) {
	return so.endpoints
}

func (so *serviceObject) activate(chng ...synchChangeType) {
	var change = so.meta.change.add(chng...)

	if !so.hasEndpoints() || change & ^SynchNoChange == 0 {
		return
	}

	so.deployLinkedService(so.deployCoreService, so.getVIP, LinkedServiceNotlinked)

	if so.info.Nodeport != 0 {
		so.deployLinkedService(so.deployNodePortService, so.getNodeportIPs, LinkedServiceNodeport)
	} else {
		so.deployLinkedService(so.deployNodePortService, so.getEmptyIPs, LinkedServiceNodeport)
	}

	// create IPVS service for the service to be exposed through the external IP's
	// For external IP (which are meant for ingress traffic) Kube-router setups IPVS services
	// based on FWMARK to enable Direct server return functionality. DSR requires a director
	// without a VIP http://www.austintek.com/LVS/LVS-HOWTO/HOWTO/LVS-HOWTO.routing_to_VIP-less_director.html
	// to avoid martian packets
	so.deployLinkedService(so.deployExternalService, so.getExternalIPs, LinkedServiceExternalip)
	so.setupRoutesForExternalIPForDSR(nil)
}

func (so *serviceObject) linkService(old *kubeServiceArrayType, ip *net.IPNet, isFWMark bool, lType linkedServiceType) {
	var ksvc *KubeService
	var err error
	var create = true

	newksvc := so.ksvc.clone(ip, isFWMark, lType, so)
	if i := old.isPresent(newksvc); i != -1 {
		ksvc = (*old)[i]
		ksvc.Service = newksvc.Service

		create = false
	} else {
		ksvc = newksvc
	}

	if err = ksvc.deploy(create || so.meta.change.CheckFor(SynchNew)); err != nil {
		glog.Errorf("Create: %v, failed %s, Object: %v\nService Object:", err.Error(), so, old)
		return
	}

	so.linkedServices[lType].add(ksvc)

	if lType != LinkedServiceNodeport {
		ksvc.updateLinkAddr(NL_ADDR_ADD, true)
	}
}

func (so *serviceObject) markEndpoints(withMark synchChangeType) {
	//so.epLock.Lock()
	//defer so.epLock.Unlock()

	//var toRemove = make([]*endpointInfo, 0)

	so.forEachEndpoint(func(ep *endpointInfo) (err error) {
		if ep.Weight == 0 {
			return
		}
		if withMark == SynchNotFound && ep.change.CheckFor(withMark) {
			//toRemove = append(toRemove, ep)
			delete(so.endpoints, ep.hash)
			return
		}
		ep.change = withMark
		return
	})

	//for i := range toRemove {
	//	delete(so.endpoints, toRemove[i].hash)
	//}
}

func (ep *endpointInfo) detach(ks *KubeService, update synchChangeType, fs ...postActionFunctionType) (err error) {
	if err = ks.detachDestination(ep); err != nil {
		return
	}

	for _, f := range fs {
		f(ep, ks, NL_ADDR_REMOVE)
	}
	return
}

func (ep *endpointInfo) attach(ks *KubeService, update synchChangeType, fs ...postActionFunctionType) (err error) {
	var upd bool

	if upd, err = ks.attachDestination(ep); err == nil && (!upd || ep.so.meta.change.CheckFor(SynchNew)) && ep.change.CheckFor(SynchNew) {
		ep.Lock(ks.getHash())
		ks.Lock(ep.hash)

	} else if err != nil {
		return
	}

	for _, f := range fs {
		f(ep, ks, NL_ADDR_ADD)
	}
	return
}

func (so *serviceObject) prepareDsr(ep *endpointInfo, ks *KubeService, la epActionType) {
	if la != NL_ADDR_ADD || !ep.isLocal || ep.change.CheckFor(SynchNoChange) || !so.isDSR() {
		glog.V(2).Infof("Endpoint %s - not preparing for DSR", ep.String(2))
		return
	}

	var containerPID int
	var err error
	defer func() {
		if containerPID != 0 && ks.Port != ep.Port {
			ks.ln.prepareEndpointForDsrNat(containerPID, ep.Address, ks.Address.String(), fmt.Sprint(ks.Port), fmt.Sprint(ep.Port), ks.Protocol.String())
		}
	}()

	if containerPID, err = so.nsc.ln.getDockerPid(ep.containerID); err != nil {
		err = tools.AppendErrorf(err, "Can't get container pid")
	}

	if err == nil && containerPID == 0 {
		err = tools.NewErrorf("Failed to find container id/pid for the endpoint with ip: %s so skipping peparing endpoint for DSR", ep.Address.String())
	}

	if err == nil && so.nsc.configuredDsrContainers[ep.containerID] {
		glog.V(2).Infof("Endpoint %s - already prepared for DSR with address %s", ep.String(2), ks.Address.String())
		return
	}

	if err == nil && so.ksvc.isTunnelService() {
		err = ks.ln.prepareEndpointForDsrTunnel(containerPID, ep.Address, ks.Address.String(), fmt.Sprint(ks.Port), fmt.Sprint(ep.Port), ks.Protocol.String())
	}

	if err == nil {
		err = ks.ln.prepareEndpointForDsr(containerPID, ep.Address, ks.Address.String(), fmt.Sprint(ks.Port), fmt.Sprint(ep.Port), ks.Protocol.String(), so.ksvc.isTunnelService())
	}

	if err == nil {
		so.nsc.configuredDsrContainers[ep.containerID] = true
	} else {
		glog.Error(err.Error())
	}
}

func (so *serviceObject) deactivateEndpoint(ep *endpointInfo) int {
	so.epLock.Lock()

	if ep.connTrack {
		ep.purgeConntrackRecords()
	}
	id := ep.hash
	so.endpoints[id] = nil
	delete(so.endpoints, id)
	return so.endpoints.Size()
}

func (so *serviceObject) forAllEndpointTypes(f endpointInfoActionType, update synchChangeType, fs ...postActionFunctionType) (errOut error) {
	allServicesTypes.ForEach(func(lk linkedServiceType) {
		if lk == LinkedServiceExternalip {
			fs = append(fs, so.prepareDsr)
		}
		so.linkedServices[lk].forEach(func(ksvc *KubeService) {
			if err := f(ksvc, update, fs...); err != nil {
				errOut = tools.AppendErrorf(errOut, "error updating endpoint %s", err.Error())
				return
			}
		})
	})
	return
}

func (so *serviceObject) generateDestination(ip net.IP, port uint16) *libipvs.Destination {
	return &libipvs.Destination{
		Address:       ip,
		AddressFamily: libipvs.AddressFamily(hostnet.NewIP(ip).Family()),
		Port:          port,
		Weight:        1,
		FwdMethod:     so.getDSR(),
	}
}

func (so *serviceObject) isDSR(dsrType ...libipvs.FwdMethod) bool {
	if len(dsrType) == 0 {
		return so.getDSR() != 0
	}
	return so.getDSR() == dsrType[0]
}

func (so *serviceObject) getDSR() libipvs.FwdMethod {
	if so == nil {
		return libipvs.IP_VS_CONN_F_MASQ
	}
	return so.info.DirectServerReturnMethod & libipvs.IP_VS_CONN_F_FWD_MASK
}

func (so *serviceObject) isFwMarkService() bool {
	return so.isDSR(libipvs.IP_VS_CONN_F_TUNNEL)
}

func (so *serviceObject) setupRoutesForExternalIPForDSR(activeExternalIPs *map[string][]string, out ...map[string]*[]byte) {
	if !so.isDSR() {
		return
	}

	var metricDelete = make([]string, 2)
	metricDelete[0] = "metric"

	for _, eip := range so.getExternalIPs() {
		eipStr := eip.IP.String()

		var inet = hostnet.NewIP(eip).ProtocolCmdParam().Inet
		if len(out) > 0 {
			if _, ok := out[0][inet]; ok && bytes.ContainsAny(*out[0][inet], eipStr) {
				continue
			}
		}

		var nexthops []string
		var rCmd = []string{inet, "route", "replace", eipStr, "table", RouteTableExternal}
		if so.getDSR() == libipvs.IP_VS_CONN_F_DROUTE {
			for _, via := range so.GetEps() {
				if via.isLocal && via.Weight != 0 {
					nexthops = append(nexthops, "nexthop", "via", via.Address.String(), "dev", options.KUBE_BRIDGE_IF)
				}
			}
		}
		if len(nexthops) > 0 {
			rCmd = append(rCmd, "metric", "2048")
			rCmd = append(rCmd, nexthops...)
			metricDelete[1] = "1024"
		} else {
			rCmd = append(rCmd, "metric", "1024", "dev", options.KUBE_BRIDGE_IF)
			metricDelete[1] = "2048"
		}

		if activeExternalIPs != nil {
			(*activeExternalIPs)[eipStr] = metricDelete
		}

		if out, err := exec.Command(tools.GetExecPath("ip"), rCmd...).CombinedOutput(); err != nil {
			glog.Error("Running command failed: " + string(out) + "\nAdding " + eipStr + " to custom route table for external IP's failed due to: " + err.Error())
			continue
		}
	}
}

func (ep *endpointInfo) purgeConntrackRecords() {
	var out []byte
	var err error
	// Conntrack exits with non zero exit code when exiting if 0 flow entries have been deleted, use regex to check output and don't Error when matching
	re := regexp.MustCompile("([[:space:]]0 flow entries have been deleted.)")
	if out, err = exec.Command("conntrack", "-D", "--orig-dst", ep.Address.String(), "-p", "udp", "--dport", fmt.Sprint(ep.Port)).CombinedOutput(); err == nil {
		glog.V(1).Infof("Deleted conntrack entry for endpoint: " + ep.Address.String() + ":" + fmt.Sprint(ep.Port))
		return
	}

	if matched := re.MatchString(string(out)); !matched {
		glog.Error("Failed to delete conntrack entry for endpoint: " + ep.Address.String() + ":" + fmt.Sprint(ep.Port) + " due to " + err.Error())
	}
}
