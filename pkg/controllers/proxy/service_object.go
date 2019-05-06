package proxy

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/cloudnativelabs/kube-router/pkg/utils/net-tools"
	"github.com/mqliang/libipvs"

	"github.com/golang/glog"
	"github.com/pkg/errors"
	"regexp"
)

func (nsc *NetworkServicesController) newServiceObject(oso *serviceObject) *serviceObject {
	var so = new(serviceObject)
	so.meta = oso.meta
	so.ksvc = &KubeService{Service: &libipvs.Service{}, ln: nsc.ln}
	so.linkedServices = make(linkedServiceListMapType)
	so.linkedServices.init()
	so.info = new(serviceInfo)
	so.endpoints = &endpointInfoMapType{}
	so.epLock = utils.NewChanLock()
	return so
}

func (so *serviceObject) getVIP() (addrs []*net.IPNet) {
	return []*net.IPNet{netutils.NewIP(so.ksvc.Address).ToIPNet()}
}

func (so *serviceObject) getNodeportIPs() (addrs []*net.IPNet) {
	var err error

	if !so.nsc.nodeportBindOnAllIp {
		addrs = []*net.IPNet{netutils.NewIP(so.nsc.nodeIP).ToIPNet()}
	} else if addrs, err = getAllLocalIPs(false, "dummy", "kube", "docker"); err != nil {
		glog.Errorf("Could not get list of system addresses for Ipvs services: %s", err.Error())
	}
	return
}

func (so *serviceObject) getExternalIPs() []*net.IPNet {
	extIPSet := so.info.ExternalIPs
	if !so.info.SkipLbIps {
		extIPSet = append(extIPSet, so.info.LoadBalancerIPs...)
	}
	return netutils.NewList(extIPSet)
}

func (so *serviceObject) deployNodePortService(old *kubeServiceArrayType, ip *net.IPNet) {
	so.linkService(old, ip, false, LINKED_SERVICE_NODEPORT)
}

func (so *serviceObject) deployCoreService(old *kubeServiceArrayType, ip *net.IPNet) {
	so.linkService(old, ip, false, LINKED_SERVICE_NOTLINKED)
}

func (so *serviceObject) deployExternalService(old *kubeServiceArrayType, ip *net.IPNet) {
	so.linkService(old, ip, so.isFwMarkService(), LINKED_SERVICE_EXTERNALIP)
}

func (so *serviceObject) deployLinkedService(deployF func(*kubeServiceArrayType, *net.IPNet), getIpF func() []*net.IPNet, lt linkedServiceType) {
	old := *so.linkedServices[lt]
	so.linkedServices.clear(lt)
	for _, ip := range getIpF() {
		deployF(&old, ip)
	}

	old.forEach(func(ks *KubeService) {
		if so.linkedServices[lt].isPresent(ks) == -1 {
			so.getEps().forEach(func(ep *endpointInfo) {
				ep.detach(ks, SYNCH_NOT_FOUND)
			})
		}
	})
}

func (eps *endpointInfoMapType) forEach(f func(*endpointInfo)) {
	for _, ep := range *eps {
		f(ep)
	}
}

func (eps *endpointInfoMapType) Size() int {
	return len(*eps)
}

func (eps *endpointInfoMapType) Add(ep *endpointInfo) (bool, *endpointInfo) {
	var id = generateId(ep)

	if (*eps)[id] != nil {
		currentEp := (*eps)[id]
		if currentEp.Weight != ep.Weight {
			currentEp.change = SYNCH_CHANGED
		} else {
			currentEp.change = SYNCH_NO_CHANGE
		}
		currentEp.Destination = ep.Destination
		return true, currentEp
	}

	ep.UsageLockType = &UsageLockType{used: make(map[infoMapsKeyType]bool), runOnNoReferences: func() {
		ep.so.destroy(ep)
	}}
	(*eps)[id] = ep
	(*eps)[id].hash = id

	return false, (*eps)[id]
}

func (so *serviceObject) updateIpvs(changed ...synchChangeType) {
	so.endpoints.forEach(func(ep *endpointInfo) {
		if ep.Weight == 0 {
			return
		}
		ch := ep.change.mergeChange(changed...)

		if ch.CheckFor(SYNCH_NEW) || ch.CheckFor(SYNCH_CHANGED) {
			so.iterateOver(ep.attach, ch)
		}

		if ch.CheckFor(SYNCH_NOT_FOUND) {
			so.iterateOver(ep.detach, ch)
		}
	})
}

func (so *serviceObject) hasActiveEndpoints() bool {
	return so.endpoints.Size() != 0
}

func (so *serviceObject) getEps() (eps *endpointInfoMapType) {
	return so.endpoints
}

func (so *serviceObject) deployService(chng ...synchChangeType) {
	var change = so.meta.change.mergeChange(chng...)

	if !so.hasActiveEndpoints() {
		return
	}

	if !change.CheckFor(SYNCH_CHANGED) && !change.CheckFor(SYNCH_NEW) && !change.CheckFor(SYNCH_NOT_FOUND) {
		return
	}

	so.deployLinkedService(so.deployCoreService, so.getVIP, LINKED_SERVICE_NOTLINKED)

	if so.info.Nodeport != 0 {
		so.deployLinkedService(so.deployNodePortService, so.getNodeportIPs, LINKED_SERVICE_NODEPORT)
	}

	// create IPVS service for the service to be exposed through the external IP's
	// For external IP (which are meant for ingress traffic) Kube-router setups IPVS services
	// based on FWMARK to enable Direct server return functionality. DSR requires a director
	// without a VIP http://www.austintek.com/LVS/LVS-HOWTO/HOWTO/LVS-HOWTO.routing_to_VIP-less_director.html
	// to avoid martian packets
	so.deployLinkedService(so.deployExternalService, so.getExternalIPs, LINKED_SERVICE_EXTERNALIP)
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

	if err = ksvc.deploy(create || so.meta.change.CheckFor(SYNCH_NEW)); err != nil {
		glog.Errorf("Create: %v, failed %s, Object: %v\nService Object:", err.Error(), so, old)
		return
	}

	so.linkedServices[lType].add(ksvc)

	if !utils.CheckForElementInArray(netutils.NewIP(ksvc.Address).ToIPNet(), so.getNodeportIPs()) {
		ksvc.updateLinkAddr(NL_ADDR_ADD, true)
	}
}

func (so *serviceObject) markEndpoints(withMark synchChangeType) {
	var toRemove = make([]*endpointInfo, 0)
	so.getEps().forEach(func(ep *endpointInfo) {
		if ep.Weight == 0 {
			return
		}
		if withMark == SYNCH_NOT_FOUND && ep.change.CheckFor(withMark) {
			toRemove = append(toRemove, ep)
			return
		}
		ep.change = withMark
	})

	so.epLock.Lock()
	for i := range toRemove {
		delete(*so.endpoints, toRemove[i].hash)
	}
	so.epLock.Unlock()
}

func (ep *endpointInfo) detach(ks *KubeService, update synchChangeType, fs ...postActionFunctionType) {
	if nil == ks.detachDestination(ep) {
		for _, f := range fs {
			f(ep, ks, NL_ADDR_REMOVE)
		}
	}
}

func (ep *endpointInfo) attach(ks *KubeService, update synchChangeType, fs ...postActionFunctionType) {
	if upd, err := ks.attachDestination(ep); err == nil && (!upd || ep.change.CheckFor(SYNCH_NEW)) {
		for _, f := range fs {
			f(ep, ks, NL_ADDR_ADD)
		}
		ep.Lock(ep.String(), ks.ipvsHash)
		ks.Lock(ks.String(), ep.hash)
	}
}

type postActionFunctionType func(*endpointInfo, *KubeService, epActionType)

func (so *serviceObject) prepareDsr(ep *endpointInfo, ks *KubeService, la epActionType) {
	if la != NL_ADDR_ADD || !so.isFwMarkService() {
		return
	}
	podObj, err := so.nsc.getPodObjectForEndpoint(ep.Address.String())
	if podObj == nil {
		err = errors.New("Failed to find endpoint with ip: " + ep.Address.String() + ". so skipping peparing endpoint for DSR")
		return
	}
	// we are only concerned with endpoint pod running on current node
	if err == nil && strings.Compare(podObj.Status.HostIP, so.nsc.nodeIP.String()) != 0 {
		return
	}

	var containerID = strings.TrimPrefix(podObj.Status.ContainerStatuses[0].ContainerID, "docker://")
	if err == nil && containerID == "" {
		err = errors.New("Failed to find container id for the endpoint with ip: " + ep.Address.String() + " so skipping peparing endpoint for DSR")
	}

	if err == nil {
		if err = ks.ln.prepareEndpointForDsr(containerID, ep.Address, ks.Address.String(), fmt.Sprint(ks.Port), fmt.Sprint(ep.Port), ks.Protocol.String()); err != nil {
			err = errors.Errorf("Failed to prepare endpoint %s to do direct server return due to %s", ep.Address.String(), err.Error())
		}
	}

	if err != nil {
		glog.Errorf(err.Error())
	}
}

func (so *serviceObject) destroy(ep *endpointInfo) {
	so.epLock.Lock()

	if ep.connTrack {
		ep.purgeConntrackRecords()
	}
	id := ep.hash
	(*so.endpoints)[id] = nil
	delete(*so.endpoints, id)
}

func (so *serviceObject) iterateOver(f func(*KubeService, synchChangeType, ...postActionFunctionType), update synchChangeType, fs ...postActionFunctionType) {
	allEndpointTypes.ForEach(func(lk linkedServiceType) {
		var fns = fs
		if lk == LINKED_SERVICE_EXTERNALIP {
			fns = append(fns, so.prepareDsr)
		}
		so.linkedServices[lk].forEach(func(ksvc *KubeService) {
			f(ksvc, update, fns...)
		})
	})
}

func (so *serviceObject) generateDestination(ip net.IP, port uint16) *libipvs.Destination {
	return &libipvs.Destination{
		Address:       ip,
		AddressFamily: libipvs.AddressFamily(netutils.NewIP(ip).Family()),
		Port:          port,
		Weight:        1,
	}
}

func (so *serviceObject) isDSR(dsrType ...libipvs.FwdMethod) bool {
	if so.info.DirectServerReturnMethod == nil {
		return false
	} else if len(dsrType) == 0 {
		return true
	}
	return *so.info.DirectServerReturnMethod&dsrType[0] == dsrType[0]
}

func (so *serviceObject) getDSR() libipvs.FwdMethod {
	if so.info.DirectServerReturnMethod == nil {
		return 0
	}
	return *so.info.DirectServerReturnMethod
}

func (so *serviceObject) isFwMarkService() bool {
	return so.isDSR(libipvs.IP_VS_CONN_F_TUNNEL)
}

func (so *serviceObject) setupRoutesForExternalIPForDSR(activeExternalIPs *map[string]bool, out ...map[string]*[]byte) {
	if !so.isDSR() {
		return
	}

	for _, eip := range so.getExternalIPs() {
		eipStr := eip.IP.String()

		if activeExternalIPs != nil {
			(*activeExternalIPs)[eipStr] = true
		}

		var inet = netutils.NewIP(eip).ProtocolCmdParam().Inet
		if len(out) > 0 {
			if _, ok := out[0][inet]; ok && bytes.ContainsAny(*out[0][inet], eipStr) {
				continue
			}
		}

		if out, err := exec.Command(utils.GetPath("ip"), inet, "route", "replace", eipStr, "dev", "kube-bridge", "table",
			ROUTE_TABLE_EXTERNAL).CombinedOutput(); err != nil {
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
