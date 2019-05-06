package netpol

import (
	"errors"
	"fmt"
	"k8s.io/apimachinery/pkg/util/intstr"
	"net"
	"sync"
	"time"

	"github.com/cloudnativelabs/kube-router/pkg/controllers"
	"github.com/cloudnativelabs/kube-router/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/cloudnativelabs/kube-router/pkg/utils/net-tools"
	"github.com/golang/glog"
	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
	api "k8s.io/api/core/v1"
	apiextensions "k8s.io/api/extensions/v1beta1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"regexp"
	"strconv"
	"strings"
)

type kubePolPrefixType string

const (
	networkPolicyAnnotation                        = "net.beta.kubernetes.io/network-policy"
	kubeNodesIpSet                                 = "KUBE-NPC-NODESIP-LIST"
	kubeForwardRejectIpSet                         = "KUBE-NPC-REJECT-LIST"
	kubePodInChainPrefix         kubePolPrefixType = "KUBE-PODIN-"
	kubePodOutChainPrefix        kubePolPrefixType = "KUBE-PODOUT-"
	kubeNetworkPolicyChainPrefix kubePolPrefixType = "KUBE-NWPLCY-"
	kubeTargetIpSetPrefix        kubePolPrefixType = "KUBE-TGT-"
	kubeIpTargetIpSetPrefix      kubePolPrefixType = "KUBE-TGTP-"
	kubeNetTargetIpSetPrefix     kubePolPrefixType = "KUBE-TGTB-"
	kubeForwardPreprocessChain   kubePolPrefixType = "KUBE-NPC-FORWARD"
	kubeOutputPreprocessChain    kubePolPrefixType = "KUBE-NPC-OUTPUT"
	kubeInputPreprocessChain     kubePolPrefixType = "KUBE-NPC-INPUT"

	kubeICMPIpSet = "KUBE-NPC-ICMP"
)

var (
	CONTROLLER_NAME        = []string{"Policy controller", "NPC"}
	kubeCleanupChainPrefix = []string{"KUBE-POD-FW-", "KUBE-POD-OUT-", "KUBE-POD-IN-"}
	kubeCleanupIpSetPrefix = []string{"KUBE-DST-", "KUBE-SRC-", kubeForwardRejectIpSet, "KUBE-TGTI"}

	icmpIpSetSource = []string{"0.0.0.0/1,icmp:ping", "128.0.0.0/1,icmp:ping", "::/1,icmpv6:ping", "8000::/1,icmpv6:ping"}
)

// Network policy controller provides both ingress and egress filtering for the pods as per the defined network
// policies. Two different types of iptables chains are used. Each pod running on the node which either
// requires ingress or egress filtering gets a pod specific chains. Each network policy has a iptables chain, which
// has rules expressed through ipsets matching source and destination pod ip's. In the FORWARD chain of the
// filter table a rule is added to jump the traffic originating (in case of egress network policy) from the pod
// or destined (in case of ingress network policy) to the pod specific iptables chain. Each
// pod specific iptables chain has rules to jump to the network polices chains, that pod matches. So packet
// originating/destined from/to pod goes through fitler table's, FORWARD chain, followed by pod specific chain,
// followed by one or more network policy chains, till there is a match which will accept the packet, or gets
// dropped by the rule in the pod chain, if there is no match.

// NetworkPolicyController strcut to hold information required by NetworkPolicyController
type NetworkPolicyController struct {
	nodeIP          net.IP
	nodeHostName    string
	mu              *utils.ChannelLockType
	syncPeriod      time.Duration
	MetricsEnabled  bool
	v1NetworkPolicy bool
	readyForUpdates bool
	clientset       kubernetes.Interface

	// list of all active network policies expressed as networkPolicyInfo
	networkPoliciesInfo *networkPolicyInfoListType
	ipSetHandler        *netutils.IPSet

	podLister cache.Indexer
	npLister  cache.Indexer
	nsLister  cache.Indexer
	epLister  cache.Indexer
	svcLister cache.Indexer

	PodEventHandler           cache.ResourceEventHandler
	NamespaceEventHandler     cache.ResourceEventHandler
	NetworkPolicyEventHandler cache.ResourceEventHandler

	Ipm      *netutils.IpTablesManager
	cfgCheck *utils.ConfigCheckType
}

type networkPolicyInfoListType map[string]*networkPolicyInfo

var data keyMetrics

var timer *time.Timer
var afterPickupOnce *sync.Once
var updatesQueue chan *utils.ApiTransaction

func init() {
	timer = nil
	updatesQueue = make(chan *utils.ApiTransaction, 25)
	afterPickupOnce = &sync.Once{}
}

func (npc *NetworkPolicyController) GetData() ([]string, time.Duration) {
	return CONTROLLER_NAME, npc.syncPeriod
}

// Run runs forver till we receive notification on stopCh
func (npc *NetworkPolicyController) Run(healthChan chan *controllers.ControllerHeartbeat, stopCh <-chan struct{}, wg *sync.WaitGroup) error {
	t := time.NewTicker(npc.syncPeriod)
	obsoleteResourceCleanupOnce := &sync.Once{}
	defer t.Stop()
	defer wg.Done()

	npc.cfgCheck = utils.GetConfigChecker()
	npc.cfgCheck.Register(npc, utils.ConfigCheck{utils.GetPath("ip6tables"), []string{"-t", "filter", "-S", "-w"}})
	npc.cfgCheck.Register(npc, utils.ConfigCheck{utils.GetPath("iptables"), []string{"-t", "filter", "-S", "-w"}})

	glog.Info("Starting network policy controller")

	// loop forever till notified to stop on stopCh
	for {
		select {
		case <-stopCh:
			glog.Info("Shutting down network policies controller")
			return nil
		default:
		}

		glog.V(1).Info("Performing periodic sync of iptables to reflect network policies")
		err := npc.Sync()
		if err != nil {
			glog.Errorf("Error during periodic sync of network policies in network policy controller. Error: " + err.Error())
			glog.Errorf("Skipping sending heartbeat from network policy controller as periodic sync failed.")
		} else {
			dataCopy := data
			healthcheck.SendHeartBeat(healthChan, npc, dataCopy)
		}

		// Run obsolete resources cleanup after first full sync, not at the start. Those resources
		// can be used by others until sync runs with new setting
		obsoleteResourceCleanupOnce.Do(func() {
			npc.cleanupObsoleteResources(kubeCleanupIpSetPrefix, kubeCleanupChainPrefix)
		})

		npc.readyForUpdates = true
		select {
		case <-stopCh:
			glog.Infof("Shutting down network policies controller")
			return nil
		case <-t.C:
		}
	}
	return nil
}

// OnPodUpdate handles updates to pods from the Kubernetes api server
func (npc *NetworkPolicyController) OnPodUpdate(obj interface{}) {
	if npc.updatePreChecks(obj) != nil {
		npc.queueUpdate(obj)
	}
}

// For now just don't run anything. all stuff needs to be present until services controller
// doesn't tear down pod/service properly (with reroute, grace period etc)
func (npc *NetworkPolicyController) OnPodDelete(obj interface{}) {
}

func (npc *NetworkPolicyController) updatePreChecks(obj interface{}) (pod *api.Pod) {
	pod = obj.(*api.Pod)
	glog.V(2).Infof("Received update to pod: %s/%s", pod.Namespace, pod.Name)

	if !npc.readyForUpdates {
		glog.V(3).Infof("Skipping update to pod: %s/%s, controller still performing bootup full-sync", pod.Namespace, pod.Name)
		return nil
	}
	return
}

// OnNetworkPolicyUpdate handles updates to network policy from the kubernetes api server
func (npc *NetworkPolicyController) OnNetworkPolicyUpdate(obj interface{}) {
	netpol := obj.(*networking.NetworkPolicy)
	glog.V(2).Infof("Received update for network policy: %s/%s", netpol.Namespace, netpol.Name)

	if !npc.readyForUpdates {
		glog.V(3).Infof("Skipping update to network policy: %s/%s, controller still performing bootup full-sync", netpol.Namespace, netpol.Name)
		return
	}

	npc.queueUpdate(obj)
}

// OnNamespaceUpdate handles updates to namespace from kubernetes api server
func (npc *NetworkPolicyController) OnNamespaceUpdate(obj interface{}) {
	namespace := obj.(*api.Namespace)
	// namespace (and annotations on it) has no significance in GA ver of network policy
	if npc.v1NetworkPolicy {
		return
	}
	glog.V(2).Infof("Received update for namespace: %s", namespace.Name)

	npc.queueUpdate(obj)
}

func (npc *NetworkPolicyController) queueUpdate(obj interface{}) {
	afterPickupOnce.Do(func() {
		npc.mu.Lock()
		timer = time.AfterFunc(250*time.Millisecond, npc.pickupQueue)
	})
	updatesQueue <- &utils.ApiTransaction{New: obj}
}

func (npc *NetworkPolicyController) pickupQueue() {

	start := time.Now()
	defer npc.mu.Unlock()

	dummyRecordSet := activeRecordSets{}.New()

	updatePolicies := &networkPolicyInfoListType{}
	var updatedPods []interface{}
	var updatedNamespaces []interface{}

	for {
		select {
		case upd := <-updatesQueue:
			switch updTyped := upd.New.(type) {
			case *api.Pod:
				updatedPods = append(updatedPods, podInfo{}.fromApi(updTyped))

			case *networking.NetworkPolicy:
				updatePolicies.Add(npc.buildSinglePolicyInfo(updTyped))

			case *api.Namespace:
				updatedNamespaces = append(updatedNamespaces, updTyped)

			default:
			}

		default:
			afterPickupOnce = &sync.Once{}

			if len(updatedPods) > 0 {
				npc.networkPoliciesInfo.ForEach(func(p *networkPolicyInfo) {
					p.targetPods = npc.ListPodInfoByNamespaceAndLabels(p.meta.namespace, p.meta.labels.AsSelector())
					p.parsePolicy(p.meta.source, npc.evalPodPeer)

					npc.findAffectedPolicies(p, updatePolicies, updatedPods)
					npc.findAffectedPolicies(p, updatePolicies, updatedNamespaces)
				})
			}

			updatePolicies.ForEach(func(p *networkPolicyInfo) {
				npc.syncSingleNetworkPolicyChain(p, dummyRecordSet, dummyRecordSet)
			})

			npc.syncPodFirewallChains(updatePolicies)
			glog.V(0).Infof("Transaction sync policy controller took %v", time.Since(start))

			npc.cfgCheck.ForceNextRun(npc)
			return
		}
	}
}

func (npc *NetworkPolicyController) findAffectedPolicies(p *networkPolicyInfo, plcs *networkPolicyInfoListType, slice []interface{}) {
	for _, obj := range slice {
		switch typed := obj.(type) {
		case *api.Namespace:
			if p.checkNamespace(typed) {
				plcs.Add(p)
			}
		case *podInfo:
			if p.checkPod(typed) {
				plcs.Add(p)
			}
		}
	}
}

// Sync synchronizes iptables to desired state of network policies
func (npc *NetworkPolicyController) Sync() (err error) {

	npc.mu.Lock()
	start := time.Now()

	defer func() {
		npc.mu.Unlock()
		endTime := time.Since(start)
		glog.V(0).Infof("Sync policy controller took %v", endTime)
		if npc.MetricsEnabled {
			metrics.ControllerIptablesSyncTime.Observe(endTime.Seconds())
		}
		data.lastSync = endTime
	}()

	if !npc.cfgCheck.GetCheckResult(npc) {
		return
	}

	data = keyMetrics{pods: len(npc.podLister.List())}

	if err = npc.rebuildPolicyInfo(); err != nil {
		return err
	}

	if err = npc.syncNodesIPSet(); err != nil {
		return errors.New("Aborting sync. Failed to sync cluster nodes ipset: " + err.Error())
	}

	activePolicyChains, activePolicyIpSets, err := npc.syncNetworkPolicyChains()
	if err != nil {
		return errors.New("Aborting sync. Failed to sync network policy chains: " + err.Error())
	}

	err = npc.addExtraSets(activePolicyIpSets)
	if err != nil {
		return errors.New("Aborting sync. Failed to sync extra sets: " + err.Error())
	}

	activePodInChains, activePodOutChains, err := npc.syncPodFirewallChains()
	if err != nil {
		return errors.New("Aborting sync. Failed to sync pod firewalls: " + err.Error())
	}

	data.ipsets = activePolicyIpSets.Size()
	data.chains = activePolicyChains.Size() + activePodInChains.Size() + activePodOutChains.Size()

	err = npc.cleanupStaleRules(activePolicyChains, activePodInChains, activePodOutChains, activePolicyIpSets)
	if err != nil {
		return errors.New("Aborting sync. Failed to cleanup stale iptables rules: " + err.Error())
	}

	return nil
}

func (npc *NetworkPolicyController) addExtraSets(activePolicyIpSets *activeRecordSets) (err error) {
	icmpIpSet, _ := npc.ipSetHandler.GetOrCreate(kubeICMPIpSet, netutils.TypeHashNetPort)
	for _, option := range icmpIpSetSource {
		if _, err = icmpIpSet.Add(option); err != nil {
			return err
		}
	}

	activePolicyIpSets.Add(kubeICMPIpSet)
	return
}

func (npc *NetworkPolicyController) rebuildPolicyInfo() (err error) {
	if npc.v1NetworkPolicy {
		npc.networkPoliciesInfo, err = npc.buildNetworkPoliciesInfo()
		if err != nil {
			return errors.New("Aborting sync. Failed to build network policies: " + err.Error())
		}
	} else {
		// TODO remove the Beta support
		npc.networkPoliciesInfo, err = npc.buildBetaNetworkPoliciesInfo()
		if err != nil {
			return errors.New("Aborting sync. Failed to build network policies: " + err.Error())
		}
	}
	return
}

// Configure iptables rules representing each network policy. All pod's matched by
// network policy spec podselector labels are grouped together in one ipset which
// is used for matching destination ip address. Each ingress rule in the network
// policyspec is evaluated to set of matching pods, which are grouped into a
// ipset used for source ip addr matching.
func (npc *NetworkPolicyController) syncNetworkPolicyChains() (*activeRecordSets, *activeRecordSets, error) {
	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		glog.V(0).Infof("Syncing network policy chains took %v", endTime)
	}()

	var err error
	var activePolicyChains = activeRecordSets{}.New()
	var activePolicyIpSets = activeRecordSets{}.New()

	// run through all network policies
	npc.networkPoliciesInfo.ForEach(func(policy *networkPolicyInfo) {
		if err = npc.syncSingleNetworkPolicyChain(policy, activePolicyIpSets, activePolicyChains); err != nil {
			return
		}
	})

	if err != nil {
		return nil, nil, err
	}

	glog.V(2).Infof("Iptables chains in the filter table are synchronized with the network policies.")

	data.policies += npc.networkPoliciesInfo.Size()
	return activePolicyChains, activePolicyIpSets, nil
}

func (npc *NetworkPolicyController) syncSingleNetworkPolicyChain(policy *networkPolicyInfo, activePolicyIpSets,
	activePolicyChains *activeRecordSets) (err error) {

	targetPodIpSetName := kubeTargetIpSetPrefix.GetFromMeta(policy.meta)

	// create an ipset for all targets pod matched by the policy spec PodSelector
	// if not exists yet (many policies can have same PodSelector)
	if !activePolicyIpSets.Contains(targetPodIpSetName) {

		targetPodIpSet, err := npc.ipSetHandler.Create(targetPodIpSetName, netutils.TypeHashIP, netutils.OptionTimeout, "0")
		if err != nil {
			return fmt.Errorf("failed to create ipset: %s", err.Error())
		}

		activePolicyIpSets.Add(targetPodIpSetName)

		currentPodIps := make([]*net.IPNet, 0)
		policy.targetPods.ForEach(func(pod *podInfo) {
			currentPodIps = append(currentPodIps, pod.ip...)
		})

		targetPodIpSet.RefreshAsync(currentPodIps)
	}

	err = npc.processRules(policy, activePolicyChains, activePolicyIpSets)
	return
}

func (npc *NetworkPolicyController) processRules(policy *networkPolicyInfo, activePolicyChains, activePolicyIpSets *activeRecordSets) (err error) {

	// run through all the ingress rules in the spec and create iptables rules
	// in the chain for the network policy
	err = policy.ingressRules.processPolicyRules(policy, &policy.ingressRules, npc.ipSetHandler,
		activePolicyChains, activePolicyIpSets, npc.Ipm)
	// run through all the egress rules in the spec and create iptables rules
	// in the chain for the network policy
	if err == nil {
		err = policy.egressRules.processPolicyRules(policy, &policy.egressRules, npc.ipSetHandler,
			activePolicyChains, activePolicyIpSets, npc.Ipm)
	}
	return
}

type templateType string

const (
	RULE_TEMPLATE_POD           templateType = "pod"
	RULE_TEMPLATE_IPBLOCK                    = "ipblock"
	RULE_TEMPLATE_MATCHALLPEERS              = ""
)

type ruleTemplate struct {
	comment []string
	rule    []string
}

var ipSetDirection = [][]string{{"dst", "from"}, {"src", "to"}}

func getTemplate(rt templateType, meta *networkPolicyMetadata, generated string, directionOffset int) *[]string {
	var tmpl *ruleTemplate

	switch rt {
	case RULE_TEMPLATE_POD:
		tmpl = &(ruleTemplate{
			comment: []string{"-m", "comment", "--comment",
				"ACCEPT traffic " + ipSetDirection[directionOffset][1] + " pods, " + meta.String()},
			rule: []string{"-m", "set", "--match-set", generated, ipSetDirection[(directionOffset+1)%2][0], "-j", "ACCEPT"},
		})
	case RULE_TEMPLATE_IPBLOCK:
		tmpl = &(ruleTemplate{
			comment: []string{"-m", "comment", "--comment",
				"ACCEPT traffic " + ipSetDirection[directionOffset][1] + " ipBlocks, " + meta.String()},
			rule: []string{"-m", "set", "--match-set", generated, ipSetDirection[(directionOffset+1)%2][0], "-j", "ACCEPT"},
		})
	case RULE_TEMPLATE_MATCHALLPEERS:
		tmpl = &(ruleTemplate{
			comment: []string{"-m", "comment", "--comment",
				"ACCEPT traffic " + ipSetDirection[directionOffset][1] + " any, " + meta.String()},
			rule: []string{"-j", "ACCEPT"},
		})
	}
	var out = tmpl.rule
	out = append(out, tmpl.comment...)
	return &out
}

func (pr *policyRuleIngress) getTemplate(rt templateType, meta *networkPolicyMetadata, generated string) *[]string {
	return getTemplate(rt, meta, generated, 0)
}

func (pr *policyRuleEgress) getTemplate(rt templateType, meta *networkPolicyMetadata, generated string) *[]string {
	return getTemplate(rt, meta, generated, 1)
}

func (prl *networkPolicyListType) processPolicyRules(policy *networkPolicyInfo, policyRule policyRuleType, ipSetHandler *netutils.IPSet,
	activePolicyChains, activePolicyIpSets *activeRecordSets, ipm *netutils.IpTablesManager) (err error) {

	rules := &netutils.IpTablesRuleListType{}
	for _, rule := range prl.rules {
		if err = rule.buildFwRules(policy.meta, policyRule, ipSetHandler, activePolicyIpSets, rules); err != nil {
			return
		}
	}

	if len(*rules) == 0 {
		return
	}

	chainName := kubeNetworkPolicyChainPrefix.Get(policy.meta.namespace, policy.meta.name, policyRule.String())
	activePolicyChains.Add(chainName)
	data.rules += len(*rules) * len(policy.targetPods.podsProtocols)

	policy.targetPods.podsProtocols.ForEachCreateRulesWithChain(ipm, "filter", chainName, netutils.IPTABLES_FULL_CHAIN_SYNC_NO_ORDER,
		netutils.NoReferencedChains, true, rules)
	return
}

func (pr *networkPolicyType) buildFwRules(meta *networkPolicyMetadata, policyRule policyRuleType, ipset *netutils.IPSet,
	activePolicyIpSets *activeRecordSets, rules *netutils.IpTablesRuleListType) (err error) {

	if pr.MatchAllPeers() {
		// case where only 'ports' details specified but no 'from' details in the ingress rule
		// so match on all sources, with specified port (if any) and protocol
		template := policyRule.getTemplate(RULE_TEMPLATE_MATCHALLPEERS, meta, "")
		pr.asIpTablesRule(rules, *template...)

	} else if pr.HasPods() {

		podIpSetName := kubeIpTargetIpSetPrefix.Get(meta.namespace, meta.name, policyRule.String())
		if !activePolicyIpSets.Contains(podIpSetName) {
			_, err = ipset.Create(podIpSetName, netutils.TypeHashIP, netutils.OptionTimeout, "0")
			if err != nil {
				return fmt.Errorf("failed to create ipset: %s", err.Error())
			}
			activePolicyIpSets.Add(podIpSetName)
		}

		ingressRuleSrcPodIps := make([]*net.IPNet, 0)
		pr.pods.ForEach(func(pod *podInfo) {
			ingressRuleSrcPodIps = append(ingressRuleSrcPodIps, pod.ip...)
		})

		ipset.Get(podIpSetName).RefreshAsync(ingressRuleSrcPodIps, netutils.OptionTimeout, "0")

		template := policyRule.getTemplate(RULE_TEMPLATE_POD, meta, podIpSetName)
		pr.asIpTablesRule(rules, *template...)

	} else if pr.HasIpBlocks() {

		blockIpSetName := kubeNetTargetIpSetPrefix.Get(meta.namespace, meta.name, policyRule.String())
		if !activePolicyIpSets.Contains(blockIpSetName) {
			_, err := ipset.Create(blockIpSetName, netutils.TypeHashNet, netutils.OptionTimeout, "0")
			if err != nil {
				return fmt.Errorf("failed to create ipset: %s", err.Error())
			}
			activePolicyIpSets.Add(blockIpSetName)
		}

		ipset.Get(blockIpSetName).RefreshAsync([][]string(*pr.GetIPBlocks()))

		template := policyRule.getTemplate(RULE_TEMPLATE_IPBLOCK, meta, blockIpSetName)
		pr.asIpTablesRule(rules, *template...)
	}

	return
}

func (npc *NetworkPolicyController) syncPodFirewallChains(inputPolicy ...*networkPolicyInfoListType) (*activeRecordSets, *activeRecordSets, error) {
	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		glog.V(0).Infof("Syncing syncPodFirewallChains policy chains took %v", endTime)
	}()

	activePodInChains := activeRecordSets{}.New()
	activePodOutChains := activeRecordSets{}.New()

	podsProtocols := &netutils.ProtocolMapType{}

	forward := netutils.NewRuleList()
	output := netutils.NewRuleList()
	input := netutils.NewRuleList()
	podOwnChain := netutils.ChainToRuleListMapType{}

	nodeProcessed := make(map[uint64]PolicyType)

	workerSet := npc.networkPoliciesInfo
	ipTablesAction := netutils.IPTABLES_FULL_CHAIN_SYNC_NO_ORDER
	if len(inputPolicy) != 0 {
		workerSet = inputPolicy[0]
		ipTablesAction = netutils.IPTABLES_APPEND_UNIQUE
	}

	// loop through the pods running on the node which to which ingress network policies to be applied
	for _, pol := range *workerSet {

		if !pol.policyType.CheckFor(NETWORK_POLICY_INGRESS) || nodeProcessed[pol.meta.hash].CheckFor(NETWORK_POLICY_INGRESS) {
			continue
		}

		podsProtocols.Merge(&pol.targetPods.podsProtocols)
		nodeProcessed[pol.meta.hash] |= NETWORK_POLICY_INGRESS

		// ensure pod specific firewall chain exist for all the pods that need ingress firewall
		podFwChainName := kubePodInChainPrefix.GetFromMeta(pol.meta)
		activePodInChains.Add(podFwChainName)

		if podOwnChain[podFwChainName] == nil {
			podOwnChain[podFwChainName] = netutils.NewRuleList()
		}

		// ensure statefull firewall, that permits return traffic for the traffic originated by the pod
		comment := "rule for stateful firewall for PODs selector:" + pol.meta.labels.String() + " namespace: " + pol.meta.namespace
		args := []string{"-m", "comment", "--comment", comment, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}
		podOwnChain[podFwChainName].Add(netutils.NewRuleWithOrder(args...))

		// icmp
		comment = "rule for icmp for PODs selector:" + pol.meta.labels.String() + " namespace: " + pol.meta.namespace
		args = []string{"-m", "comment", "--comment", comment, "-m", "set", "--match-set", kubeICMPIpSet, "src", "-j", "ACCEPT"}
		podOwnChain[podFwChainName].Add(netutils.NewRuleWithOrder(args...))

		// enable cluster nodes to create IPIP tunnels to pods (Dsr), or coming via tun+ interface in case
		// overlay tunnels are active
		for proto := range pol.targetPods.podsProtocols {
			tunnelProto := netutils.NewIP(proto).ProtocolCmdParam().TunnelProto
			comment = "rule to permit ipip tunnels for FWMark services from cluster nodes"
			args = []string{"-m", "comment", "--comment", comment, "-m", "set", "--match-set", kubeNodesIpSet, "src", "-p", tunnelProto, "-j", "ACCEPT"}
			podOwnChain[podFwChainName].Add(netutils.NewRule(args...))
			args = []string{"-m", "comment", "--comment", comment, "-i", "tun+", "-p", tunnelProto, "-j", "ACCEPT"}
			podOwnChain[podFwChainName].Add(netutils.NewRule(args...))
		}

		// add entries in pod firewall to run through required network policies
		for _, policy := range *npc.networkPoliciesInfo {
			if pol.meta.hash == policy.meta.hash && policy.policyType.CheckFor(NETWORK_POLICY_INGRESS) {
				podsProtocols.Merge(&policy.targetPods.podsProtocols)
				comment := "run through nw policy " + policy.meta.name + " " + policyRuleIngress{}.String()
				policyChainName := kubeNetworkPolicyChainPrefix.Get(policy.meta.namespace, policy.meta.name, policyRuleIngress{}.String())
				args := []string{"-m", "comment", "--comment", comment, "-j", policyChainName}
				podOwnChain[podFwChainName].Add(netutils.NewRule(args...))
			}
		}

		comment = "rule to permit the traffic to pods when source is the pod's local node"
		args = []string{"-m", "comment", "--comment", comment, "-m", "addrtype", "--src-type", "LOCAL", "-j", "ACCEPT"}
		podOwnChain[podFwChainName].Add(netutils.NewRule(args...))

		// ensure there is rule in filter table and FORWARD chain to jump to pod specific firewall chain
		// this rule applies to the traffic getting routed (coming for other node pods)
		comment = "rule to jump traffic destined to PODs selector:" + pol.meta.labels.String() + " namespace: " + pol.meta.namespace +
			" to chain " + podFwChainName
		args = []string{"-m", "comment", "--comment", comment,
			"-m", "set", "--match-set", kubeTargetIpSetPrefix.GetFromMeta(pol.meta), "dst",
			"-j", podFwChainName}
		forward.Add(netutils.NewRule(args...))

		// ensure there is rule in filter table and OUTPUT chain to jump to pod specific firewall chain
		// this rule applies to the traffic from a pod getting routed back to another pod on same node by service proxy
		output.Add(netutils.NewRule(args...))
		input.Add(netutils.NewRule(args...))

		// ensure there is rule in filter table and forward chain to jump to pod specific firewall chain
		// this rule applies to the traffic getting switched (coming for same node pods)
		comment = "rule to jump traffic destined to PODs selector:" + pol.meta.labels.String() + " namespace: " + pol.meta.namespace +
			" to chain " + podFwChainName
		args = []string{"-m", "physdev", "--physdev-is-bridged",
			"-m", "comment", "--comment", comment,
			"-m", "set", "--match-set", kubeTargetIpSetPrefix.GetFromMeta(pol.meta), "dst",
			"-j", podFwChainName}
		forward.Add(netutils.NewRule(args...))

		// add default DROP rule at the end of chain
		comment = "default rule to REJECT traffic from PODs selector: " + pol.meta.labels.String() + " namespace: " + pol.meta.namespace
		args = []string{"-m", "comment", "--comment", comment,
			"-m", "set", "--match-set", kubeTargetIpSetPrefix.GetFromMeta(pol.meta), "dst",
			"-j", "REJECT"}
		podOwnChain[podFwChainName].Add(netutils.NewRule(args...))
	}

	// loop through the pods running on the node which egress network policies to be applied
	for _, pol := range *workerSet {

		if !pol.policyType.CheckFor(NETWORK_POLICY_EGRESS) || nodeProcessed[pol.meta.hash].CheckFor(NETWORK_POLICY_EGRESS) {
			continue
		}

		podsProtocols.Merge(&pol.targetPods.podsProtocols)
		nodeProcessed[pol.meta.hash] |= NETWORK_POLICY_EGRESS

		// ensure pod specific firewall chain exist for all the pods that need egress firewall
		podFwChainName := kubePodOutChainPrefix.GetFromMeta(pol.meta)
		activePodOutChains.Add(podFwChainName)

		if podOwnChain[podFwChainName] == nil {
			podOwnChain[podFwChainName] = netutils.NewRuleList()
		}

		// ensure statefull firewall, that permits return traffic for the traffic originated by the pod
		comment := "rule for stateful firewall for PODs selector:" + pol.meta.labels.String() + " namespace: " + pol.meta.namespace
		args := []string{"-m", "comment", "--comment", comment, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}
		podOwnChain[podFwChainName].Add(netutils.NewRuleWithOrder(args...))

		// add entries in pod firewall to run through required network policies
		for _, policy := range *npc.networkPoliciesInfo {
			if pol.meta.hash == policy.meta.hash && policy.policyType.CheckFor(NETWORK_POLICY_EGRESS) {
				podsProtocols.Merge(&policy.targetPods.podsProtocols)
				comment := "run through nw policy " + policy.meta.name + " " + policyRuleEgress{}.String()
				policyChainName := kubeNetworkPolicyChainPrefix.Get(policy.meta.namespace, policy.meta.name, policyRuleEgress{}.String())
				args = []string{"-m", "comment", "--comment", comment, "-j", policyChainName}
				podOwnChain[podFwChainName].Add(netutils.NewRule(args...))
			}
		}

		// ensure there is rule in filter table and FORWARD chain to jump to pod specific firewall chain
		// this rule applies to the traffic getting routed (coming for other node pods)
		comment = "rule to jump traffic from PODs selector:" + pol.meta.labels.String() + " namespace: " + pol.meta.namespace +
			" to chain " + podFwChainName
		args = []string{"-m", "comment", "--comment", comment,
			"-m", "set", "--match-set", kubeTargetIpSetPrefix.GetFromMeta(pol.meta), "src",
			"-j", podFwChainName}
		forward.Add(netutils.NewRule(args...))

		// ensure there is rule in filter table and forward chain to jump to pod specific firewall chain
		// this rule applies to the traffic getting switched (coming for same node pods)
		comment = "rule to jump traffic from PODs selector:" + pol.meta.labels.String() + " namespace: " + pol.meta.namespace +
			" to chain " + podFwChainName
		args = []string{"-m", "physdev", "--physdev-is-bridged",
			"-m", "comment", "--comment", comment,
			"-m", "set", "--match-set", kubeTargetIpSetPrefix.GetFromMeta(pol.meta), "src",
			"-j", podFwChainName}
		forward.Add(netutils.NewRule(args...))

		// add default DROP rule at the end of chain
		comment = "default rule to REJECT traffic from PODs selector: " + pol.meta.labels.String() + " namespace: " + pol.meta.namespace
		args = []string{"-m", "comment", "--comment", comment,
			"-m", "set", "--match-set", kubeTargetIpSetPrefix.GetFromMeta(pol.meta), "src",
			"-j", "REJECT"}
		podOwnChain[podFwChainName].Add(netutils.NewRule(args...))
	}

	if err, rules := podsProtocols.ForEachCreateRulesWithChain(npc.Ipm, "filter", "", netutils.IPTABLES_FULL_CHAIN_SYNC_NO_ORDER,
		netutils.NoReferencedChains, true, podOwnChain); err != nil {
		return activePodInChains, activePodOutChains, err
	} else {
		data.rules += rules
	}

	if err, _ := podsProtocols.ForEachCreateRulesWithChain(
		npc.Ipm, "filter", string(kubeOutputPreprocessChain),
		ipTablesAction, []string{"OUTPUT"}, true, output); err != nil {

		return activePodInChains, activePodOutChains, err
	}
	data.rules += output.Size() * len(*podsProtocols)

	if err, _ := podsProtocols.ForEachCreateRulesWithChain(
		npc.Ipm, "filter", string(kubeInputPreprocessChain),
		ipTablesAction, []string{"INPUT"}, true, input); err != nil {

		return activePodInChains, activePodOutChains, err
	}
	data.rules += input.Size() * len(*podsProtocols)

	if err, _ := podsProtocols.ForEachCreateRulesWithChain(
		npc.Ipm, "filter", string(kubeForwardPreprocessChain),
		ipTablesAction, []string{netutils.CHAIN_KUBE_COMMON_FORWARD},
		true, forward); err != nil {

		return activePodInChains, activePodOutChains, err
	}
	data.rules += forward.Size() * len(*podsProtocols)
	return activePodInChains, activePodOutChains, nil
}

func (ma *activeRecordSets) contains(a, b string) bool {
	return !ma.at[a] && !ma.at[b]
}

func (npc *NetworkPolicyController) cleanupObsoleteResources(ipsets, chains []string) {
	for _, chainPrefix := range chains {
		npc.cleanupChains(chainPrefix, cmp.Comparer((&activeRecordSets{}).contains))
	}
	npc.cleanupIpSets(&activeRecordSets{}, ipsets)
}

func (npc *NetworkPolicyController) cleanupChains(chainPrefix string, comparer cmp.Option) {
	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		glog.V(0).Infof("Syncing cleanupChains policy chains took %v", endTime)
	}()

	netutils.UsedTcpProtocols.ForEach(func(proto netutils.Proto) error {
		return npc.Ipm.IptablesCleanUpChainWithComparer(proto, chainPrefix, true,
			cmp.FilterValues(utils.SymetricHasPrefix, comparer), "filter")
	})
}

func (npc *NetworkPolicyController) cleanupIpSets(activePolicyIPSets *activeRecordSets, prefixToClean []string) error {
	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		glog.V(0).Infof("Syncing cleanupIpSets policy chains took %v", endTime)
	}()

	setsToClean, err := netutils.NewIPSet().SaveSimpleList()
	if err != nil {
		glog.Errorf("failed to get IPSet data for cleanup due to %s", err.Error())
	}

	for _, set := range *setsToClean {
		ok := false
		for _, prefix := range prefixToClean {
			if strings.HasPrefix(set.Name, prefix) {
				ok = true
				break
			}
		}

		if !ok {
			continue
		}

		name := set.Name
		if strings.HasSuffix(name, netutils.TmpTableSuffix) {
			name = name[:len(name)-1]
		}
		if !activePolicyIPSets.Contains(name) {
			fmt.Println("Destroy:", name)
			set.DestroyAsync()
		}
	}
	return nil
}

func (npc *NetworkPolicyController) cleanupStaleRules(activePolicyChains, activePodInChains,
	activePodOutChains, activePolicyIPSets *activeRecordSets) error {
	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		glog.V(0).Infof("Syncing cleanupStaleRules policy chains took %v", endTime)
	}()

	npc.cleanupChains(kubeNetworkPolicyChainPrefix.String(), cmp.Comparer(activePolicyChains.contains))

	npc.cleanupChains(kubePodInChainPrefix.String(), cmp.Comparer(activePodInChains.contains))
	npc.cleanupChains(kubePodOutChainPrefix.String(), cmp.Comparer(activePodOutChains.contains))

	npc.cleanupIpSets(activePolicyIPSets, []string{"KUBE-TGT"})
	return nil
}

func (pr *networkPolicyType) checkForNamedPorts(ports *[]networking.NetworkPolicyPort) error {
	for _, npProtocolPort := range *ports {
		if npProtocolPort.Port != nil && npProtocolPort.Port.Type == intstr.String {
			return fmt.Errorf("Found named port %s in network policy", npProtocolPort.Port.String())
		}
	}
	return nil
}

func (npc *NetworkPolicyController) buildNetworkPoliciesInfo() (*networkPolicyInfoListType, error) {
	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		glog.V(0).Infof("Syncing buildNetworkPoliciesInfo policy chains took %v", endTime)
	}()

	NetworkPolicies := &networkPolicyInfoListType{}

	for _, policyObj := range npc.npLister.List() {

		policy, ok := policyObj.(*networking.NetworkPolicy)
		if !ok {
			return nil, fmt.Errorf("failed to convert")
		}

		NetworkPolicies.Add(npc.buildSinglePolicyInfo(policy))
	}

	return NetworkPolicies, nil
}

func (npc *NetworkPolicyController) buildSinglePolicyInfo(policy *networking.NetworkPolicy) *networkPolicyInfo {

	newPolicy := &networkPolicyInfo{
		meta: &networkPolicyMetadata{
			name:      policy.Name,
			namespace: policy.Namespace,
			labels:    policy.Spec.PodSelector.MatchLabels,
			hash:      utils.DoHash64(policy.Namespace + labels.FormatLabels(policy.Spec.PodSelector.MatchLabels)),
			source:    policy,
		},
	}

	newPolicy.decodePolicyType(policy)
	newPolicy.targetPods = npc.ListPodInfoByNamespaceAndLabels(policy.Namespace, newPolicy.meta.labels.AsSelector())

	if newPolicy.parsePolicy(policy, npc.evalPodPeer) {
		return nil
	}

	return newPolicy
}

func (pol *networkPolicyInfo) decodePolicyType(policy *networking.NetworkPolicy) {
	// check if there is explicitly specified PolicyTypes in the spec
	for _, policyType := range policy.Spec.PolicyTypes {
		if policyType == networking.PolicyTypeIngress {
			pol.policyType |= NETWORK_POLICY_INGRESS
		}
		if policyType == networking.PolicyTypeEgress {
			pol.policyType |= NETWORK_POLICY_EGRESS
		}
	}
	if pol.policyType == NETWORK_POLICY_NOPOLICY {
		if policy.Spec.Egress != nil {
			pol.policyType |= NETWORK_POLICY_EGRESS
		}
		if policy.Spec.Ingress != nil {
			pol.policyType |= NETWORK_POLICY_INGRESS
		}
	}
}

type EvalPodPeer func(*networking.NetworkPolicy, *networking.NetworkPolicyPeer) *podListType

func (npc *NetworkPolicyController) evalPodPeer(policy *networking.NetworkPolicy, peer *networking.NetworkPolicyPeer) *podListType {
	var namespaces = []*api.Namespace{{ObjectMeta: v1.ObjectMeta{Name: policy.Namespace}}}
	var podSelectorLabels = labels.Everything()
	var matchingPods = podListType{podsProtocols: netutils.ProtocolMapType{}, pods: &podListMapType{}}

	if peer.NamespaceSelector == nil && peer.PodSelector == nil {
		return nil
	}

	// NetworkPolicyPeer describes a peer to allow traffic from. Exactly one of its fields
	// must be specified. {#link namespaceSelector/podSelector/ipBlocks}
	if peer.NamespaceSelector != nil {
		namespaces = npc.ListNamespaceByLabels(labels.SelectorFromSet(peer.NamespaceSelector.MatchLabels))
	} else if peer.PodSelector != nil {
		podSelectorLabels = labels.SelectorFromSet(peer.PodSelector.MatchLabels)
	}

	for _, namespace := range namespaces {
		matchingPods.AddList(npc.ListPodInfoByNamespaceAndLabels(namespace.Name, podSelectorLabels))
	}

	return &matchingPods
}

func (npc *NetworkPolicyController) ListPodInfoByNamespaceAndLabels(namespace string, selector labels.Selector) *podListType {
	matchingPods := podListType{podsProtocols: netutils.ProtocolMapType{}, portNameToPort: &nameToPortType{}, pods: &podListMapType{}}
	for _, namespacePod := range npc.ListPodsByNamespaceAndLabels(namespace, selector) {
		if namespacePod.Status.PodIP != "" {
			podInfo := podInfo{}.fromApi(namespacePod)
			matchingPods.Add(podInfo)

			matchingPods.podsProtocols[netutils.NewIP(namespacePod.Status.PodIP).Protocol()] = true
			if !matchingPods.hasPodsLocally && npc.nodeIP.Equal(netutils.NewIP(namespacePod.Status.HostIP).ToIP()) {
				matchingPods.hasPodsLocally = true
			}

			podInfo.ip = append(podInfo.ip, netutils.NewList(npc.getExternalIP(podInfo.ip[0].IP, namespace))...)

			npc.getPortNameToPortMap(matchingPods.portNameToPort, namespacePod)
		}
	}
	return &matchingPods
}

func (npc *NetworkPolicyController) getPortNameToPortMap(out *nameToPortType, pod *api.Pod) {
	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			(*out)[port.Name] = port.ContainerPort
		}
	}
}

func (npc *NetworkPolicyController) ListPodsByNamespaceAndLabels(namespace string, selector labels.Selector) (ret []*api.Pod) {
	allMatchedNameSpacePods, err := listers.NewPodLister(npc.podLister).Pods(namespace).List(selector)
	if err != nil {
		glog.Error("Failed to build network policies info due to " + err.Error())
		return
	}
	return allMatchedNameSpacePods
}

func (npc *NetworkPolicyController) ListNamespaceByLabels(selector labels.Selector) []*api.Namespace {
	matchedNamespaces, err := listers.NewNamespaceLister(npc.nsLister).List(selector)
	if err != nil {
		glog.Error("Failed to build network policies info due to " + err.Error())
		return nil
	}
	return matchedNamespaces
}

func evalIPBlockPeer(peer *networking.NetworkPolicyPeer) (ipBlock [][]string) {
	if peer.IPBlock == nil {
		return
	}

	ipBlock = append(ipBlock, append(parseCIDR(peer.IPBlock.CIDR, netutils.OptionTimeout, "0"))...)
	for _, except := range peer.IPBlock.Except {
		ipBlock = append(ipBlock, append(parseCIDR(except, netutils.OptionTimeout, "0", netutils.OptionNoMatch))...)
	}

	return
}

func parseCIDR(cidr string, options ...string) [][]string {
	if strings.HasSuffix(cidr, "/0") {
		if netutils.NewIP(cidr).IsIPv4() {
			return [][]string{append([]string{"0.0.0.0/1"}, options...), append([]string{"128.0.0.0/1"}, options...)}
		} else {
			return [][]string{append([]string{"::/1"}, options...), append([]string{"8000::/1"}, options...)}
		}
	}
	return [][]string{append([]string{cidr}, options...)}
}

func (npc *NetworkPolicyController) buildBetaNetworkPoliciesInfo() (*networkPolicyInfoListType, error) {

	NetworkPolicies := make(networkPolicyInfoListType, 0)

	for _, policyObj := range npc.npLister.List() {

		policy, _ := policyObj.(*apiextensions.NetworkPolicy)

		newPolicy := &networkPolicyInfo{
			meta: &networkPolicyMetadata{
				name:      policy.Name,
				namespace: policy.Namespace,
				labels:    policy.Spec.PodSelector.MatchLabels,
				hash:      utils.DoHash64(policy.Namespace + labels.FormatLabels(policy.Spec.PodSelector.MatchLabels)),
			},
		}

		newPolicy.targetPods = npc.ListPodInfoByNamespaceAndLabels(policy.Namespace, newPolicy.meta.labels.AsSelector())

		for _, specIngressRule := range policy.Spec.Ingress {
			ingressRule := &networkPolicyType{}

			for _, port := range specIngressRule.Ports {
				protocolAndPort := newProtocolAndPort(&networking.NetworkPolicyPort{port.Protocol, port.Port})
				ingressRule.GetPorts().Add(protocolAndPort)
			}

			for _, peer := range specIngressRule.From {
				ingressRule.AddPods(npc.ListPodInfoByNamespaceAndLabels(policy.Namespace, labels.SelectorFromSet(peer.PodSelector.MatchLabels)))
			}
			newPolicy.ingressRules.Add(ingressRule)
		}
		NetworkPolicies.Add(newPolicy)
	}

	return &NetworkPolicies, nil
}

func (p kubePolPrefixType) String() string {
	return string(p)
}

func (p kubePolPrefixType) GetFromMeta(meta *networkPolicyMetadata) string {
	return p.getInternal(meta.hash)
}

func (p kubePolPrefixType) Get(i ...interface{}) string {
	return p.getInternal(utils.DoHash64(fmt.Sprint(i...)))
}

func (p kubePolPrefixType) getInternal(hash uint64) string {
	return string(p) + fmt.Sprintf("%0.16X", hash)
}

// Cleanup cleanup configurations done
func (npc *NetworkPolicyController) Cleanup() {

	glog.Info("Cleaning up iptables configuration permanently done by kube-router")

	for p := range netutils.UsedTcpProtocols {
		npc.Ipm.IptablesCleanUpChainWithComparer(p, kubePodInChainPrefix.String(), true, cmp.Comparer(utils.SymetricHasPrefix))
		npc.Ipm.IptablesCleanUpChainWithComparer(p, kubePodOutChainPrefix.String(), true, cmp.Comparer(utils.SymetricHasPrefix))
		npc.Ipm.IptablesCleanUpChainWithComparer(p, kubeNetworkPolicyChainPrefix.String(), true, cmp.Comparer(utils.SymetricHasPrefix))
	}

	npc.cleanupObsoleteResources([]string{}, kubeCleanupChainPrefix)

	// delete all ipsets
	ipset := netutils.NewIPSet()

	err := ipset.Save()
	if err != nil {
		glog.Errorf("Failed to clean up ipsets: " + err.Error())
	}
	err = ipset.DestroyAllWithin()
	if err != nil {
		glog.Errorf("Failed to clean up ipsets: " + err.Error())
	}
	glog.Infof("Successfully cleaned the iptables configuration done by kube-router")
}

func (npc *NetworkPolicyController) newPodEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			npc.OnPodUpdate(obj)

		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newPoObj := newObj.(*api.Pod)
			oldPoObj := oldObj.(*api.Pod)
			if newPoObj.Status.Phase != oldPoObj.Status.Phase || newPoObj.Status.PodIP != oldPoObj.Status.PodIP {
				// for the network policies, we are only interested in pod status phase change or IP change
				npc.OnPodUpdate(newObj)
			}
		},
		DeleteFunc: func(obj interface{}) {
			npc.OnPodDelete(obj)
		},
	}
}

func (npc *NetworkPolicyController) newNamespaceEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			npc.OnNamespaceUpdate(obj)

		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			npc.OnNamespaceUpdate(newObj)

		},
		DeleteFunc: func(obj interface{}) {
			npc.OnNamespaceUpdate(obj)

		},
	}
}

func (npc *NetworkPolicyController) newNetworkPolicyEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			npc.OnNetworkPolicyUpdate(obj)

		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			npc.OnNetworkPolicyUpdate(newObj)
		},
		DeleteFunc: func(obj interface{}) {
			npc.OnNetworkPolicyUpdate(obj)
		},
	}
}

func (npc *NetworkPolicyController) syncNodesIPSet() error {
	nodes, err := npc.clientset.CoreV1().Nodes().List(v1.ListOptions{})
	if err != nil {
		err = errors.New("Failed to list nodes from API server due to: " + err.Error())
	}

	currentNodes := make([]string, 0)
	if err == nil {
		for _, node := range nodes.Items {
			nodeIP, _ := utils.GetNodeIP(&node)
			currentNodes = append(currentNodes, nodeIP.String())
		}
	}

	if err == nil {
		if set, errSet := npc.ipSetHandler.GetOrCreate(kubeNodesIpSet, netutils.TypeHashIP, netutils.OptionTimeout, "0"); errSet != nil {
			err = errors.New("Failed to create ipset " + kubeNodesIpSet)
		} else {
			set.RefreshAsync(currentNodes)
		}
	}
	if err != nil {
		glog.Error(err)
	}
	return err
}

func (npc *NetworkPolicyController) getExternalIP(podIP net.IP, namespace string) (eips []string) {
	var svc *api.Service
	obj, exists, err := npc.getSvcFromPodIP(podIP, namespace)
	svc, ok := obj.(*api.Service)
	if err != nil {
		glog.Errorf("error getting externalIPs: %s", err.Error())
		return
	} else if !exists || !ok || svc == nil {
		return
	}

	eips = svc.Spec.ExternalIPs
	for _, lbIngress := range svc.Status.LoadBalancer.Ingress {
		if len(lbIngress.IP) > 0 {
			eips = append(eips, lbIngress.IP)
		}
	}

	return
}

func (npc *NetworkPolicyController) getSvcFromPodIP(podIP net.IP, namespace string) (item interface{}, exists bool, err error) {
	for _, obj := range npc.epLister.List() {
		eps := obj.(*api.Endpoints)
		for _, ep := range eps.Subsets {
			for _, addr := range ep.Addresses {
				if netutils.NewIP(addr.IP).ToIP().Equal(podIP) {
					return npc.svcLister.GetByKey(eps.Namespace + "/" + eps.Name)
				}
			}
		}
	}
	return nil, false, nil
}

// NewNetworkPolicyController returns new NetworkPolicyController object
func NewNetworkPolicyController(clientset kubernetes.Interface, config *options.KubeRouterConfig,
	podInformer, npInformer, nsInformer, epInformer, svcInformer cache.SharedIndexInformer) (*NetworkPolicyController, error) {
	npc := NetworkPolicyController{mu: utils.NewChanLock()}

	if config.MetricsEnabled {
		//GetData the metrics for this controller
		prometheus.MustRegister(metrics.ControllerIptablesSyncTime)
		prometheus.MustRegister(metrics.ControllerPolicyChainsSyncTime)
		npc.MetricsEnabled = true
	}

	npc.syncPeriod = config.IPTablesSyncPeriod
	npc.clientset = clientset

	npc.v1NetworkPolicy = true
	v, _ := clientset.Discovery().ServerVersion()
	valid := regexp.MustCompile("[0-9]")
	v.Minor = strings.Join(valid.FindAllString(v.Minor, -1), "")
	minorVer, _ := strconv.Atoi(v.Minor)
	if v.Major == "1" && minorVer < 7 {
		npc.v1NetworkPolicy = false
	}

	node, err := utils.GetNodeObject(clientset, config.HostnameOverride)
	if err != nil {
		return nil, err
	}

	npc.nodeHostName = node.Name

	nodeIP, err := utils.GetNodeIP(node)
	if err != nil {
		return nil, err
	}
	npc.nodeIP = nodeIP

	npc.Ipm = netutils.NewIpTablesManager([]string{npc.nodeIP.String()})

	ipset := netutils.NewIPSet()
	err = ipset.Save()
	if err != nil {
		return nil, err
	}
	npc.ipSetHandler = ipset

	npc.epLister = epInformer.GetIndexer()
	npc.svcLister = svcInformer.GetIndexer()

	npc.podLister = podInformer.GetIndexer()
	npc.PodEventHandler = npc.newPodEventHandler()

	npc.nsLister = nsInformer.GetIndexer()
	npc.NamespaceEventHandler = npc.newNamespaceEventHandler()

	npc.npLister = npInformer.GetIndexer()
	npc.NetworkPolicyEventHandler = npc.newNetworkPolicyEventHandler()

	return &npc, nil
}
