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
	"github.com/cloudnativelabs/kube-router/pkg/helpers/api"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/hostconf"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/hostnet"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/tools"
	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/eapache/channels"
	"github.com/golang/glog"
	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
	k8sapi "k8s.io/api/core/v1"
	apiextensions "k8s.io/api/extensions/v1beta1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
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
	controllers.Controller

	mu              sync.Mutex
	MetricsEnabled  bool
	v1NetworkPolicy bool
	readyForUpdates bool
	rejectTargets   []string

	activeRecordSetPool *sync.Pool

	// list of all active network policies expressed as networkPolicyInfo
	networkPoliciesInfo networkPolicyInfoListType
	ipSetHandler        *hostnet.IPSet

	podLister  cache.Indexer
	npLister   cache.Indexer
	nsLister   cache.Indexer
	epLister   cache.Indexer
	svcLister  cache.Indexer
	nodeLister cache.Indexer

	PodEventHandler           cache.ResourceEventHandler
	NamespaceEventHandler     cache.ResourceEventHandler
	NetworkPolicyEventHandler cache.ResourceEventHandler
	NodesEventHandler         cache.ResourceEventHandler

	Ipm      *hostnet.IpTablesManager
	cfgCheck *hostconf.ConfigCheckType
}

type networkPolicyInfoListType map[string]*networkPolicyInfo

var metricsData keyMetrics

const synchQueueChannelSize = 7

var afterPickupOnce = new(sync.Once)
var updatesQueue = channels.NewBatchingChannel(synchQueueChannelSize)
var hashSlicePool = sync.Pool{
	New: func() interface{} {
		return make([]uint64, 0, synchQueueChannelSize)
	}}

// Run runs forver till we receive notification on stopCh
func (npc *NetworkPolicyController) run(stopCh <-chan struct{}) (err error) {
	t := time.NewTicker(npc.GetSyncPeriod())
	obsoleteResourceCleanupOnce := &sync.Once{}
	defer func() {
		glog.Infof("Shutting down %s", npc.GetControllerName())
		t.Stop()
	}()

	npc.cfgCheck = hostconf.GetConfigChecker()
	npc.cfgCheck.Register(npc, hostconf.ConfigCheck{tools.GetExecPath("ip6tables"), []string{"-t", "filter", "-S", "-w"}})
	npc.cfgCheck.Register(npc, hostconf.ConfigCheck{tools.GetExecPath("iptables"), []string{"-t", "filter", "-S", "-w"}})
	npc.cfgCheck.Register(npc, hostconf.ConfigCheck{tools.GetExecPath("ipvsadm"), []string{"--save", "-n"}})

	glog.Infof("Started %s", npc.GetControllerName())

	// loop forever till notified to stop on stopCh
	for {
		glog.V(1).Info("Performing periodic sync of iptables to reflect network policies")
		if updatesQueue.Len() == 0 {
			if err = npc.Sync(); err != nil {
				glog.Errorf("Error during periodic sync of network policies in network policy controller. Error: " + err.Error())
				glog.Errorf("Skipping sending heartbeat from network policy controller as periodic sync failed.")
			} else {
				dataCopy := metricsData
				healthcheck.SendHeartBeat(npc, dataCopy)
			}
		}
		// Run obsolete resources cleanup after first full sync, not at the start. Those resources
		// can be used by others until sync runs with new setting
		obsoleteResourceCleanupOnce.Do(func() {
			npc.cleanupObsoleteResources(kubeCleanupIpSetPrefix, kubeCleanupChainPrefix)
		})

		npc.readyForUpdates = true
		select {
		case <-stopCh:
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
	npc.cfgCheck.ForceNextRun(npc)
}

func (npc *NetworkPolicyController) updatePreChecks(obj interface{}) (pod *k8sapi.Pod) {
	pod = obj.(*k8sapi.Pod)
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
	namespace := obj.(*k8sapi.Namespace)
	// namespace (and annotations on it) has no significance in GA ver of network policy
	if npc.v1NetworkPolicy {
		return
	}
	glog.V(2).Infof("Received update for namespace: %s", namespace.Name)

	npc.queueUpdate(obj)
}

func (npc *NetworkPolicyController) queueUpdate(obj interface{}) {
	updatesQueue.In() <- &tools.ApiTransaction{New: obj}
	npc.scheduleQueueProcess(250 * time.Millisecond)
}

func (npc *NetworkPolicyController) scheduleQueueProcess(after time.Duration) {
	afterPickupOnce.Do(func() {
		npc.mu.Lock()
		time.AfterFunc(after, npc.updatesQueue)
	})
}

func (npc *NetworkPolicyController) updatesQueue() {

	start := time.Now()
	defer func() {
		npc.cfgCheck.ForceNextRun(npc)
		npc.mu.Unlock()
		if updatesQueue.Len() != 0 {
			npc.scheduleQueueProcess(100 * time.Millisecond)
		}
	}()

	var activeIpSets = npc.activeRecordSetPool.Get().(*activeRecordSet)
	var activePolicyChains = npc.activeRecordSetPool.Get().(*activeRecordSet)

	var updateHashes = hashSlicePool.Get().([]uint64)
	var updatePolicies = make(networkPolicyInfoListType)
	var updatedPods []interface{}
	var updatedNamespaces []interface{}

	var processed = updatesQueue.Len()

	for _, update := range (<-updatesQueue.Out()).([]interface{}) {

		switch updTyped := update.(*tools.ApiTransaction).New.(type) {
		case *k8sapi.Pod:
			updatedPods = append(updatedPods, podInfo{}.fromApi(updTyped))
			glog.V(3).Infof("Added pod %v to bulk change", *updTyped)

		case *networking.NetworkPolicy:
			p := npc.buildSinglePolicyInfo(updTyped)
			updateHashes = append(updateHashes, p.meta.hash)
			glog.V(3).Infof("Added policy %v to bulk change", *updTyped)

		case *k8sapi.Namespace:
			updatedNamespaces = append(updatedNamespaces, updTyped)
			glog.V(3).Infof("Added namespace %v to bulk change", *updTyped)
		}
	}

	afterPickupOnce = &sync.Once{}
	preparedIpSets := &preparedIpSetsType{}

	npc.rebuildPolicyInfo()

	npc.networkPoliciesInfo.ForEach(func(p *networkPolicyInfo) {
		if tools.CheckForElementInArray(p.meta.hash, updateHashes) {
			updatePolicies.Add(p)
		}
		npc.findAffectedPolicies(p, updatePolicies, updatedPods)
		npc.findAffectedPolicies(p, updatePolicies, updatedNamespaces)
	})

	updatePolicies.ForEach(func(p *networkPolicyInfo) {
		npc.syncSingleNetworkPolicyChain(p, activeIpSets, activePolicyChains, preparedIpSets, true)
	})

	npc.refreshIpSets(activeIpSets, preparedIpSets)
	healthcheck.SendHeartBeat(npc, metricsData)

	hashSlicePool.Put(updateHashes[:0])
	npc.activeRecordSetPool.Put(activePolicyChains.Reset())
	npc.activeRecordSetPool.Put(activeIpSets.Reset())
	glog.Infof("Transaction sync policy controller took %v (processed %d changes)", time.Since(start), processed)
}

func (npc *NetworkPolicyController) findAffectedPolicies(p *networkPolicyInfo, plcs networkPolicyInfoListType, slice []interface{}) {
	for _, obj := range slice {
		switch typed := obj.(type) {
		case *k8sapi.Namespace:
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

type preparedIpSetsType map[string]*hostnet.Set

// Sync synchronizes iptables to desired state of network policies
func (npc *NetworkPolicyController) Sync() (err error) {
	npc.mu.Lock()
	start := time.Now()

	defer func() {
		endTime := time.Since(start)
		npc.mu.Unlock()
		glog.Infof("Sync policy controller took %v", endTime)
		if npc.MetricsEnabled {
			metrics.ControllerIptablesSyncTime.Observe(endTime.Seconds())
		}
		metricsData.lastSync = endTime
	}()

	npc.ipSetHandler.Save()
	if err = npc.syncNodesIPSet(); err != nil {
		return errors.New("Aborting sync. Failed to sync cluster nodes ipset: " + err.Error())
	}

	if !npc.cfgCheck.GetCheckResult(npc) {
		npc.addExtraSets(nil)
		return
	}

	preparedIpSets := make(preparedIpSetsType)
	metricsData = keyMetrics{pods: len(npc.podLister.List())}

	if err = npc.rebuildPolicyInfo(); err != nil {
		return err
	}

	activePolicyChains, activePolicyIpSets, err := npc.syncNetworkPolicyChains(&preparedIpSets)
	if err != nil {
		return errors.New("Aborting sync. Failed to sync network policy chains: " + err.Error())
	}

	err = npc.addExtraSets(activePolicyIpSets)
	if err != nil {
		return errors.New("Aborting sync. Failed to sync extra sets: " + err.Error())
	}

	activePodInChains, activePodOutChains, err := npc.syncPodFirewallChains(activePolicyChains)
	if err != nil {
		return errors.New("Aborting sync. Failed to sync pod firewalls: " + err.Error())
	}

	metricsData.ipsets = activePolicyIpSets.Size()
	metricsData.chains = activePolicyChains.Size() + activePodInChains.Size() + activePodOutChains.Size()

	npc.refreshIpSets(activePolicyIpSets, &preparedIpSets)

	err = npc.cleanupStaleRules(activePolicyChains, activePodInChains, activePodOutChains, activePolicyIpSets)
	if err != nil {
		return errors.New("Aborting sync. Failed to cleanup stale iptables rules: " + err.Error())
	}

	return nil
}

func (npc *NetworkPolicyController) refreshIpSets(ipSets *activeRecordSet, preparedIpSets *preparedIpSetsType) {
	start := time.Now()
	defer glog.Infof("Refreshing ipSets took %v", time.Since(start))

	ipSets.ForEach(func(ipset string) {
		set := npc.ipSetHandler.Get(ipset)
		if set == nil || (*preparedIpSets)[set.Name] == nil {
			return
		}
		set.CommitWithSet((*preparedIpSets)[set.Name])
	})
}

func (npc *NetworkPolicyController) addExtraSets(activePolicyIpSets *activeRecordSet) (err error) {
	start := time.Now()
	defer glog.Infof("Syncing extra sets took %v", time.Since(start))

	icmpIpSet, _ := npc.ipSetHandler.GetOrCreate(kubeICMPIpSet, hostnet.TypeHashNetPort)
	icmpIpSet.RefreshAsync(icmpIpSetSource)

	if activePolicyIpSets != nil {
		activePolicyIpSets.Add(kubeICMPIpSet)
	}
	return
}

func (npc *NetworkPolicyController) rebuildPolicyInfo() (err error) {
	start := time.Now()
	defer glog.Infof("Rebuild policy info took %v", time.Since(start))

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
func (npc *NetworkPolicyController) syncNetworkPolicyChains(preparedIpSets *preparedIpSetsType) (*activeRecordSet, *activeRecordSet, error) {
	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		glog.Infof("Syncing network policy chains took %v", endTime)
		if npc.MetricsEnabled {
			metrics.ControllerPolicyChainsSyncTime.Observe(endTime.Seconds())
		}
	}()

	var err error
	var activePolicyChains = npc.activeRecordSetPool.Get().(*activeRecordSet)
	var activePolicyIpSets = npc.activeRecordSetPool.Get().(*activeRecordSet)

	// run through all network policies
	npc.networkPoliciesInfo.ForEach(func(policy *networkPolicyInfo) {
		if err = npc.syncSingleNetworkPolicyChain(policy, activePolicyIpSets, activePolicyChains, preparedIpSets, false); err != nil {
			return
		}
	})

	if err != nil {
		return nil, nil, err
	}

	glog.V(2).Infof("Iptables chains in the filter table are synchronized with the network policies.")

	metricsData.policies += npc.networkPoliciesInfo.Size()
	return activePolicyChains, activePolicyIpSets, nil
}

func (npc *NetworkPolicyController) syncSingleNetworkPolicyChain(policy *networkPolicyInfo, activePolicyIpSets,
	activePolicyChains *activeRecordSet, preparedIpSets *preparedIpSetsType, force bool) (err error) {

	targetPodIpSetName := kubeTargetIpSetPrefix.GetFromMeta(policy.meta)

	// create an ipset for all targets pod matched by the policy spec PodSelector
	// if not exists yet (many policies can have same PodSelector)
	if force || !activePolicyIpSets.Contains(targetPodIpSetName) {

		/**/
		targetPodIpSet, err := npc.ipSetHandler.GetOrCreate(targetPodIpSetName, hostnet.TypeHashIP, hostnet.OptionTimeout, "0")
		if err != nil {
			return fmt.Errorf("failed to create ipset: %s", err.Error())
		}

		activePolicyIpSets.Add(targetPodIpSetName)

		currentPodIps := make([]*net.IPNet, 0)
		policy.targetPods.ForEach(func(pod *podInfo) {
			currentPodIps = append(currentPodIps, pod.ip...)
		})

		(*preparedIpSets)[targetPodIpSet.Name] = targetPodIpSet.Prepare(currentPodIps)
	}

	err = npc.processRules(policy, activePolicyChains, activePolicyIpSets, preparedIpSets)
	return
}

func (npc *NetworkPolicyController) processRules(policy *networkPolicyInfo, activePolicyChains, activePolicyIpSets *activeRecordSet,
	preparedIpSets *preparedIpSetsType) (err error) {

	// run through all the ingress rules in the spec and create iptables rules
	// in the chain for the network policy
	err = policy.ingressRules.processPolicyRules(policy, &policy.ingressRules, npc.ipSetHandler,
		activePolicyChains, activePolicyIpSets, preparedIpSets, npc.Ipm)
	// run through all the egress rules in the spec and create iptables rules
	// in the chain for the network policy
	if err == nil {
		err = policy.egressRules.processPolicyRules(policy, &policy.egressRules, npc.ipSetHandler,
			activePolicyChains, activePolicyIpSets, preparedIpSets, npc.Ipm)
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

func getTemplate(rt templateType, meta *networkPolicyMetadata, generated string, directionOffset int) []string {
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
	return out
}

func (pr *policyRuleIngress) getTemplate(rt templateType, meta *networkPolicyMetadata, generated string) []string {
	return getTemplate(rt, meta, generated, 0)
}

func (pr *policyRuleEgress) getTemplate(rt templateType, meta *networkPolicyMetadata, generated string) []string {
	return getTemplate(rt, meta, generated, 1)
}

func (prl *networkPolicyListType) processPolicyRules(policy *networkPolicyInfo, policyRule policyRuleType, ipSetHandler *hostnet.IPSet,
	activePolicyChains, activePolicyIpSets *activeRecordSet, preparedIpSets *preparedIpSetsType, ipm *hostnet.IpTablesManager) (err error) {

	if policy.targetPods.Size() == 0 {
		return
	}

	rules := &hostnet.IpTablesRuleListType{}
	for i, rule := range prl.rules {
		if err = rule.buildFwRules(policy.meta, policyRule, ipSetHandler, activePolicyIpSets, rules, preparedIpSets, i); err != nil {
			return
		}
	}

	if rules.Size() == 0 || len(policy.targetPods.podsProtocols) == 0 {
		return
	}

	chainName := kubeNetworkPolicyChainPrefix.Get(policy.meta.namespace, policy.meta.name, policyRule.String())
	activePolicyChains.Add(chainName)
	metricsData.rules += len(*rules) * len(policy.targetPods.podsProtocols)

	hostnet.UsedTcpProtocols.ForEachCreateRulesWithChain(ipm, "filter", chainName, hostnet.IPTABLES_FULL_CHAIN_SYNC_NO_ORDER,
		true, rules)
	return
}

func (pr *networkPolicyType) buildFwRules(meta *networkPolicyMetadata, policyRule policyRuleType, ipset *hostnet.IPSet,
	activePolicyIpSets *activeRecordSet, rules *hostnet.IpTablesRuleListType, preparedIpSets *preparedIpSetsType, i int) (err error) {

	if pr.MatchAllPeers() {
		// case where only 'ports' details specified but no 'from' details in the ingress rule
		// so match on all sources, with specified port (if any) and protocol
		pr.asIpTablesRule(rules, policyRule.getTemplate(RULE_TEMPLATE_MATCHALLPEERS, meta, "")...)

	} else if pr.HasPods() {

		podIpSetName := kubeIpTargetIpSetPrefix.Get(meta.namespace, meta.name, policyRule, i)
		if !activePolicyIpSets.Contains(podIpSetName) {
			/**/
			_, err = ipset.GetOrCreate(podIpSetName, hostnet.TypeHashIP, hostnet.OptionTimeout, "0")
			if err != nil {
				return fmt.Errorf("failed to create ipset: %s", err.Error())
			}
			activePolicyIpSets.Add(podIpSetName)
		}

		ingressRuleSrcPodIps := make([]*net.IPNet, 0)
		pr.pods.ForEach(func(pod *podInfo) {
			ingressRuleSrcPodIps = append(ingressRuleSrcPodIps, pod.ip...)
		})

		//ipset.Get(podIpSetName).RefreshAsync(ingressRuleSrcPodIps, netutils.OptionTimeout, "0")
		(*preparedIpSets)[podIpSetName] = ipset.Get(podIpSetName).Prepare(ingressRuleSrcPodIps)

		pr.asIpTablesRule(rules, policyRule.getTemplate(RULE_TEMPLATE_POD, meta, podIpSetName)...)

	} else if pr.HasIpBlocks() {

		blockIpSetName := kubeNetTargetIpSetPrefix.Get(meta.namespace, meta.name, policyRule, i)
		if !activePolicyIpSets.Contains(blockIpSetName) {
			/**/
			_, err := ipset.GetOrCreate(blockIpSetName, hostnet.TypeHashNet, hostnet.OptionTimeout, "0")
			if err != nil {
				return fmt.Errorf("failed to create ipset: %s", err.Error())
			}
			activePolicyIpSets.Add(blockIpSetName)
		}

		//ipset.Get(blockIpSetName).RefreshAsync([][]string(*pr.GetIPBlocks()))
		(*preparedIpSets)[blockIpSetName] = ipset.Get(blockIpSetName).Prepare([][]string(*pr.GetIPBlocks()))

		pr.asIpTablesRule(rules, policyRule.getTemplate(RULE_TEMPLATE_IPBLOCK, meta, blockIpSetName)...)
	}

	return
}

func (npc *NetworkPolicyController) syncPodFirewallChains(activeChains *activeRecordSet, inputPolicy ...networkPolicyInfoListType) (*activeRecordSet, *activeRecordSet, error) {
	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		glog.Infof("Syncing syncPodFirewallChains policy chains took %v", endTime)
	}()

	activePodInChains := npc.activeRecordSetPool.Get().(*activeRecordSet)
	activePodOutChains := npc.activeRecordSetPool.Get().(*activeRecordSet)

	podsProtocols := &hostnet.ProtocolMapType{}

	forward := hostnet.NewRuleList()
	output := hostnet.NewRuleList()
	input := hostnet.NewRuleList()
	podOwnChain := hostnet.ChainToRuleListMapType{}

	nodeProcessed := make(map[uint64]PolicyType)

	workerSet := npc.networkPoliciesInfo
	ipTablesAction := hostnet.IPTABLES_FULL_CHAIN_SYNC_NO_ORDER
	if len(inputPolicy) != 0 {
		workerSet = inputPolicy[0]
		ipTablesAction = hostnet.IPTABLES_APPEND_UNIQUE
	}

	// loop through the pods running on the node which to which ingress network policies to be applied
	for _, pol := range workerSet {

		if !pol.policyType.CheckFor(NETWORK_POLICY_INGRESS) || nodeProcessed[pol.meta.hash].CheckFor(NETWORK_POLICY_INGRESS) {
			continue
		}

		podsProtocols.Merge(&pol.targetPods.podsProtocols)
		nodeProcessed[pol.meta.hash] |= NETWORK_POLICY_INGRESS

		// ensure pod specific firewall chain exist for all the pods that need ingress firewall
		podFwChainName := kubePodInChainPrefix.GetFromMeta(pol.meta)
		activePodInChains.Add(podFwChainName)

		if podOwnChain[podFwChainName] == nil {
			podOwnChain[podFwChainName] = hostnet.NewRuleList()
		}

		// ensure statefull firewall, that permits return traffic for the traffic originated by the pod
		comment := "rule for stateful firewall for PODs selector:" + pol.meta.labels.String() + " namespace: " + pol.meta.namespace
		args := []string{"-m", "comment", "--comment", comment, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}
		podOwnChain[podFwChainName].Add(hostnet.NewRuleWithOrder(args...))

		// icmp
		comment = "rule for icmp for PODs selector:" + pol.meta.labels.String() + " namespace: " + pol.meta.namespace
		args = []string{"-m", "comment", "--comment", comment, "-m", "set", "--match-set", kubeICMPIpSet, "src", "-j", "ACCEPT"}
		podOwnChain[podFwChainName].Add(hostnet.NewRuleWithOrder(args...))

		// enable cluster nodes to create IPIP tunnels to pods (Dsr), or coming via tun+ interface in case
		// overlay tunnels are active
		for proto := range pol.targetPods.podsProtocols {
			tunnelProto := hostnet.NewIP(proto).ProtocolCmdParam().TunnelProto
			comment = "rule to permit ipip tunnels for FWMark services from cluster nodes"
			args = []string{"-m", "comment", "--comment", comment, "-m", "set", "--match-set", kubeNodesIpSet, "src", "-p", tunnelProto, "-j", "ACCEPT"}
			podOwnChain[podFwChainName].Add(hostnet.NewRule(args...))
			args = []string{"-m", "comment", "--comment", comment, "-i", "tun+", "-p", tunnelProto, "-j", "ACCEPT"}
			podOwnChain[podFwChainName].Add(hostnet.NewRule(args...))
		}

		// add entries in pod firewall to run through required network policies
		for _, policy := range npc.networkPoliciesInfo {
			if pol.meta.hash == policy.meta.hash && policy.policyType.CheckFor(NETWORK_POLICY_INGRESS) {
				comment := "run through nw policy " + policy.meta.name + " " + policyRuleIngress{}.String()
				policyChainName := kubeNetworkPolicyChainPrefix.Get(policy.meta.namespace, policy.meta.name, policyRuleIngress{}.String())
				if !activeChains.Contains(policyChainName) {
					continue
				}
				podsProtocols.Merge(&policy.targetPods.podsProtocols)
				args := []string{"-m", "comment", "--comment", comment, "-j", policyChainName}
				podOwnChain[podFwChainName].Add(hostnet.NewRule(args...))
			}
		}

		comment = "rule to permit the traffic to pods when source is the pod's local node"
		args = []string{"-m", "comment", "--comment", comment, "-m", "addrtype", "--src-type", "LOCAL", "-j", "ACCEPT"}
		podOwnChain[podFwChainName].Add(hostnet.NewRule(args...))

		// ensure there is rule in filter table and FORWARD chain to jump to pod specific firewall chain
		// this rule applies to the traffic getting routed (coming for other node pods)
		comment = "rule to jump traffic destined to PODs selector:" + pol.meta.labels.String() + " namespace: " + pol.meta.namespace +
			" to chain " + podFwChainName
		args = []string{"-m", "comment", "--comment", comment,
			"-m", "set", "--match-set", kubeTargetIpSetPrefix.GetFromMeta(pol.meta), "dst",
			"-j", podFwChainName}
		forward.Add(hostnet.NewRule(args...))

		// ensure there is rule in filter table and OUTPUT chain to jump to pod specific firewall chain
		// this rule applies to the traffic from a pod getting routed back to another pod on same node by service proxy
		output.Add(hostnet.NewRule(args...))
		input.Add(hostnet.NewRule(args...))

		// ensure there is rule in filter table and forward chain to jump to pod specific firewall chain
		// this rule applies to the traffic getting switched (coming for same node pods)
		comment = "rule to jump traffic destined to PODs selector:" + pol.meta.labels.String() + " namespace: " + pol.meta.namespace +
			" to chain " + podFwChainName
		args = []string{"-m", "physdev", "--physdev-is-bridged",
			"-m", "comment", "--comment", comment,
			"-m", "set", "--match-set", kubeTargetIpSetPrefix.GetFromMeta(pol.meta), "dst",
			"-j", podFwChainName}
		forward.Add(hostnet.NewRule(args...))

		// add default DROP rule at the end of chain
		for _, target := range npc.rejectTargets {
			comment = "default rule to " + target + " traffic from PODs selector: " + pol.meta.labels.String() + " namespace: " + pol.meta.namespace
			args = []string{"-m", "comment", "--comment", comment,
				"-m", "set", "--match-set", kubeTargetIpSetPrefix.GetFromMeta(pol.meta), "dst",
				"-j", target}
			podOwnChain[podFwChainName].Add(hostnet.NewRule(args...))
		}
	}

	// loop through the pods running on the node which egress network policies to be applied
	for _, pol := range workerSet {

		if !pol.policyType.CheckFor(NETWORK_POLICY_EGRESS) || nodeProcessed[pol.meta.hash].CheckFor(NETWORK_POLICY_EGRESS) {
			continue
		}

		podsProtocols.Merge(&pol.targetPods.podsProtocols)
		nodeProcessed[pol.meta.hash] |= NETWORK_POLICY_EGRESS

		// ensure pod specific firewall chain exist for all the pods that need egress firewall
		podFwChainName := kubePodOutChainPrefix.GetFromMeta(pol.meta)
		activePodOutChains.Add(podFwChainName)

		if podOwnChain[podFwChainName] == nil {
			podOwnChain[podFwChainName] = hostnet.NewRuleList()
		}

		// ensure statefull firewall, that permits return traffic for the traffic originated by the pod
		comment := "rule for stateful firewall for PODs selector:" + pol.meta.labels.String() + " namespace: " + pol.meta.namespace
		args := []string{"-m", "comment", "--comment", comment, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}
		podOwnChain[podFwChainName].Add(hostnet.NewRuleWithOrder(args...))

		// add entries in pod firewall to run through required network policies
		for _, policy := range npc.networkPoliciesInfo {
			if pol.meta.hash == policy.meta.hash && policy.policyType.CheckFor(NETWORK_POLICY_EGRESS) {
				comment := "run through nw policy " + policy.meta.name + " " + policyRuleEgress{}.String()
				policyChainName := kubeNetworkPolicyChainPrefix.Get(policy.meta.namespace, policy.meta.name, policyRuleEgress{}.String())
				if !activeChains.Contains(policyChainName) {
					continue
				}
				podsProtocols.Merge(&policy.targetPods.podsProtocols)
				args = []string{"-m", "comment", "--comment", comment, "-j", policyChainName}
				podOwnChain[podFwChainName].Add(hostnet.NewRule(args...))
			}
		}

		// ensure there is rule in filter table and FORWARD chain to jump to pod specific firewall chain
		// this rule applies to the traffic getting routed (coming for other node pods)
		comment = "rule to jump traffic from PODs selector:" + pol.meta.labels.String() + " namespace: " + pol.meta.namespace +
			" to chain " + podFwChainName
		args = []string{"-m", "comment", "--comment", comment,
			"-m", "set", "--match-set", kubeTargetIpSetPrefix.GetFromMeta(pol.meta), "src",
			"-j", podFwChainName}
		forward.Add(hostnet.NewRule(args...))

		// ensure there is rule in filter table and forward chain to jump to pod specific firewall chain
		// this rule applies to the traffic getting switched (coming for same node pods)
		comment = "rule to jump traffic from PODs selector:" + pol.meta.labels.String() + " namespace: " + pol.meta.namespace +
			" to chain " + podFwChainName
		args = []string{"-m", "physdev", "--physdev-is-bridged",
			"-m", "comment", "--comment", comment,
			"-m", "set", "--match-set", kubeTargetIpSetPrefix.GetFromMeta(pol.meta), "src",
			"-j", podFwChainName}
		forward.Add(hostnet.NewRule(args...))

		// add default DROP rule at the end of chain
		for _, target := range npc.rejectTargets {
			comment = "default rule to " + target + " traffic from PODs selector: " + pol.meta.labels.String() + " namespace: " + pol.meta.namespace
			args = []string{"-m", "comment", "--comment", comment,
				"-m", "set", "--match-set", kubeTargetIpSetPrefix.GetFromMeta(pol.meta), "src",
				"-j", target}
			podOwnChain[podFwChainName].Add(hostnet.NewRule(args...))
		}
	}

	if err, rules := podsProtocols.ForEachCreateRulesWithChain(npc.Ipm, "filter", "", hostnet.IPTABLES_FULL_CHAIN_SYNC_NO_ORDER,
		true, podOwnChain); err != nil {
		return activePodInChains, activePodOutChains, err
	} else {
		metricsData.rules += rules
	}

	if err, _ := podsProtocols.ForEachCreateRulesWithChain(
		npc.Ipm, "filter", string(kubeOutputPreprocessChain),
		ipTablesAction, true, output, hostnet.ReferenceFromType{In: "OUTPUT", Pos: 1}); err != nil {

		return activePodInChains, activePodOutChains, err
	}
	metricsData.rules += output.Size() * len(*podsProtocols)

	if err, _ := podsProtocols.ForEachCreateRulesWithChain(
		npc.Ipm, "filter", string(kubeInputPreprocessChain),
		ipTablesAction, true, input, hostnet.ReferenceFromType{In: "INPUT", Pos: 1}); err != nil {

		return activePodInChains, activePodOutChains, err
	}
	metricsData.rules += input.Size() * len(*podsProtocols)

	if err, _ := podsProtocols.ForEachCreateRulesWithChain(
		npc.Ipm, "filter", string(kubeForwardPreprocessChain),
		ipTablesAction, true, forward, hostnet.ReferenceFromType{In: hostnet.CHAIN_KUBE_COMMON_FORWARD}); err != nil {

		return activePodInChains, activePodOutChains, err
	}
	metricsData.rules += forward.Size() * len(*podsProtocols)
	return activePodInChains, activePodOutChains, nil
}

func (ma *activeRecordSet) contains(a, b string) bool {
	return !ma.activeRecordMapType[a] && !ma.activeRecordMapType[b]
}

func (npc *NetworkPolicyController) cleanupObsoleteResources(ipsets, chains []string) {
	for _, chainPrefix := range chains {
		npc.cleanupChains(chainPrefix, cmp.Comparer((&activeRecordSet{}).contains))
	}
	npc.cleanupIpSets(&activeRecordSet{}, ipsets)
}

func (npc *NetworkPolicyController) cleanupChains(chainPrefix string, comparer cmp.Option) {
	hostnet.UsedTcpProtocols.ForEach(func(proto hostnet.Proto) error {
		return npc.Ipm.IptablesCleanUpChainWithComparer(proto, chainPrefix, true,
			cmp.FilterValues(tools.SymmetricHasPrefix, comparer), "filter")
	})
}

func (npc *NetworkPolicyController) cleanupIpSets(activePolicyIPSets *activeRecordSet, prefixToClean []string) error {
	start := time.Now()
	defer glog.Infof("CleanupIpSets policy chains took %v", time.Since(start))

	if npc.cfgCheck.GetForceNextRun(npc) {
		return nil
	}

	setsToClean, err := hostnet.NewIPSet().SaveSimpleList()
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
		if strings.HasSuffix(name, hostnet.TmpTableSuffix) {
			name = name[:len(name)-1]
		}
		if !activePolicyIPSets.Contains(name) {
			npc.ipSetHandler.Destroy(name)
		}
	}
	return nil
}

func (npc *NetworkPolicyController) cleanupStaleRules(activePolicyChains, activePodInChains,
	activePodOutChains, activePolicyIPSets *activeRecordSet) error {

	start := time.Now()
	defer glog.Infof("Syncing cleanupStaleRules policy chains took %v", time.Since(start))

	npc.cleanupChains(kubeNetworkPolicyChainPrefix.String(), cmp.Comparer(activePolicyChains.contains))

	npc.cleanupChains(kubePodInChainPrefix.String(), cmp.Comparer(activePodInChains.contains))
	npc.cleanupChains(kubePodOutChainPrefix.String(), cmp.Comparer(activePodOutChains.contains))

	npc.cleanupIpSets(activePolicyIPSets, []string{"KUBE-TGT"})

	npc.activeRecordSetPool.Put(activePolicyChains.Reset())
	npc.activeRecordSetPool.Put(activePodInChains.Reset())
	npc.activeRecordSetPool.Put(activePodOutChains.Reset())
	npc.activeRecordSetPool.Put(activePolicyIPSets.Reset())
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

func (npc *NetworkPolicyController) buildNetworkPoliciesInfo() (networkPolicyInfoListType, error) {
	start := time.Now()
	defer glog.Infof("Syncing buildNetworkPoliciesInfo policy chains took %v", time.Since(start))

	NetworkPolicies := make(networkPolicyInfoListType)

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
			hash:      tools.GetHash64(policy.Namespace + labels.FormatLabels(policy.Spec.PodSelector.MatchLabels)),
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
	var namespaces = []*k8sapi.Namespace{{ObjectMeta: v1.ObjectMeta{Name: policy.Namespace}}}
	var podSelectorLabels = labels.Everything()
	var matchingPods = podListType{podsProtocols: hostnet.ProtocolMapType{}, pods: &podListMapType{}}

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
	matchingPods := podListType{podsProtocols: hostnet.ProtocolMapType{}, portNameToPort: &nameToPortType{}, pods: &podListMapType{}}
	for _, namespacePod := range npc.ListPodsByNamespaceAndLabels(namespace, selector) {
		podInfo := podInfo{}.fromApi(namespacePod)
		matchingPods.Add(podInfo)

		npc.getPortNameToPortMap(matchingPods.portNameToPort, namespacePod)

		if namespacePod.Status.PodIP == "" {
			continue
		}

		matchingPods.podsProtocols[hostnet.NewIP(namespacePod.Status.PodIP).Protocol()] = true
		if !matchingPods.hasPodsLocally && npc.GetNodeIP().IP.Equal(hostnet.NewIP(namespacePod.Status.HostIP).ToIP()) {
			matchingPods.hasPodsLocally = true
		}
		podInfo.AppendIPs(hostnet.NewIPNetList(npc.getExternalIP(labels.Set(namespacePod.Labels), namespace))...)
	}
	return &matchingPods
}

func (npc *NetworkPolicyController) getPortNameToPortMap(out *nameToPortType, pod *k8sapi.Pod) {
	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			(*out)[port.Name] = port.ContainerPort
		}
	}
}

func (npc *NetworkPolicyController) ListPodsByNamespaceAndLabels(namespace string, selector labels.Selector) (ret []*k8sapi.Pod) {
	allMatchedNameSpacePods, err := listers.NewPodLister(npc.podLister).Pods(namespace).List(selector)
	if err != nil {
		glog.Error("Failed to build network policies info due to " + err.Error())
		return
	}
	return allMatchedNameSpacePods
}

func (npc *NetworkPolicyController) ListNamespaceByLabels(selector labels.Selector) []*k8sapi.Namespace {
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

	ipBlock = append(ipBlock, append(parseCIDR(peer.IPBlock.CIDR, hostnet.OptionTimeout, "0"))...)
	for _, except := range peer.IPBlock.Except {
		ipBlock = append(ipBlock, append(parseCIDR(except, hostnet.OptionTimeout, "0", hostnet.OptionNoMatch))...)
	}

	return
}

func parseCIDR(cidr string, options ...string) [][]string {
	if strings.HasSuffix(cidr, "/0") {
		if hostnet.NewIP(cidr).IsIPv4() {
			return [][]string{append([]string{"0.0.0.0/1"}, options...), append([]string{"128.0.0.0/1"}, options...)}
		} else {
			return [][]string{append([]string{"::/1"}, options...), append([]string{"8000::/1"}, options...)}
		}
	}
	return [][]string{append([]string{cidr}, options...)}
}

func (npc *NetworkPolicyController) buildBetaNetworkPoliciesInfo() (networkPolicyInfoListType, error) {

	NetworkPolicies := make(networkPolicyInfoListType)

	for _, policyObj := range npc.npLister.List() {

		policy, _ := policyObj.(*apiextensions.NetworkPolicy)

		newPolicy := &networkPolicyInfo{
			meta: &networkPolicyMetadata{
				name:      policy.Name,
				namespace: policy.Namespace,
				labels:    policy.Spec.PodSelector.MatchLabels,
				hash:      tools.GetHash64(policy.Namespace + labels.FormatLabels(policy.Spec.PodSelector.MatchLabels)),
			},
		}

		newPolicy.targetPods = npc.ListPodInfoByNamespaceAndLabels(policy.Namespace, newPolicy.meta.labels.AsSelector())

		for _, specIngressRule := range policy.Spec.Ingress {
			ingressRule := &networkPolicyType{}

			for _, port := range specIngressRule.Ports {
				protocolAndPort := newProtocolAndPort(&networking.NetworkPolicyPort{port.Protocol, port.Port})
				ingressRule.AddPorts(protocolAndPort)
			}

			for _, peer := range specIngressRule.From {
				ingressRule.AddPods(npc.ListPodInfoByNamespaceAndLabels(policy.Namespace, labels.SelectorFromSet(peer.PodSelector.MatchLabels)))
			}
			newPolicy.ingressRules.Add(ingressRule)
		}
		NetworkPolicies.Add(newPolicy)
	}

	return NetworkPolicies, nil
}

func (p kubePolPrefixType) String() string {
	return string(p)
}

func (p kubePolPrefixType) GetFromMeta(meta *networkPolicyMetadata) string {
	return p.getInternal(meta.hash)
}

func (p kubePolPrefixType) Get(i ...interface{}) string {
	return p.getInternal(tools.GetHash64(fmt.Sprint(i...)))
}

func (p kubePolPrefixType) getInternal(hash uint64) string {
	return string(p) + fmt.Sprintf("%0.16X", hash)
}

// Cleanup cleanup configurations done
func (npc *NetworkPolicyController) Cleanup() {

	glog.Info("Cleaning up iptables configuration permanently done by kube-router")

	for p := range hostnet.UsedTcpProtocols {
		npc.Ipm.IptablesCleanUpChainWithComparer(p, kubePodInChainPrefix.String(), true, cmp.Comparer(tools.SymmetricHasPrefix))
		npc.Ipm.IptablesCleanUpChainWithComparer(p, kubePodOutChainPrefix.String(), true, cmp.Comparer(tools.SymmetricHasPrefix))
		npc.Ipm.IptablesCleanUpChainWithComparer(p, kubeNetworkPolicyChainPrefix.String(), true, cmp.Comparer(tools.SymmetricHasPrefix))
	}

	npc.cleanupObsoleteResources([]string{}, kubeCleanupChainPrefix)

	// delete all ipsets
	ipset := hostnet.NewIPSet()

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
			newPoObj := newObj.(*k8sapi.Pod)
			oldPoObj := oldObj.(*k8sapi.Pod)
			if newPoObj.Status.Phase != oldPoObj.Status.Phase && newPoObj.Status.Phase != k8sapi.PodSucceeded || newPoObj.Status.PodIP != oldPoObj.Status.PodIP {
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

func (npc *NetworkPolicyController) newNodesEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			npc.syncNodesIPSet()
		},
		UpdateFunc: func(oldObj, newObj interface{}) {},
		DeleteFunc: func(obj interface{}) {
			npc.syncNodesIPSet()
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

func (npc *NetworkPolicyController) syncNodesIPSet() (err error) {
	currentNodes := make([]string, 0)
	for _, node := range api.GetAllClusterNodes(npc.nodeLister) {
		nodeIP := api.GetNodeIP(&node)
		currentNodes = append(currentNodes, nodeIP.String())
	}

	if set, errSet := npc.ipSetHandler.GetOrCreate(kubeNodesIpSet, hostnet.TypeHashIP, hostnet.OptionTimeout, "0"); errSet != nil {
		err = errors.New("Failed to create ipset " + kubeNodesIpSet)
	} else {
		set.RefreshAsync(currentNodes)
	}

	if err != nil {
		glog.Error(err)
	}
	return err
}

func (npc *NetworkPolicyController) getExternalIP(labels labels.Labels, namespace string) (eips []string) {
	objs, _ := npc.getSvcFromPodLabels(labels, namespace)
	for _, svc := range objs {
		eips = append(eips, svc.Spec.ExternalIPs...)
		for _, lbIngress := range svc.Status.LoadBalancer.Ingress {
			if len(lbIngress.IP) > 0 {
				eips = append(eips, lbIngress.IP)
			}
		}
	}
	return
}

func (npc *NetworkPolicyController) getSvcFromPodLabels(podLabels labels.Labels, namespace string) (item []*k8sapi.Service, err error) {
	for _, obj := range npc.svcLister.List() {
		svc := obj.(*k8sapi.Service)
		if svc.Namespace == namespace && labels.SelectorFromSet(svc.Spec.Selector).Matches(podLabels) {
			item = append(item, svc)
		}
	}
	return item, nil
}

// NewNetworkPolicyController returns new NetworkPolicyController object
func NewNetworkPolicyController(config *options.KubeRouterConfig,
	podInformer, npInformer, nsInformer, epInformer, svcInformer, nodeInformer cache.SharedIndexInformer) controllers.ControllerType {
	npc := NetworkPolicyController{
		activeRecordSetPool: &sync.Pool{New: func() interface{} {
			return &activeRecordSet{activeRecordMapType: make(activeRecordMapType)}
		}},
	}

	npc.Init("Policy controller", config.IPTablesSyncPeriod, config, npc.run)

	if config.MetricsEnabled {
		//GetData the metrics for this controller
		prometheus.MustRegister(metrics.ControllerIptablesSyncTime)
		prometheus.MustRegister(metrics.ControllerPolicyChainsSyncTime)
		npc.MetricsEnabled = true
	}

	if config.LogRejects {
		npc.rejectTargets = []string{"LOG", "REJECT"}
	} else {
		npc.rejectTargets = []string{"REJECT"}
	}

	npc.v1NetworkPolicy = true
	v, _ := npc.GetConfig().ClientSet.Discovery().ServerVersion()
	valid := regexp.MustCompile("[0-9]")
	v.Minor = strings.Join(valid.FindAllString(v.Minor, -1), "")
	minorVer, _ := strconv.Atoi(v.Minor)
	if v.Major == "1" && minorVer < 7 {
		npc.v1NetworkPolicy = false
	}

	npc.Ipm = hostnet.NewIpTablesManager(npc.GetNodeIP().IP)

	npc.ipSetHandler = hostnet.NewIPSet()
	npc.ipSetHandler.Save()

	npc.epLister = epInformer.GetIndexer()
	npc.svcLister = svcInformer.GetIndexer()

	npc.podLister = podInformer.GetIndexer()
	npc.PodEventHandler = npc.newPodEventHandler()
	podInformer.AddEventHandler(npc.PodEventHandler)

	npc.nsLister = nsInformer.GetIndexer()
	npc.NamespaceEventHandler = npc.newNamespaceEventHandler()
	nsInformer.AddEventHandler(npc.NamespaceEventHandler)

	npc.npLister = npInformer.GetIndexer()
	npc.NetworkPolicyEventHandler = npc.newNetworkPolicyEventHandler()
	npInformer.AddEventHandler(npc.NetworkPolicyEventHandler)

	npc.nodeLister = nodeInformer.GetIndexer()
	npc.NodesEventHandler = npc.newNodesEventHandler()
	nodeInformer.AddEventHandler(npc.NodesEventHandler)

	return &npc
}
