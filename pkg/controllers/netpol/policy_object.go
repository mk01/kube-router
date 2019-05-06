package netpol

import (
	"fmt"

	"github.com/cloudnativelabs/kube-router/pkg/utils/net-tools"
	"github.com/golang/glog"
	api "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"net"
	"time"
)

type PolicyType byte

const (
	NETWORK_POLICY_NOPOLICY PolicyType = 0
	NETWORK_POLICY_INGRESS  PolicyType = 1
	NETWORK_POLICY_EGRESS   PolicyType = 2
	NETWORK_POLICY_BOTH     PolicyType = 3
)

type infoMapsKeyType types.UID

// internal structure to represent a network policy
type networkPolicyInfo struct {
	meta *networkPolicyMetadata

	// set of pods matching network policy spec podselector label selector
	targetPods *podListType

	// whitelist ingress rules from the network policy spec
	ingressRules policyRuleIngress

	// whitelist egress rules from the network policy spec
	egressRules policyRuleEgress

	// policy type "ingress" or "egress" or "both" as defined by PolicyType in the spec
	policyType PolicyType

	fmt.Stringer
}

type networkPolicyMetadata struct {
	name      string
	namespace string
	labels    labels.Set
	source    *networking.NetworkPolicy
	hash      uint64
}

// internal structure to represent Pod
type podInfo struct {
	ip        []*net.IPNet
	name      string
	namespace string
	uid       infoMapsKeyType

	fmt.Stringer
}

type protocolAndPortListType []*protocolAndPort

type podListMapType map[infoMapsKeyType]*podInfo

type podListType struct {
	podsProtocols  netutils.ProtocolMapType
	pods           *podListMapType
	hasPodsLocally bool
}

type ipBlockListType [][]string

type networkPolicyType struct {
	ports    protocolAndPortListType
	pods     podListType
	ipBlocks ipBlockListType

	policyRuleOperations
	networkPolicyOperations
}

type egress interface {
	policyRuleType
}

type ingress interface {
	policyRuleType
}

type policyRuleOperations interface {
	GetPorts() *protocolAndPortListType
	GetIPBlocks() *ipBlockListType
	GetPods() *podListType

	MatchAllPorts() bool
	MatchAllPeers() bool
	HasIpBlocks() bool
}

type networkPolicyOperations interface {
	asIpTablesRule([]string, func() bool, *netutils.IpTablesRuleListType)
	parsePolicyPorts([]networking.NetworkPolicyPort, *networking.NetworkPolicy) bool
	parsePolicyPeers([]networking.NetworkPolicyPeer, *networking.NetworkPolicy, EvalPodPeer) bool
	parsePolicy(*networking.NetworkPolicy, EvalPodPeer)
}

type policyRuleType interface {
	fmt.Stringer
	getTemplate(templateType, *networkPolicyMetadata, string) *[]string
}

type policyRuleEgress struct {
	networkPolicyListType
	egress
}

type policyRuleIngress struct {
	networkPolicyListType
	ingress
}

type networkPolicyListType struct {
	rules []networkPolicyType
}

type activeRecordMapType map[string]bool

type activeRecordSets struct {
	at activeRecordMapType
}

func (ars activeRecordSets) New() *activeRecordSets {
	(&ars).at = make(activeRecordMapType)
	return &ars
}

func (ars *activeRecordSets) Size() int {
	return len(ars.at)
}

func (ars *activeRecordSets) Add(used string) {
	ars.at[used] = true
}

func (ars *activeRecordSets) Contains(used string) bool {
	return ars.at[used]
}

func (ars *activeRecordSets) ForEach(fn func(args string)) {
	for rs := range ars.at {
		fn(rs)
	}
}

type keyMetrics struct {
	policies, rules int
	chains, ipsets  int
	pods            int

	lastSync time.Duration
	fmt.Stringer
}

/*  for debugging purposes, to be removed when needed
the following data is output from /healthz
*/
func (km keyMetrics) String() string {
	return "= Policies: " + fmt.Sprint(km.policies) + ", Rules: " + fmt.Sprint(km.rules) +
		", Chains: " + fmt.Sprint(km.chains) + ", IPSets: " + fmt.Sprint(km.ipsets) +
		", Pods: " + fmt.Sprint(km.pods) + ", LastSync took: " + km.lastSync.String()
}

func (prl *networkPolicyListType) Add(pr *networkPolicyType) {
	prl.rules = append(prl.rules, *pr)
}

func (npt PolicyType) String() (out string) {
	switch npt {
	case NETWORK_POLICY_BOTH:
		out = "both"
	case NETWORK_POLICY_INGRESS:
		out = "ingress"
	case NETWORK_POLICY_EGRESS:
		out = "egress"
	case NETWORK_POLICY_NOPOLICY:
		out = "nopolicy"
	}
	return out
}

func newProtocolAndPort(port *networking.NetworkPolicyPort) *protocolAndPort {
	out := protocolAndPort{"tcp", "0:65535"}

	if port.Port != nil {
		out.port = fmt.Sprint(port.Port)
	}
	if port.Protocol != nil && *port.Protocol == api.ProtocolUDP {
		out.protocol = "udp"
	}

	return &out
}

func (pi podInfo) fromApi(pod *api.Pod) *podInfo {
	pi.ip = []*net.IPNet{netutils.NewIP(pod.Status.PodIP).ToIPNet()}
	pi.namespace = pod.Namespace
	pi.name = pod.Name
	pi.uid = infoMapsKeyType(pod.UID)
	return &pi
}

func (prl *networkPolicyListType) Get() *networkPolicyListType {
	return prl
}

func (pr *policyRuleEgress) parseEgressPolicy(policy *networking.NetworkPolicy, peerEvaluator EvalPodPeer) (skip bool) {
	for _, egress := range policy.Spec.Egress {
		data := networkPolicyType{}
		if data.parsePolicyPorts(egress.Ports, policy) || data.parsePolicyPeers(egress.To, policy, peerEvaluator) {
			return true
		}
		pr.Add(&data)
	}
	return
}

func (pr *policyRuleIngress) parseIngressPolicy(policy *networking.NetworkPolicy, peerEvaluator EvalPodPeer) (skip bool) {
	for _, ingress := range policy.Spec.Ingress {
		data := networkPolicyType{}
		if data.parsePolicyPorts(ingress.Ports, policy) || data.parsePolicyPeers(ingress.From, policy, peerEvaluator) {
			return true
		}
		pr.Add(&data)
	}
	return
}

func (npi *networkPolicyInfo) parsePolicy(policy *networking.NetworkPolicy, peerEvaluator EvalPodPeer) (skip bool) {
	return npi.egressRules.parseEgressPolicy(policy, peerEvaluator) ||
		npi.ingressRules.parseIngressPolicy(policy, peerEvaluator)
}

type protocolAndPort struct {
	protocol string
	port     string
}

func (npt PolicyType) CheckFor(check PolicyType) bool {
	return npt&check == check
}

func (pr *networkPolicyType) parsePolicyPorts(ports []networking.NetworkPolicyPort, policy *networking.NetworkPolicy) (skip bool) {
	// If this field is empty or missing in the spec, this rule matches all ports
	if err := pr.checkForNamedPorts(&ports); err != nil {
		glog.Errorf("%s/%s - Skipping processing network policy as its unspported yet: %s", policy.Namespace, policy.Name, err.Error())
		return true
	}
	for _, port := range ports {
		protocolAndPort := newProtocolAndPort(&port)
		pr.GetPorts().Add(protocolAndPort)
	}
	return
}

func (pr *networkPolicyType) parsePolicyPeers(peers []networking.NetworkPolicyPeer, policy *networking.NetworkPolicy, peval EvalPodPeer) (skip bool) {
	// If this field is empty or missing in the spec, this rule matches all sources
	for _, peer := range peers {
		if pods := peval(policy, &peer); pods != nil {
			pr.AddPods(pods)
		} else {
			pr.GetIPBlocks().Add(evalIPBlockPeer(&peer)...)
		}
	}
	return
}

func (pr *networkPolicyType) asIpTablesRule(exportTo *netutils.IpTablesRuleListType, template ...string) {

	if !pr.MatchAllPorts() {
		// case where 'ports' details and 'from' details specified in the ingress rule
		for _, portProtocol := range *pr.GetPorts() {
			exportTo.Add(netutils.NewRule(append([]string{"-p", portProtocol.protocol,
				"-m", portProtocol.protocol, "--dport", portProtocol.port}, template...)...))
		}
	} else {
		// case where no 'ports' details specified in the ingress rule but 'from' details specified
		exportTo.Add(netutils.NewRule(template...))
	}
	return
}

func (pp *protocolAndPortListType) Add(port ...*protocolAndPort) {
	*pp = append(*pp, port...)
}

func (pp *protocolAndPortListType) Size() int {
	return len(*pp)
}

func (pd *podListType) Add(pod ...*podInfo) {
	pd.Get().Add(pod...)
}

func (pd *podListType) Size() int {
	return len(*pd.Get())
}

func (pd *podListType) ForEach(f func(*podInfo)) {
	for _, p := range *pd.Get() {
		f(p)
	}
}

func (pd *podListType) AddList(pod *podListType) {
	pod.ForEach(func(p *podInfo) {
		pd.Add(p)
	})
	pd.hasPodsLocally = pd.hasPodsLocally || pod.hasPodsLocally
	pd.podsProtocols.Merge(&pod.podsProtocols)
}

func (pd *podListType) Get() *podListMapType {
	if pd.pods == nil {
		pd.pods = &podListMapType{}
	}
	return pd.pods
}

func (pm *podListMapType) Add(pod ...*podInfo) {
	for _, p := range pod {
		(*pm)[p.uid] = p
	}
}

func (ipb *ipBlockListType) Add(ipBlock ...[]string) {
	*ipb = append(*ipb, ipBlock...)
}

func (ipb *ipBlockListType) Size() int {
	return len(*ipb)
}

func (pr *networkPolicyType) GetPorts() *protocolAndPortListType {
	return &pr.ports
}

func (pr *networkPolicyType) GetPods() *podListMapType {
	return pr.pods.Get()
}

func (pr *networkPolicyType) AddPods(pods *podListType) {
	pods.ForEach(func(info *podInfo) {
		pr.pods.Add(info)
	})
}

func (pr *networkPolicyType) GetIPBlocks() *ipBlockListType {
	return &pr.ipBlocks
}

func (pr *networkPolicyType) MatchAllPorts() bool {
	return len(*pr.GetPorts()) == 0
}

func (pr *networkPolicyType) MatchAllPeers() bool {
	return !pr.HasPods() && !pr.HasIpBlocks()
}

func (pr *networkPolicyType) HasIpBlocks() bool {
	return pr.GetIPBlocks().Size() != 0
}

func (pr *networkPolicyType) HasPods() bool {
	return pr.pods.Size() != 0
}

func (pr policyRuleIngress) String() string {
	return string(networking.PolicyTypeIngress)
}

func (pr policyRuleEgress) String() string {
	return string(networking.PolicyTypeEgress)
}

func (pr *networkPolicyType) String() string {
	return fmt.Sprint(*pr)
}

func (nm *networkPolicyMetadata) String() string {
	return fmt.Sprintf("policy: %s, namespace: %s", nm.name, nm.namespace)
}

func (npl *networkPolicyInfoListType) ForEach(f func(*networkPolicyInfo)) {
	for _, np := range *npl {
		f(np)
	}
}

func (npl *networkPolicyInfoListType) Add(policy *networkPolicyInfo) {
	if policy == nil {
		return
	}
	(*npl)[policy.meta.namespace+policy.meta.name] = policy
}

func (npl *networkPolicyInfoListType) Size() int {
	return len(*npl)
}

func (pi *networkPolicyInfo) checkPod(pod *podInfo) bool {
	if (*pi.targetPods.pods)[pod.uid] != nil {
		return true
	}
	for _, ir := range append(pi.egressRules.rules, pi.ingressRules.rules...) {
		if (*ir.pods.Get())[pod.uid] != nil {
			return true
		}
	}
	return false
}

func (pi *networkPolicyInfo) checkNamespace(ns *api.Namespace) bool {
	if pi.meta.namespace == ns.Name {
		return true
	}

	var lbls labels.Set = ns.Labels
	for _, r := range pi.meta.source.Spec.Ingress {
		for _, s := range r.From {
			if s.NamespaceSelector != nil &&
				labels.SelectorFromSet(s.NamespaceSelector.MatchLabels).Matches(lbls) {
				return true
			}
		}
	}
	return false
}

func (pi *podInfo) String() string {
	return fmt.Sprintf("Namespace: %s, Name: %s, IP: %s\n\tPodSelector: %v", pi.namespace, pi.name, pi.ip, "")
}

func (pd *podListType) String() (out string) {
	i := 0
	pd.ForEach(func(pod *podInfo) {
		out += fmt.Sprintf("#%d UID: %s, %v\n\n", i, pod.uid, pod)
		i++
	})
	return
}

func (npi *networkPolicyInfo) String() (out string) {
	out += fmt.Sprintf("NPI: %s\n", npi.meta)
	out += fmt.Sprintf("targetPods: %v\n", npi.targetPods.String())
	out += "ingres:\n"
	for _, r := range npi.ingressRules.rules {
		out += fmt.Sprintf("     %v\n", r)
	}
	out += "egress:\n"
	for _, r := range npi.egressRules.rules {
		out += fmt.Sprintf("     %v\n", r)
	}
	out += "policyType: " + npi.policyType.String() + "\n"
	return
}
