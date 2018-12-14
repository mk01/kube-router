package routing

import (
	"fmt"

	"github.com/cloudnativelabs/kube-router/pkg/utils/net-tools"
	"github.com/golang/glog"
)

// set up MASQUERADE rule so that egress traffic from the pods gets masqueraded to node's IP

type pktDirection string
type ipSetNameValues map[string]int
type orientedIPSetNameValues map[pktDirection]ipSetNameValues

const (
	CHAIN_POD_EGRESS_RULE = "KUBE-ROUTER-POD-EGRESS"

	IPSetSource pktDirection = "src"
	IPSetDest   pktDirection = "dst"
)

var (
	orientedIPSetNameToIntMap = orientedIPSetNameValues{
		IPSetSource: {
			podSubnetsIPSetName: 1 << 31,
			nodeAddrsIPSetName:  1 << 30,
		},
		IPSetDest: {
			podSubnetsIPSetName: 1 << 29,
			nodeAddrsIPSetName:  1 << 28,
		},
	}

	podEgressArgs = netutils.NewRule([]string{"-m", "mark", "--mark",
		fmt.Sprintf("0x%x/0x%x", orientedIPSetNameToIntMap[IPSetSource][podSubnetsIPSetName], orientedIPSetNameToIntMap[IPSetSource][podSubnetsIPSetName]|
			orientedIPSetNameToIntMap[IPSetDest][podSubnetsIPSetName]|orientedIPSetNameToIntMap[IPSetDest][nodeAddrsIPSetName]),
		"!", "-o", "tun-+", "-j", netutils.CHAIN_KUBE_SNAT_TARGET}).AsList()

	podEgressObsoleteChains = []string{"KUBE-ROUTER-BGP-SNAT", "KUBE-ROUTER-BGP-EGRESS-NEW", "KUBE-ROUTER-HAIRPINOLD", "KUBE-ROUTER-HAIRPINOLD"}
)

func (nrc *NetworkRoutingController) createPodEgressRule(protocol netutils.Proto, action netutils.IpTableManipulationType) error {
	nrc.setupMangleRules(protocol, action)
	return nrc.ipm.CreateIpTablesRuleWithChain(protocol, "nat", CHAIN_POD_EGRESS_RULE, action, []string{"POSTROUTING"}, true, podEgressArgs)
}

func (nrc *NetworkRoutingController) deletePodEgressRule(protocol netutils.Proto) error {
	return nrc.ipm.IptablesCleanUpChain(protocol, CHAIN_POD_EGRESS_RULE, true)
}

func (nrc *NetworkRoutingController) deleteBadPodEgressRules(protocol netutils.Proto) error {
	for _, chain := range podEgressObsoleteChains {
		if err := nrc.ipm.IptablesCleanUpChain(protocol, chain, true); err != nil {
			glog.Errorf("Error cl")
		}
	}
	return nil
}

func (nrc *NetworkRoutingController) setupMangleRules(protocol netutils.Proto, action netutils.IpTableManipulationType) {
	nrc.ipm.CreateIpTablesRuleWithChain(protocol, "mangle", CHAIN_POD_EGRESS_RULE, action, []string{"FORWARD"}, true, nil)

	rules := make(netutils.IpTablesRuleListType, 0)
	for _, dir := range []pktDirection{IPSetSource, IPSetDest} {
		for ipSetName, ipSetNamedValue := range orientedIPSetNameToIntMap[dir] {
			rules = append(rules, netutils.NewRule([]string{"-m", "set", "--match-set", ipSetName, fmt.Sprint(dir), "-j", "MARK", "--or-mark", fmt.Sprint(ipSetNamedValue)}))
		}
	}

	nrc.ipm.CreateIpTablesRuleWithChain(protocol, "mangle", CHAIN_POD_EGRESS_RULE, netutils.IPTABLES_FULL_CHAIN_SYNC, []string{"FORWARD"}, false, rules)
}
