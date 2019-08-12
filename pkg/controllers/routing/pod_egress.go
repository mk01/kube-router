package routing

import (
	"fmt"

	"github.com/cloudnativelabs/kube-router/pkg/helpers/hostnet"
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

	podEgressArgs = hostnet.NewRuleList("-m", "mark", "--mark",
		fmt.Sprintf("0x%x/0x%x", orientedIPSetNameToIntMap[IPSetSource][podSubnetsIPSetName], orientedIPSetNameToIntMap[IPSetSource][podSubnetsIPSetName]|
			orientedIPSetNameToIntMap[IPSetDest][podSubnetsIPSetName]|orientedIPSetNameToIntMap[IPSetDest][nodeAddrsIPSetName]),
		"!", "-o", "tun-+", "-j", hostnet.CHAIN_KUBE_SNAT_TARGET)

	podEgressObsoleteChains = hostnet.NewCleanupRule("", "KUBE-ROUTER-BGP-SNAT", "KUBE-ROUTER-BGP-EGRESS-NEW", "KUBE-ROUTER-HAIRPINOLD", "KUBE-ROUTER-HAIRPINOLD")
)

func (nrc *NetworkRoutingController) createPodEgressRule(protocol hostnet.Proto, action hostnet.IpTableManipulationType) error {
	nrc.setupMangleRules(protocol, action)
	return nrc.Ipm.CreateRuleChain(protocol, "nat", CHAIN_POD_EGRESS_RULE, action, true, podEgressArgs, hostnet.ReferenceFromType{In: "POSTROUTING"})
}

func (nrc *NetworkRoutingController) deletePodEgressRule(protocol hostnet.Proto) error {
	return nrc.Ipm.IptablesCleanUpChain(protocol, CHAIN_POD_EGRESS_RULE, true)
}

func (nrc *NetworkRoutingController) setupMangleRules(protocol hostnet.Proto, action hostnet.IpTableManipulationType) {
	rules := make(hostnet.IpTablesRuleListType, 0)
	rules.Add(hostnet.NewRule("-m", "mark", "!", "--mark", "0", "-j", "RETURN"))
	for _, dir := range []pktDirection{IPSetSource, IPSetDest} {
		for ipSetName, ipSetNamedValue := range orientedIPSetNameToIntMap[dir] {
			rules.Add(hostnet.NewRule("-m", "set", "--match-set", ipSetName, fmt.Sprint(dir), "-j", "MARK", "--or-mark", fmt.Sprintf("0x%x", ipSetNamedValue)))
		}
	}

	nrc.Ipm.CreateRuleChain(protocol, "mangle", CHAIN_POD_EGRESS_RULE, hostnet.IPTABLES_FULL_CHAIN_SYNC_NO_ORDER, true, &rules,
		hostnet.ReferenceFromType{In: "FORWARD"},
		hostnet.ReferenceFromType{In: "OUTPUT", Rule: []string{"-o", nrc.GetNodeIF()}})
}
