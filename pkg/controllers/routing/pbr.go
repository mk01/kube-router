package routing

import (
	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/cloudnativelabs/kube-router/pkg/utils/net-tools"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"os/exec"
	"strings"
)

var customRouteTable netutils.RouteTableMapType

// setup a custom routing table that will be used for policy based routing to ensure traffic originating
// on tunnel interface only leaves through tunnel interface irrespective rp_filter enabled/disabled
func (nrc *NetworkRoutingController) setupPolicyBasedRouting(enabled bool) error {
	cidr, err := utils.GetPodCidrFromNodeSpec(nrc.clientset, nrc.hostnameOverride)
	if err != nil {
		return err
	}

	glog.V(1).Infof("IPIP Tunnel Overlay %v in configuration.", enabled)
	customRouteTable = netutils.RouteTableMapType{
		customRouteTableName: netutils.RouteTableType{
			Desc:        "Setting up policy routing required overlays setup.",
			Id:          customRouteTableID,
			Name:        customRouteTableName,
			ForChecking: netutils.RouteTableCheck{Cmd: []string{"rule", "list"}, Output: "lookup " + customRouteTableName},
			Cmd:         []string{"rule", "add", "from", cidr.String(), "lookup", customRouteTableName},
			CmdDisable:  []string{"rule", "del", "from", cidr.String(), "lookup", customRouteTableName},
			ForProto:    netutils.ProtocolsType{netutils.NewIP(cidr).Protocol(): true},
		},
	}
	nrc.rtm = netutils.NewRouteTableManager(&customRouteTable)
	return nrc.rtm.Setup(enabled)
}

func (nrc *NetworkRoutingController) cleanUpOverlayRules() error {
	return netutils.UsedTcpProtocols.ForEach(nrc.cleanUpOverlayRulesProto)
}

func (nrc *NetworkRoutingController) cleanUpOverlayRulesProto(protocol netutils.Proto) error {
	hasError := false
	cidr, err := utils.GetPodCidrFromNodeSpec(nrc.clientset, nrc.hostnameOverride)
	if err != nil {
		return err
	}
	out, err := exec.Command(utils.GetPath("ip"), netutils.NewIP(protocol).ProtocolCmdParam().Inet, "rule").CombinedOutput()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			rule := strings.Fields(line)
			if utils.CheckForElementInArray(customRouteTableName, rule) && !utils.CheckForElementInArray(cidr.String(), rule) {
				if err = exec.Command(utils.GetPath("ip"), netutils.NewIP(protocol).ProtocolCmdParam().Inet, "rule", "del", "pref", rule[0][:len(rule[0])-1]).Run(); err != nil {
					glog.Errorf("Failed to clean up wrong overlay rule: %s", err.Error())
					hasError = true
					continue
				}
			}
		}
	}
	if hasError {
		err = errors.New("cleanUpOverlayRulesProto failed")
	}
	return err
}
