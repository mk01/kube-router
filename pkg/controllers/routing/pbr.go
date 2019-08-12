package routing

import (
	"github.com/cloudnativelabs/kube-router/pkg/helpers/api"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/hostnet"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/tools"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"os/exec"
	"strings"
)

var customRouteTable hostnet.RouteTableMapType

// setup a custom routing table that will be used for policy based routing to ensure traffic originating
// on tunnel interface only leaves through tunnel interface irrespective rp_filter enabled/disabled
func (nrc *NetworkRoutingController) setupPolicyBasedRouting(enabled bool) error {
	cidr, err := api.GetPodCidrFromNodeSpec(nrc.GetConfig().ClientSet, nrc.GetConfig().HostnameOverride)
	if err != nil {
		return err
	}

	glog.V(1).Infof("IPIP Tunnel Overlay %v in configuration.", enabled)
	customRouteTable = hostnet.RouteTableMapType{
		customRouteTableName: hostnet.RouteTableType{
			Desc:        "Setting up policy routing required overlays setup.",
			Id:          customRouteTableID,
			Name:        customRouteTableName,
			ForChecking: hostnet.RouteTableCheck{Cmd: []string{"rule", "list"}, Output: "lookup " + customRouteTableName},
			Cmd:         []string{"rule", "add", "from", cidr.String(), "lookup", customRouteTableName},
			CmdDisable:  []string{"rule", "del", "from", cidr.String(), "lookup", customRouteTableName},
			ForProto:    hostnet.ProtocolMapType{hostnet.NewIP(cidr).Protocol(): true},
		},
	}
	nrc.rtm = hostnet.NewRouteTableManager(&customRouteTable)
	return nrc.rtm.Setup(enabled)
}

func (nrc *NetworkRoutingController) cleanUpOverlayRules() error {
	return hostnet.UsedTcpProtocols.ForEach(nrc.cleanUpOverlayRulesProto)
}

func (nrc *NetworkRoutingController) cleanUpOverlayRulesProto(protocol hostnet.Proto) error {
	hasError := false
	cidr, err := api.GetPodCidrFromNodeSpec(nrc.GetConfig().ClientSet, nrc.GetConfig().HostnameOverride)
	if err != nil {
		return err
	}
	out, err := exec.Command(tools.GetExecPath("ip"), hostnet.NewIP(protocol).ProtocolCmdParam().Inet, "rule").CombinedOutput()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			rule := strings.Fields(line)
			if tools.CheckForElementInArray(customRouteTableName, rule) && !tools.CheckForElementInArray(cidr.String(), rule) {
				if err = exec.Command(tools.GetExecPath("ip"), hostnet.NewIP(protocol).ProtocolCmdParam().Inet, "rule", "del", "pref", rule[0][:len(rule[0])-1]).Run(); err != nil {
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
