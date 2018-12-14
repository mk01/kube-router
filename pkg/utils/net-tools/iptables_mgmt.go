package netutils

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/coreos/go-iptables/iptables"
	"github.com/golang/glog"
	"os/exec"
)

var UsedTcpProtocols = []Proto{V4, V6}

type Proto iptables.Protocol

const (
	V4 = Proto(iptables.ProtocolIPv4)
	V6 = Proto(iptables.ProtocolIPv6)
)

type FunctionNoArgsType func(handler *iptables.IPTables, protocol Proto) error

type IpTablesRuleType []string

type IpTablesPtrType *IpTablesRuleType

type IpTablesRuleListType []IpTablesPtrType

type IpTableManipulationType int

const (
	IPTABLES_CLEAR_EXISTING_CHAIN IpTableManipulationType = 1 << iota
	IPTABLES_FULL_CHAIN_SYNC
	IPTABLES_APPEND_UNIQUE
	IPTABLES_APPEND
)

const (
	CHAIN_KUBE_SNAT_TARGET = "KUBE-ROUTER-SNAT"
)

var defaultTables = []string{"filter", "nat", "mangle"}
var NoReferencedChains = make([]string, 0)

type IpTablesManager struct {
	chainsToCleanUp  []string
	iptablesHandler  map[Proto]*iptables.IPTables
	localAddressList []string
}

func NewIpTablesManager(localAddressList []string, cleanupChainsOnStartup []string) *IpTablesManager {
	var ipm IpTablesManager

	ipm.iptablesHandler = make(map[Proto]*iptables.IPTables)
	ipm.localAddressList = localAddressList

	for _, p := range UsedTcpProtocols {
		if handler, err := iptables.NewWithProtocol(iptables.Protocol(p)); err != nil {
			glog.Errorf("Can't create iptables handler: %s", err)
			return nil
		} else {
			ipm.iptablesHandler[p] = handler
			if err = ipm.IptablesStartUp(p, IPTABLES_FULL_CHAIN_SYNC); err != nil {
				glog.Errorf("Can't create SNAT target: %s", err)
				return nil
			}
		}
	}
	for p := range ipm.iptablesHandler {
		for _, ch := range cleanupChainsOnStartup {
			ipm.IptablesCleanUpChain(p, ch, true, defaultTables...)
		}
	}
	return &ipm
}

func (ipm *IpTablesManager) RecordChainForCleanUp(chain string) {
	if !utils.CheckForElementInArray(chain, ipm.chainsToCleanUp) {
		ipm.chainsToCleanUp = append(ipm.chainsToCleanUp, chain)
	}
}

func (ipm *IpTablesManager) BothTCPProtocolsWrapperNoArg(toCall FunctionNoArgsType) error {
	for _, protocol := range UsedTcpProtocols {
		err := toCall(ipm.iptablesHandler[protocol], protocol)
		if err != nil {
			return err
		}
	}
	return nil
}

func (ipm *IpTablesManager) ApplyRules(protocol Proto, table string, chain string, action IpTableManipulationType, rules IpTablesRuleListType) (err error) {
	for i, rule := range rules {
		if len(*rule) < 1 {
			continue
		}
		if err != nil {
			glog.Errorf("error adding records to table %s", err)
			break
		}

		switch action {
		case IPTABLES_APPEND_UNIQUE:
			err = ipm.iptablesHandler[protocol].AppendUnique(table, chain, *rule...)
		case IPTABLES_FULL_CHAIN_SYNC:
			err = ipm.iptablesHandler[protocol].Insert(table, chain, i+1, *rule...)
		default:
			err = ipm.iptablesHandler[protocol].Append(table, chain, *rule...)
		}
	}
	return
}

func (ipm *IpTablesManager) CreateIpTablesRuleWithChain(protocol Proto, table string, chain string, action IpTableManipulationType, referenceIn []string, logError bool, rules IpTablesRuleListType) (err error) {

	chainList, _ := ipm.iptablesHandler[protocol].List(table, chain)
	if len(chainList) == 0 {
		err = ipm.iptablesHandler[protocol].NewChain(table, chain)
	} else if action == IPTABLES_CLEAR_EXISTING_CHAIN {
		err = ipm.iptablesHandler[protocol].ClearChain(table, chain)
	}

	ipm.RecordChainForCleanUp(chain)

	for _, ch := range referenceIn {
		if err != nil {
			glog.Errorf("can't insert reference record %s", err)
			break
		}
		if exists, err := ipm.iptablesHandler[protocol].Exists(table, ch, "-j", chain); err != nil || exists {
			continue
		}
		err = ipm.iptablesHandler[protocol].Insert(table, ch, 1, "-j", chain)
	}

	if err != nil {
		return
	}

	if action == IPTABLES_FULL_CHAIN_SYNC {
		ipm.prepareListForActionObsolete(protocol, table, chain, rules, chainList)
	}

	if len(rules) == 0 {
		return
	}

	return ipm.ApplyRules(protocol, table, chain, action, rules)
}

func (ipm *IpTablesManager) prepareListForActionObsolete(protocol Proto, table, chain string, rules IpTablesRuleListType, currentList []string) (err error) {
	hashList := make(map[uint32]*IpTablesRuleType)
	for i, rule := range rules {
		b := []byte(strings.Join(*rule, ""))
		hash := utils.DoHash(&b)
		if hashList[hash] != nil {
			(rules)[i] = &IpTablesRuleType{}
			continue
		}
		*rules[i] = append(*rules[i], "-m", "comment", "--comment", fmt.Sprintf("ipmHash:%0.8x", hash))
		hashList[hash] = (rules)[i]
	}

	deleted := 0
	for i, rule := range currentList {
		if !strings.HasPrefix(rule, "-A") {
			continue
		}
		split := strings.Split(rule, "ipmHash:")
		if len(split) > 1 {
			hash, _ := strconv.ParseUint(split[1:][0][:8], 16, 32)
			hash32 := uint32(hash)
			if hashList[hash32] != nil {
				*hashList[hash32] = []string{}
				delete(hashList, hash32)
				continue
			}
		}
		if err = ipm.iptablesHandler[protocol].Delete(table, chain, strings.Fields(rule)[2:]...); err != nil {
			err = exec.Command(NewIP(protocol).ProtocolCmdParam().IptCmd, "-t", table, "-D", chain, fmt.Sprint(i-deleted)).Run()
		}
		if err != nil {
			glog.Errorf("Can't remove obsolete rule: %s", err)
			continue
		}
		deleted++
	}
	return
}

func (ipm *IpTablesManager) IptablesStartUp(protocol Proto, action IpTableManipulationType) error {
	var rule IpTablesRuleType
	if protocol == NewIP(ipm.localAddressList[0]).Protocol() {
		rule = []string{"-j", "SNAT", "--to", ipm.localAddressList[0]}
	}
	return ipm.CreateIpTablesRuleWithChain(protocol, "nat", CHAIN_KUBE_SNAT_TARGET, action, NoReferencedChains, true, NewRule(rule).AsList())
}

func (ipm *IpTablesManager) IptablesCleanUp() error {
	return ipm.BothTCPProtocolsWrapperNoArg(FunctionNoArgsType(ipm._IptablesCleanUp))
}

func (ipm *IpTablesManager) _IptablesCleanUp(h *iptables.IPTables, protocol Proto) error {
	for _, chain := range append(ipm.chainsToCleanUp, CHAIN_KUBE_SNAT_TARGET) {
		ipm.IptablesCleanUpChain(protocol, chain, true)
	}
	return nil
}

func (ipm *IpTablesManager) IptablesCleanUpChain(protocol Proto, chain string, shouldLog bool, tables ...string) error {
	if len(tables) == 0 {
		tables = defaultTables
	}

	for _, table := range tables {
		chainList, _ := ipm.iptablesHandler[protocol].ListChains(table)
		if !utils.CheckForElementInArray(chain, chainList) {
			continue
		}

		ipm.iptablesHandler[protocol].ClearChain(table, chain)

		for _, referencingChain := range chainList {
			deleteMatchingRules(ipm.iptablesHandler[protocol], protocol, table, referencingChain, chain, shouldLog)
		}
		if ipm.iptablesHandler[protocol].DeleteChain(table, chain) == nil && shouldLog {
			glog.Infof("Deleted %s chain %s from table %s.", NewIP(protocol).ProtocolCmdParam().IptCmd, chain, table)
		}
	}
	return nil
}

func IptablesCleanRule(protocol Proto, toDelete string, shouldLog bool) error {
	handler, _ := iptables.NewWithProtocol(iptables.Protocol(protocol))

	for _, table := range defaultTables {
		chainList, _ := handler.ListChains(table)
		for _, referencingChain := range chainList {
			deleteMatchingRules(handler, protocol, table, referencingChain, toDelete, shouldLog)
		}
	}
	return nil
}

func deleteMatchingRules(handler *iptables.IPTables, protocol Proto, table string, chain string, toDelete string, shouldLog bool) {
	order := 0
	ruleList, _ := handler.List(table, chain)
	for _, rule := range ruleList {
		args := strings.Fields(rule)
		if args[0] == "-A" {
			order++
			if utils.CheckForElementInArray(toDelete, args) {
				if err := handler.Delete(table, chain, fmt.Sprint(order)); err == nil && shouldLog {
					glog.Infof("Deleted %s rule %s from table %s", NewIP(protocol).ProtocolCmdParam().IptCmd, args[2:], table)
					order--
				} else if shouldLog {
					glog.Errorf("Failed to deleted %s rule %s from table %s with error: %s", NewIP(protocol).ProtocolCmdParam().IptCmd, args[2:], table, err)
				}
			}
		}
	}
}

func (rule *IpTablesRuleType) AsList() IpTablesRuleListType {
	rl := make(IpTablesRuleListType, 0)
	rl = append(rl, rule)
	return rl
}

func NewRule(source []string) *IpTablesRuleType {
	r := IpTablesRuleType(append(source))
	return &r
}
