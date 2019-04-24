package netutils

import (
	"fmt"
	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/coreos/go-iptables/iptables"
	"github.com/golang/glog"
	"github.com/google/go-cmp/cmp"
	"os/exec"
	"strconv"
	"strings"
)

const hashTag = "ipmHash:"

type Proto iptables.Protocol

type FunctionNoArgsType func(handler *iptables.IPTables, protocol Proto) error

type IpTablesRuleType struct {
	Args      []string
	keepOrder bool
}

type IpTablesRuleApplyListType struct {
	rules       *IpTablesRuleListType
	noApplyList *map[int]bool
}

type IpTablesRuleListType []*IpTablesRuleType

type PerProtocolRuleListType map[Proto]*IpTablesRuleListType

type IpTableManipulationType int

type IpTablesManager struct {
	chainsToCleanUp  []string
	localAddressList []string
	ipTablesHandler  map[Proto]*iptables.IPTables
}

type IpTablesCleanupRuleType struct {
	RuleContaining []string
	InChain        string
}

type ProtocolMapType map[Proto]bool

type ChainToRuleListMapType map[string]*IpTablesRuleListType

const (
	IPTABLES_CLEAR_EXISTING_CHAIN IpTableManipulationType = 1 << iota
	IPTABLES_FULL_CHAIN_SYNC
	IPTABLES_APPEND_UNIQUE
	IPTABLES_FULL_CHAIN_SYNC_NO_ORDER
)

const (
	CHAIN_KUBE_SNAT_TARGET    = "KUBE-ROUTER-SNAT"
	CHAIN_KUBE_COMMON_FORWARD = "KUBE-ROUTER-FORWARD"
)

const (
	V4 = Proto(iptables.ProtocolIPv4)
	V6 = Proto(iptables.ProtocolIPv6)
)

var defaultTables = []string{"filter", "nat", "mangle"}
var NoReferencedChains = make([]string, 0)
var EmptyIpTablesRuleListType = &IpTablesRuleListType{}

var UsedTcpProtocols = ProtocolMapType{V4: true, V6: true}

var ipmLock *utils.ChannelLockType

func init() {
	ipmLock = utils.NewChanLock(2)
}

func NewIpTablesManager(localAddressList []string, cleanupChainsOnStartup ...IpTablesCleanupRuleType) *IpTablesManager {
	var ipm IpTablesManager

	ipm.localAddressList = localAddressList

	ipm.ipTablesHandler = make(map[Proto]*iptables.IPTables)
	for p := range UsedTcpProtocols {
		if handler, err := iptables.NewWithProtocol(iptables.Protocol(p)); err != nil {
			glog.Fatalf("Can't create iptables handler: %s", err)
		} else {
			ipm.ipTablesHandler[p] = handler
		}
	}

	for p := range UsedTcpProtocols {
		if err := ipm.IptablesStartUp(p, IPTABLES_FULL_CHAIN_SYNC); err != nil {
			glog.Errorf("Can't create SNAT target: %s", err)
			return nil
		}
	}
	for p, h := range ipm.ipTablesHandler {
		for _, ch := range cleanupChainsOnStartup {
			IptablesCleanRule(h, p, ch, true)
		}
	}
	return &ipm
}

func (ipm *IpTablesManager) GetHandler(proto Proto) *iptables.IPTables {
	return ipm.ipTablesHandler[proto]
}

func (ipm *IpTablesManager) RecordChainForCleanUp(chains ...string) {
	for _, chain := range chains {
		if !utils.CheckForElementInArray(chain, ipm.chainsToCleanUp) {
			ipm.chainsToCleanUp = append(ipm.chainsToCleanUp, chain)
		}
	}
}

func (ipm *IpTablesManager) applyRules(protocol Proto, table string, chain string, action IpTableManipulationType, rules *IpTablesRuleApplyListType) (err error) {
	var deleted = 0
	for i, rule := range *rules.rules {
		if err != nil {
			glog.Errorf("error adding records to table %s", err)
			break
		}

		if rules.noApplyList != nil && (*rules.noApplyList)[i] {
			if len(rule.Args) < 1 {
				deleted++
			}
			continue
		}

		switch action {
		case IPTABLES_APPEND_UNIQUE:
			err = ipm.ipTablesHandler[protocol].AppendUnique(table, chain, rule.Args...)
		case IPTABLES_FULL_CHAIN_SYNC:
			fallthrough
		case IPTABLES_FULL_CHAIN_SYNC_NO_ORDER:
			err = ipm.ipTablesHandler[protocol].Insert(table, chain, i+1-deleted, rule.Args...)
		default:
			err = ipm.ipTablesHandler[protocol].Append(table, chain, rule.Args...)
		}
	}
	return
}

func (ipm *IpTablesManager) CreateIpTablesRuleWithChain(protocol Proto, table string, chain string, action IpTableManipulationType, referenceIn []string, logError bool, rules *IpTablesRuleListType) (err error) {
	ipmLock.Lock()
	defer ipmLock.Unlock()
	return ipm.createIpTablesRuleWithChain(protocol, table, chain, action, referenceIn, logError, rules)
}

func (ipm *IpTablesManager) createIpTablesRuleWithChain(protocol Proto, table string, chain string, action IpTableManipulationType, referenceIn []string, logError bool, rules *IpTablesRuleListType) (err error) {
	var applyList *IpTablesRuleApplyListType

	chainList, _ := ipm.ipTablesHandler[protocol].List(table, chain)
	if len(chainList) == 0 {
		err = ipm.ipTablesHandler[protocol].NewChain(table, chain)
	} else if len(chainList) == 1 && (rules == nil || rules.Size() == 0) {
		return
	} else if action == IPTABLES_CLEAR_EXISTING_CHAIN {
		err = ipm.ipTablesHandler[protocol].ClearChain(table, chain)
	}

	ipm.RecordChainForCleanUp(chain)

	for _, ch := range referenceIn {
		if err != nil {
			glog.Errorf("can't insert reference record %s", err)
			break
		}
		if exists, err := ipm.ipTablesHandler[protocol].Exists(table, ch, "-j", chain); err != nil || exists {
			continue
		}
		err = ipm.ipTablesHandler[protocol].Insert(table, ch, 1, "-j", chain)
	}

	if err != nil || rules == nil {
		return
	}

	if action == IPTABLES_FULL_CHAIN_SYNC || action == IPTABLES_FULL_CHAIN_SYNC_NO_ORDER {
		applyList = ipm.prepareListForActionObsolete(protocol, table, chain, action, rules, chainList)
	} else {
		applyList = &IpTablesRuleApplyListType{rules: rules}
	}

	if rules == nil || len(*rules) == 0 {
		return
	}

	return ipm.applyRules(protocol, table, chain, action, applyList)
}

func (ipm *IpTablesManager) prepareListForActionObsolete(protocol Proto, table, chain string, action IpTableManipulationType, rules *IpTablesRuleListType, currentList []string) *IpTablesRuleApplyListType {
	var err error
	var hashList = make(map[uint64]int)
	var noApplyList = make(map[int]bool)

	deleted := 0
	for i, rule := range *rules {
		var hash uint64
		var secondRun bool
		if len(rule.Args) > 3 && strings.HasPrefix(rule.Args[len(rule.Args)-1], hashTag) {
			hash = extractHash(rule.Args[len(rule.Args)-1][len(hashTag):])
			secondRun = true
		} else {
			hash = utils.DoHash64(strings.Join(rule.Args, ""))
		}

		if _, ok := hashList[hash]; ok || len(rule.Args) < 1 {
			noApplyList[i] = true
			(*rules)[i].Args = []string{}
			continue
		}

		hashList[hash] = i

		if secondRun {
			continue
		}
		(*rules)[i].Args = append((*rules)[i].Args, "-m", "comment", "--comment", fmt.Sprintf("ipmHash:%0.16X", hash))
	}

	deleted = 0
	for i, rule := range currentList {
		if !strings.HasPrefix(rule, "-A") {
			continue
		}
		if split := strings.Split(rule, hashTag); len(split) > 1 {
			hash := extractHash(split[1])
			if order, ok := hashList[hash]; ok &&
				(action == IPTABLES_FULL_CHAIN_SYNC_NO_ORDER || !(*rules)[order].keepOrder || order == i-1) {
				noApplyList[order] = true
				delete(hashList, hash)
				continue
			}
		}

		var out []byte
		if err = ipm.ipTablesHandler[protocol].Delete(table, chain, strings.Fields(rule)[2:]...); err != nil {
			out, err = exec.Command(NewIP(protocol).ProtocolCmdParam().IptCmd, "-t", table, "-D", chain, fmt.Sprint(i-deleted)).Output()
		}
		if err != nil {
			glog.Errorf("Can't remove obsolete rule: %s\n%v", err, string(out))
			continue
		}
		deleted++
	}
	return &IpTablesRuleApplyListType{rules: rules, noApplyList: &noApplyList}
}

func (ipm *IpTablesManager) IptablesStartUp(protocol Proto, action IpTableManipulationType) (err error) {
	var rule *IpTablesRuleListType
	if len(ipm.localAddressList) > 0 && protocol == NewIP(ipm.localAddressList[0]).Protocol() {
		rule = &IpTablesRuleListType{&IpTablesRuleType{[]string{"-j", "SNAT", "--to", ipm.localAddressList[0]}, false}}
	}
	err = ipm.CreateIpTablesRuleWithChain(protocol, "nat", CHAIN_KUBE_SNAT_TARGET, action, NoReferencedChains, true, rule)
	if err == nil {
		err = ipm.CreateIpTablesRuleWithChain(protocol, "filter", CHAIN_KUBE_COMMON_FORWARD, IPTABLES_APPEND_UNIQUE, []string{"FORWARD"}, true, EmptyIpTablesRuleListType)
	}
	return
}

func (ipm *IpTablesManager) IptablesCleanUp(chains ...string) error {
	ipm.RecordChainForCleanUp(chains...)
	return UsedTcpProtocols.ForEach(ipm._iptablesCleanUp)
}

func (ipm *IpTablesManager) _iptablesCleanUp(protocol Proto) error {
	for _, chain := range append(ipm.chainsToCleanUp, CHAIN_KUBE_SNAT_TARGET) {
		ipm.iptablesCleanUpChain(protocol, chain, true, ComparerStd)
	}
	return nil
}

func (ipm *IpTablesManager) IptablesCleanUpChainWithComparer(protocol Proto, chain string, shouldLog bool, option cmp.Option, tables ...string) error {
	return ipm.iptablesCleanUpChain(protocol, chain, shouldLog, option, tables...)
}

func (ipm *IpTablesManager) IptablesCleanUpChain(protocol Proto, chain string, shouldLog bool, tables ...string) error {
	return ipm.iptablesCleanUpChain(protocol, chain, shouldLog, ComparerStd, tables...)
}

func (ipm *IpTablesManager) iptablesCleanUpChain(protocol Proto, chain string, shouldLog bool, option cmp.Option, tables ...string) error {
	ipmLock.Lock()
	defer ipmLock.Unlock()

	if len(tables) == 0 {
		tables = defaultTables
	}
	for _, table := range tables {
		chainList, _ := ipm.ipTablesHandler[protocol].ListChains(table)
		if !utils.CheckForElementInArray(chain, chainList, option) {
			continue
		}

		toDelete := make([]string, 0)
		for _, referencingChain := range chainList {
			if cmp.Equal(referencingChain, chain, option) {
				ipm.ipTablesHandler[protocol].ClearChain(table, referencingChain)
				toDelete = append(toDelete, referencingChain)
			}
		}

		for _, deleteIn := range chainList {
			for _, deleteChain := range toDelete {
				deleteMatchingRules(ipm.ipTablesHandler[protocol], protocol, table, deleteIn, deleteChain, shouldLog, option)
			}
		}

		for _, rmChain := range toDelete {
			if ipm.ipTablesHandler[protocol].DeleteChain(table, rmChain) == nil && shouldLog {
				glog.Infof("Deleted %s chain %s from table %s.", NewIP(protocol).ProtocolCmdParam().IptCmd, rmChain, table)
			}
		}
	}
	return nil
}

func IptablesCleanRule(handler *iptables.IPTables, protocol Proto, toDelete IpTablesCleanupRuleType, shouldLog bool) error {
	for _, table := range defaultTables {
		chainList, _ := handler.ListChains(table)
		for _, referencingChain := range chainList {
			if toDelete.InChain != "" && referencingChain != toDelete.InChain {
				continue
			}
			for _, rule := range toDelete.RuleContaining {
				deleteMatchingRules(handler, protocol, table, referencingChain, rule, shouldLog)
			}
		}
	}
	return nil
}

func deleteMatchingRules(handler *iptables.IPTables, protocol Proto, table string, chain string, toDelete string, shouldLog bool, option ...cmp.Option) {
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

func NewPerProtoRuleList() *PerProtocolRuleListType {
	return &PerProtocolRuleListType{V4: &IpTablesRuleListType{}, V6: &IpTablesRuleListType{}}
}

func (rl *IpTablesRuleListType) Add(rule ...*IpTablesRuleType) {
	*rl = append(*rl, rule...)
}

func (rl *IpTablesRuleListType) Size() int {
	return len(*rl)
}

func (rl *IpTablesRuleListType) String() (out string) {
	for i, r := range *rl {
		out += fmt.Sprintf("#%d: %s\n", i, r.Args)
	}
	return
}

func (pl *ProtocolMapType) Merge(apply *ProtocolMapType) {
	for proto := range *apply {
		(*pl)[proto] = true
	}
}

func (pl ProtocolMapType) ForEach(fn func(Proto) error) error {
	for proto := range pl {
		if err := fn(proto); err != nil {
			return err
		}
	}
	return nil
}

func (pl ProtocolMapType) ForEachWithLock(fn func(Proto) error) error {
	ipmLock.Lock()
	defer ipmLock.Unlock()
	return pl.ForEach(fn)
}

func (pl ProtocolMapType) ForEachCreateRulesWithChain(ipm *IpTablesManager, table string, chain string, action IpTableManipulationType,
	referenceIn []string, logError bool, rules interface{}) (err error, processedRules int) {

	ipmLock.Lock()
	defer ipmLock.Unlock()

	var rulesToApply ChainToRuleListMapType
	for proto := range pl {
		switch tRules := rules.(type) {
		case *IpTablesRuleListType:
			rulesToApply = ChainToRuleListMapType{chain: tRules}
		case *PerProtocolRuleListType:
			rulesToApply = ChainToRuleListMapType{chain: (*tRules)[proto]}
		case ChainToRuleListMapType:
			rulesToApply = tRules
		}

		for chainName := range rulesToApply {
			if err = ipm.createIpTablesRuleWithChain(proto, table, chainName, action, referenceIn, logError, rulesToApply[chainName]); err != nil {
				return
			}
			processedRules += len(*rulesToApply[chainName])
		}
	}

	return
}

func NewCleanupRule(limitTo string, chains ...string) IpTablesCleanupRuleType {
	return IpTablesCleanupRuleType{RuleContaining: append(chains), InChain: limitTo}
}

func NewRule(source ...string) *IpTablesRuleType {
	return &IpTablesRuleType{Args: source}
}

func NewRuleWithOrder(source ...string) *IpTablesRuleType {
	return &IpTablesRuleType{Args: source, keepOrder: true}
}

func NewRuleList(rule ...string) *IpTablesRuleListType {
	rl := &IpTablesRuleListType{}
	rl.Add(&IpTablesRuleType{Args: rule})
	return rl
}

var ComparerStd = cmp.Comparer(equals)

func equals(a, b string) bool {
	return a == b
}

func (pr *Proto) String() string {
	if *pr == V4 {
		return "v4"
	}
	return "v6"
}

func extractHash(s string) (hash uint64) {
	hash, _ = strconv.ParseUint(s[:16], 16, 64)
	return
}
