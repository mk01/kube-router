package hostnet

import (
	"github.com/cloudnativelabs/kube-router/pkg/helpers/async_worker"
	"github.com/golang/glog"
	"time"
)

type IpTablesPeriodicFunction func(*IpTablesManager)

type ipTablesPeriodicTask struct {
	ipm      *IpTablesManager
	fn       IpTablesPeriodicFunction
	interval time.Duration
	nextRun  time.Time
}

var periodicTasks []*ipTablesPeriodicTask

type periodicTaskRunner struct {
	async_worker.Worker
}

func init() {
	async_worker.GlobalManager.AddWorkerRoutine(new(periodicTaskRunner), "IpTablbes Periodic Tasks")
}

func (pr *periodicTaskRunner) StartWorker() {
	go func() {
		for !pr.IsStopped() {
			time.Sleep(time.Second)
			now := time.Now()

			for _, task := range periodicTasks {
				if now.Before(task.nextRun) || pr.IsStopped() {
					continue
				}
				task.fn(task.ipm)
				task.nextRun = now.Add(task.interval)
			}
		}
		glog.V(3).Infof("%s done", pr.GetName())
		pr.Done()
	}()
}

func CreateSnats(ipm *IpTablesManager) {
	glog.V(1).Infof("Ensuring snat targets exists")
	UsedTcpProtocols.ForEach(func(p Proto) (err error) {
		if err = createSnatsPerProto(ipm, p, IPTABLES_FULL_CHAIN_SYNC); err != nil {
			glog.Errorf("Can't create SNAT target: %s", err)
		}
		return err
	})
}

func createSnatsPerProto(ipm *IpTablesManager, protocol Proto, action IpTableManipulationType) (err error) {
	var rule *IpTablesRuleListType
	if protocol == NewIP(ipm.localNodeAddress).Protocol() {
		glog.V(2).Infof("Will create snat target with ip %s", ipm.localNodeAddress.String())
		rule = &IpTablesRuleListType{&IpTablesRuleType{[]string{"-j", "SNAT", "--to", ipm.localNodeAddress.String()}, false}}
	}
	if err = ipm.CreateRuleChain(protocol, "nat", CHAIN_KUBE_SNAT_TARGET, action, true, rule); err == nil {
		err = ipm.CreateRuleChain(protocol, "filter", CHAIN_KUBE_COMMON_FORWARD, IPTABLES_APPEND_UNIQUE, true, EmptyIpTablesRuleListType, ReferenceFromType{In: "FORWARD", Pos: 1})
	}
	return
}

func (ipm *IpTablesManager) CreateLBHealthChecksEnsureRule(table, chain, ref string, rule []string) error {
	glog.V(1).Infof("Ensuring LB health checks rules exists")
	return UsedTcpProtocols.ForEach(func(p Proto) (err error) {
		return ipm.CreateRuleChain(p, table, chain, IPTABLES_FULL_CHAIN_SYNC_NO_ORDER, true, NewRuleList(rule...), ReferenceFromType{In: ref, Pos: 1})
	})
}

func (ipm *IpTablesManager) RegisterPeriodicFunction(fn IpTablesPeriodicFunction, interval ...time.Duration) {
	newTask := &ipTablesPeriodicTask{ipm: ipm, fn: fn}

	if len(interval) > 0 {
		newTask.interval = interval[0]
	} else {
		newTask.interval = 30 * time.Second
	}

	fn(ipm)
	newTask.nextRun = time.Now().Add(newTask.interval)

	periodicTasks = append(periodicTasks, newTask)
}
