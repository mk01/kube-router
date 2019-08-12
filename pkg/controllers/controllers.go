package controllers

import (
	"sync"

	"fmt"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/async_worker"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/golang/glog"
	"time"
)

type RunLoopFunction func(<-chan struct{}) error

type RegisterType interface {
	Register(ControllerType)
}

type ControllerType interface {
	GetControllerName() string
	GetSyncPeriod() time.Duration
	GetConfig() *options.KubeRouterConfig

	Run(<-chan struct{}, *sync.WaitGroup, RegisterType)
}

//ControllerHeartbeat is the structure to hold the heartbeats sent by controllers
type ControllerHeartbeat struct {
	Component     ControllerType
	LastHeartBeat time.Time
	Data          fmt.Stringer
}

type Controller struct {
	ControllerType

	prettyName string
	syncPeriod time.Duration
	config     *options.KubeRouterConfig

	options.NodeInfoType

	runLoopFn RunLoopFunction

	async_worker.Manager
}

func (cnt *Controller) Init(name string, period time.Duration, config *options.KubeRouterConfig, fn RunLoopFunction) *Controller {
	cnt.prettyName = name
	cnt.syncPeriod = period
	cnt.config = config
	cnt.NodeInfoType = &config.NodeInfo
	cnt.runLoopFn = fn
	return cnt
}

func (cnt *Controller) GetConfig() *options.KubeRouterConfig {
	return cnt.config
}

func (cnt *Controller) GetControllerName() string {
	return cnt.prettyName
}

func (cnt *Controller) GetSyncPeriod() time.Duration {
	return cnt.syncPeriod
}

func (cnt *Controller) Run(stopCh <-chan struct{}, wg *sync.WaitGroup, hc RegisterType) {
	hc.Register(cnt)

	wg.Add(1)

	glog.Infof("Starting %s", cnt.GetControllerName())
	go func() {
		if err := cnt.runLoopFn(stopCh); err != nil {
			glog.Fatalf("Can't start controller: %s", err.Error())
			return
		}
		cnt.StopWorkerManager()
		glog.Infof("%s stopped", cnt.GetControllerName())
		wg.Done()
	}()
}
