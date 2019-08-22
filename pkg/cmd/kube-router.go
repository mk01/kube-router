package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"

	"github.com/cloudnativelabs/kube-router/pkg/controllers"
	"github.com/cloudnativelabs/kube-router/pkg/controllers/netpol"
	"github.com/cloudnativelabs/kube-router/pkg/controllers/proxy"
	"github.com/cloudnativelabs/kube-router/pkg/controllers/routing"
	"github.com/cloudnativelabs/kube-router/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/golang/glog"

	"github.com/cloudnativelabs/kube-router/pkg/helpers/async_worker"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/hostnet"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"net"
	"time"
)

// These get set at build time via -ldflags magic
var version string
var buildDate string

// KubeRouter holds the information needed to run server
type KubeRouter struct {
	Config *options.KubeRouterConfig
	hc     *healthcheck.HealthController
}

// NewKubeRouterDefault returns a KubeRouter object
func NewKubeRouterDefault(config *options.KubeRouterConfig) (*KubeRouter, error) {

	var clientconfig *rest.Config
	var err error
	PrintVersion(true)
	// Use out of cluster config if the URL or kubeconfig have been specified. Otherwise use incluster config.
	if len(config.Master) != 0 || len(config.Kubeconfig) != 0 {
		clientconfig, err = clientcmd.BuildConfigFromFlags(config.Master, config.Kubeconfig)
		if err != nil {
			return nil, errors.New("Failed to build configuration from CLI: " + err.Error())
		}
	} else {
		clientconfig, err = rest.InClusterConfig()
		if err != nil {
			return nil, errors.New("unable to initialize inclusterconfig: " + err.Error())
		}
	}

	clientset, err := kubernetes.NewForConfig(clientconfig)
	if err != nil {
		return nil, errors.New("Failed to create Kubernetes client: " + err.Error())
	}

	config.ClientSet = clientset
	config.NodeInfo.InitCommons(config)
	return &KubeRouter{Config: config}, nil
}

// CleanupConfigAndExit performs Cleanup on all three controllers
func CleanupConfigAndExit() {
	ipm := hostnet.NewIpTablesManager(net.IP{})

	npc := netpol.NetworkPolicyController{Ipm: ipm}
	npc.Cleanup()

	nsc := proxy.NetworkServicesController{Ipm: ipm}
	nsc.Cleanup()

	nrc := routing.NetworkRoutingController{Ipm: ipm}
	nrc.Cleanup()
}

// Run starts the controllers and waits forever till we get SIGINT or SIGTERM
func (kr *KubeRouter) Run() error {
	var err error
	var wg sync.WaitGroup
	healthChan := make(chan *controllers.ControllerHeartbeat, 10)
	defer close(healthChan)
	stopCh := make(chan struct{})

	if !(kr.Config.RunFirewall || kr.Config.RunServiceProxy || kr.Config.RunRouter) {
		glog.Info("Router, Firewall or Service proxy functionality must be specified. Exiting!")
		os.Exit(0)
	}

	kr.Config.KubeRouterPid = os.Getpid()

	kr.hc = healthcheck.NewHealthController(healthChan, kr.Config)
	go kr.hc.Run(stopCh, &wg, kr.hc)

	informerFactory := informers.NewSharedInformerFactory(kr.Config.ClientSet, 0)
	svcInformer := informerFactory.Core().V1().Services().Informer()
	epInformer := informerFactory.Core().V1().Endpoints().Informer()
	podInformer := informerFactory.Core().V1().Pods().Informer()
	nodeInformer := informerFactory.Core().V1().Nodes().Informer()
	nsInformer := informerFactory.Core().V1().Namespaces().Informer()
	npInformer := informerFactory.Networking().V1().NetworkPolicies().Informer()
	informerFactory.Start(stopCh)

	err = kr.CacheSyncOrTimeout(informerFactory, stopCh)
	if err != nil {
		return errors.New("Failed to synchronize cache: " + err.Error())
	}

	if kr.Config.MetricsPort > 0 {
		kr.Config.MetricsEnabled = true
		go metrics.NewMetricsController(kr.Config).Run(stopCh, &wg, kr.hc)
	}

	if kr.Config.RunFirewall {
		go netpol.NewNetworkPolicyController(kr.Config, podInformer, npInformer, nsInformer, epInformer, svcInformer, nodeInformer).
			Run(stopCh, &wg, kr.hc)
	}

	if kr.Config.BGPGracefulRestart {
		if kr.Config.BGPGracefulRestartDeferralTime > time.Hour*18 {
			return errors.New("BGPGracefuleRestartDeferralTime should be less than 18 hours")
		}
		if kr.Config.BGPGracefulRestartDeferralTime <= 0 {
			return errors.New("BGPGracefuleRestartDeferralTime must be positive")
		}
	}

	if kr.Config.RunRouter {
		go routing.NewNetworkRoutingController(kr.Config, nodeInformer, svcInformer, epInformer).Run(stopCh, &wg, kr.hc)
	}

	if kr.Config.RunServiceProxy {
		go proxy.NewNetworkServicesController(kr.Config, svcInformer, epInformer, podInformer, nodeInformer).Run(stopCh, &wg, kr.hc)
	}

	// Handle SIGINT and SIGTERM
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch

	glog.Infof("Shutting down the controllers")
	close(stopCh)

	wg.Wait()
	async_worker.GlobalManager.StopWorkerManager()
	return nil
}

// CacheSync performs cache synchronization under timeout limit
func (kr *KubeRouter) CacheSyncOrTimeout(informerFactory informers.SharedInformerFactory, stopCh <-chan struct{}) error {
	syncOverCh := make(chan struct{})
	go func() {
		informerFactory.WaitForCacheSync(stopCh)
		close(syncOverCh)
	}()

	select {
	case <-time.After(kr.Config.CacheSyncTimeout):
		return errors.New(kr.Config.CacheSyncTimeout.String() + " timeout")
	case <-syncOverCh:
		return nil
	}
}

func PrintVersion(logOutput bool) {
	output := fmt.Sprintf("Running %v version %s, built on %s, %s\n", os.Args[0], version, buildDate, runtime.Version())

	if !logOutput {
		fmt.Fprintf(os.Stderr, output)
	} else {
		glog.Info(output)
	}
}
