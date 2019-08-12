package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/cloudnativelabs/kube-router/pkg/controllers"
	"github.com/cloudnativelabs/kube-router/pkg/healthcheck"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/tools"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	namespace = "kube_router"
)

var (
	defaultBucket = prometheus.ExponentialBuckets(0.005, 2.327, 10)
	fastBucket    = prometheus.ExponentialBuckets(0.001, 2.5, 10)

	// ServiceTotalConn Total incoming connections made
	ServiceTotalConn = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_total_connections",
		Help:      "Total incoming connections made",
	}, []string{"svc_namespace", "service_name", "service_vip", "protocol", "port"})
	// ServicePacketsIn Total incoming packets
	ServicePacketsIn = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_packets_in",
		Help:      "Total incoming packets",
	}, []string{"svc_namespace", "service_name", "service_vip", "protocol", "port"})
	// ServicePacketsOut Total outgoing packets
	ServicePacketsOut = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_packets_out",
		Help:      "Total outgoing packets",
	}, []string{"svc_namespace", "service_name", "service_vip", "protocol", "port"})
	// ServiceBytesIn Total incoming bytes
	ServiceBytesIn = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_bytes_in",
		Help:      "Total incoming bytes",
	}, []string{"svc_namespace", "service_name", "service_vip", "protocol", "port"})
	// ServiceBytesOut Total outgoing bytes
	ServiceBytesOut = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_bytes_out",
		Help:      "Total outgoing bytes",
	}, []string{"svc_namespace", "service_name", "service_vip", "protocol", "port"})
	// ServicePpsIn Incoming packets per second
	ServicePpsIn = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_pps_in",
		Help:      "Incoming packets per second",
	}, []string{"svc_namespace", "service_name", "service_vip", "protocol", "port"})
	// ServicePpsOut Outgoing packets per second
	ServicePpsOut = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_pps_out",
		Help:      "Outgoing packets per second",
	}, []string{"svc_namespace", "service_name", "service_vip", "protocol", "port"})
	// ServiceCPS Service connections per second
	ServiceCPS = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_cps",
		Help:      "Service connections per second",
	}, []string{"svc_namespace", "service_name", "service_vip", "protocol", "port"})
	// ServiceBpsIn Incoming bytes per second
	ServiceBpsIn = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_bps_in",
		Help:      "Incoming bytes per second",
	}, []string{"svc_namespace", "service_name", "service_vip", "protocol", "port"})
	// ServiceBpsOut Outgoing bytes per second
	ServiceBpsOut = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "service_bps_out",
		Help:      "Outgoing bytes per second",
	}, []string{"svc_namespace", "service_name", "service_vip", "protocol", "port"})
	// ControllerIpvsServices Number of ipvs services in the instance
	ControllerIpvsServices = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "controller_ipvs_services",
		Help:      "Number of ipvs services in the instance",
	})
	// ControllerIptablesSyncTime Time it took for controller to sync iptables
	ControllerIptablesSyncTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "controller_iptables_sync_time",
		Help:      "Time it took for controller to sync iptables",
		Buckets:   defaultBucket,
	})
	// ControllerIpvsServicesSyncTime Time it took for controller to sync ipvs services
	ControllerIpvsServicesSyncTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "controller_ipvs_services_sync_time",
		Help:      "Time it took for controller to sync ipvs services",
		Buckets:   defaultBucket,
	})
	// ControllerRoutesSyncTime Time it took for controller to sync ipvs services
	ControllerRoutesSyncTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "controller_routes_sync_time",
		Help:      "Time it took for controller to sync routes",
		Buckets:   defaultBucket,
	})
	// ControllerBPGpeers BGP peers in the runtime configuration
	ControllerBPGpeers = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "controller_bgp_peers",
		Help:      "BGP peers in the runtime configuration",
	})
	// ControllerBGPInternalPeersSyncTime Time it took to sync internal bgp peers
	ControllerBGPInternalPeersSyncTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "controller_bgp_internal_peers_sync_time",
		Help:      "Time it took to sync internal bgp peers",
		Buckets:   fastBucket,
	})
	// ControllerBGPadvertisementsReceived Number of received route advertisements
	ControllerBGPadvertisementsReceived = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "controller_bgp_advertisements_received",
		Help:      "BGP advertisements received",
	})
	// ControllerBGPadvertisementsSent Number of received route advertisements
	ControllerBGPadvertisementsSent = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "controller_bgp_advertisements_sent",
		Help:      "BGP advertisements sent",
	})
	// ControllerIpvsMetricsExportTime Time it took to export metrics
	ControllerIpvsMetricsExportTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "controller_ipvs_metrics_export_time",
		Help:      "Time it took to export metrics",
		Buckets:   fastBucket,
	})
	// ControllerPolicyChainsSyncTime Time it took for controller to sync policies
	ControllerPolicyChainsSyncTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "controller_policy_chains_sync_time",
		Help:      "Time it took for controller to sync policy chains",
		Buckets:   defaultBucket,
	})
)

// Controller Holds settings for the metrics controller
type MetricsController struct {
	controllers.Controller
}

// Run prometheus metrics controller
func (mc *MetricsController) run(stopCh <-chan struct{}) error {
	t := time.NewTicker(3 * time.Second)

	// register metrics for this controller
	prometheus.MustRegister(ControllerIpvsMetricsExportTime)

	srv := &tools.HttpStartStopWrapper{
		Server: &http.Server{
			Addr:    ":" + strconv.Itoa(int(mc.GetConfig().MetricsPort)),
			Handler: http.DefaultServeMux,
		},
	}

	// add prometheus handler on metrics path
	http.Handle(mc.GetConfig().MetricsPath, promhttp.Handler())
	go srv.ServeAndLogReturn()

	for {
		healthcheck.SendHeartBeat(mc, nil)
		select {
		case <-stopCh:
			glog.Infof("Shutting down %s", mc.GetControllerName())
			return srv.ShutDown()
		case <-t.C:
			glog.V(4).Info("Metrics controller tick")
		}
	}
}

// NewMetricsController returns new MetricController object
func NewMetricsController(config *options.KubeRouterConfig) controllers.ControllerType {
	mc := &MetricsController{}
	mc.Init("Metrics controller", time.Duration(5*time.Second), config, mc.run)
	return mc
}
