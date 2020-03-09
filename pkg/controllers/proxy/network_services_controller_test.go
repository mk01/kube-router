package proxy

import (
	"fmt"
	"github.com/cloudnativelabs/kube-router/pkg/controllers"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/hostnet"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"net"
	"time"

	"github.com/mqliang/libipvs"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
	v1core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

type LinuxNetworkingMockImpl struct {
	ipvsSvcs ipvsServiceArrayType
}

func NewLinuxNetworkMock() *LinuxNetworkingMockImpl {
	lnm := &LinuxNetworkingMockImpl{
		ipvsSvcs: make(ipvsServiceArrayType, 0, 64),
	}
	return lnm
}

func (lnm *LinuxNetworkingMockImpl) getKubeDummyInterface(force ...bool) (netlink.Link, error) {
	var iface netlink.Link
	iface, err := netlink.LinkByName("lo")
	return iface, err
}
func (lnm *LinuxNetworkingMockImpl) setupPolicyRoutingForDSR() error {
	return nil
}
func (lnm *LinuxNetworkingMockImpl) setupRoutesForExternalIPForDSR(s *serviceInfoMapType) error {
	return nil
}
func (lnm *LinuxNetworkingMockImpl) ipvsGetServices() ipvsServiceArrayType {
	// need to return a copy, else if the caller does `range svcs` and then calls
	// DelService (on the returned svcs reference), it'll skip the "next" element
	svcsCopy := make(ipvsServiceArrayType, len(lnm.ipvsSvcs))
	copy(svcsCopy, lnm.ipvsSvcs)
	return svcsCopy
}
func (lnm *LinuxNetworkingMockImpl) ipAddrAdd(iface netlink.Link, ip *net.IPNet, addRoute bool) error {
	return nil
}
func (lnm *LinuxNetworkingMockImpl) ipvsAddServer(ks *KubeService, ep *endpointInfo) (bool, error) {
	return false, nil
}
func (lnm *LinuxNetworkingMockImpl) ipvsAddService(ks *KubeService, update bool) (*libipvs.Service, error) {
	svc := ks.Service
	lnm.ipvsSvcs = append(lnm.ipvsSvcs, svc)
	return svc, nil
}
func (lnm *LinuxNetworkingMockImpl) ipvsDelService(ks *KubeService) error {
	for idx, svc := range lnm.ipvsSvcs {
		if svc.Address.Equal(ks.Address) && svc.Protocol == ks.Protocol && svc.Port == ks.Port {
			lnm.ipvsSvcs = append(lnm.ipvsSvcs[:idx], lnm.ipvsSvcs[idx+1:]...)
			break
		}
	}
	return nil
}
func (lnm *LinuxNetworkingMockImpl) ipvsGetDestinations(ipvsSvc *libipvs.Service, force bool) ipvsDestinationArrayType {
	return make(ipvsDestinationArrayType, 0)
}
func (lnm *LinuxNetworkingMockImpl) cleanupMangleTableRule(ip string, protocol string, port string, fwmark string) error {
	return nil
}

func logf(format string, a ...interface{}) {
	fmt.Fprintf(GinkgoWriter, "INFO: "+format+"\n", a...)
}
func fatalf(format string, a ...interface{}) {
	msg := fmt.Sprintf("FATAL: "+format+"\n", a...)
	Fail(msg)
}

// There's waitForListerWithTimeout in network_routes_controller_test.go
// that receives a 2nd *testing argument - mixing testing and ginkgo
// is discouraged (latter uses own GinkgoWriter), so need to create
// our own here.
func waitForListerWithTimeoutG(lister cache.Indexer, timeout time.Duration) {
	tick := time.Tick(100 * time.Millisecond)
	timeoutCh := time.After(timeout)
	for {
		select {
		case <-timeoutCh:
			fatalf("timeout exceeded waiting for service lister to fill cache")
		case <-tick:
			if len(lister.List()) != 0 {
				return
			}
		}
	}
}

type TestCaseSvcEPs struct {
	existingService  *v1core.Service
	existingEndpoint *v1core.Endpoints
	nodeHasEndpoints bool
}

var _ = Describe("NetworkServicesController", func() {
	var lnm *LinuxNetworkingMockImpl
	var testcase *TestCaseSvcEPs
	var mockedLinuxNetworking *LinuxNetworkingMock
	var nsc *NetworkServicesController
	BeforeEach(func() {
		lnm = NewLinuxNetworkMock()
		mockedLinuxNetworking = &LinuxNetworkingMock{
			//cleanupMangleTableRuleFunc:         lnm.cleanupMangleTableRule,
			getKubeDummyInterfaceFunc:          lnm.getKubeDummyInterface,
			ipAddrAddFunc:                      lnm.ipAddrAdd,
			ipvsAddServerFunc:                  lnm.ipvsAddServer,
			ipvsAddServiceFunc:                 lnm.ipvsAddService,
			ipvsDelServiceFunc:                 lnm.ipvsDelService,
			ipvsGetDestinationsFunc:            lnm.ipvsGetDestinations,
			ipvsGetServicesFunc:                lnm.ipvsGetServices,
			setupPolicyRoutingForDSRFunc:       lnm.setupPolicyRoutingForDSR,
			setupRoutesForExternalIPForDSRFunc: lnm.setupRoutesForExternalIPForDSR,
		}

	})
	JustBeforeEach(func() {
		clientset := fake.NewSimpleClientset()

		_, err := clientset.CoreV1().Endpoints("default").Create(testcase.existingEndpoint)
		if err != nil {
			fatalf("failed to create existing endpoints: %v", err)
		}

		_, err = clientset.CoreV1().Services("default").Create(testcase.existingService)
		if err != nil {
			fatalf("failed to create existing services: %v", err)
		}

		nsc = &NetworkServicesController{
			Controller: controllers.Controller{
				Config: &options.KubeRouterConfig{
					NodeInfo: options.NodeInfo{
						NodeName: "node-1",
						NodeIP:   hostnet.NewIP("10.0.0.0").ToIPNet(),
					},
				},
			},
			ln: mockedLinuxNetworking,
		}

		startInformersForServiceProxy(nsc, clientset)
		waitForListerWithTimeoutG(nsc.svcLister, time.Second*10)
		waitForListerWithTimeoutG(nsc.epLister, time.Second*10)

		nsc.buildServicesInfo(nsc.serviceMap)
	})
	Context("service no endpoints with ExternalIPs", func() {
		var fooSvc1, fooSvc2 *libipvs.Service
		var syncErr error
		BeforeEach(func() {
			testcase = &TestCaseSvcEPs{
				&v1core.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "svc-1"},
					Spec: v1core.ServiceSpec{
						Type:        "ClusterIP",
						ClusterIP:   "10.0.0.1",
						ExternalIPs: []string{"1.1.1.1", "2.2.2.2"},
						Ports: []v1core.ServicePort{
							{Name: "Port-1", Port: 8080, Protocol: "TCP"},
						},
					},
				},
				&v1core.Endpoints{},
				false,
			}
		})
		JustBeforeEach(func() {
			// pre-inject some foo Ipvs Service to verify its deletion
			fooSvc1, _ = lnm.ipvsAddService(&KubeService{Service: &libipvs.Service{Address: net.ParseIP("1.2.3.4"), Protocol: 6, Port: 1234}}, false)
			fooSvc2, _ = lnm.ipvsAddService(&KubeService{Service: &libipvs.Service{Address: net.ParseIP("5.6.7.8"), Protocol: 6, Port: 5678}}, false)
			syncErr = nsc.syncIpvsServices()
		})
		It("Should have called syncIpvsServices OK", func() {
			Expect(syncErr).To(Succeed())
		})
		/*		It("Should have called cleanupMangleTableRule for ExternalIPs", func() {
				Expect(
					fmt.Sprintf("%v", mockedLinuxNetworking.cleanupMangleTableRuleCalls())).To(
					Equal(
						fmt.Sprintf("[{1.1.1.1 tcp 8080 %d} {2.2.2.2 tcp 8080 %d}]",
							generateFwmark(&libipvs.Service{Address: netutils.NewIP("1.1.1.1").ToIP(), Protocol: syscall.IPPROTO_TCP, Port: 8080}),
							generateFwmark(&libipvs.Service{Address: netutils.NewIP("2.2.2.2").ToIP(), Protocol: syscall.IPPROTO_TCP, Port: 8080}))))
			})*/
		It("Should have called setupPolicyRoutingForDSR", func() {
			Expect(
				mockedLinuxNetworking.setupPolicyRoutingForDSRCalls()).To(
				HaveLen(1))
		})
		It("Should have called getKubeDummyInterface", func() {
			Expect(
				mockedLinuxNetworking.getKubeDummyInterfaceCalls()).To(
				HaveLen(1))
		})
		It("Should have called setupRoutesForExternalIPForDSR with serviceInfoMapType", func() {
			Expect(
				mockedLinuxNetworking.setupRoutesForExternalIPForDSRCalls()).To(
				ContainElement(
					struct{ In1 serviceInfoMapType }{In1: nsc.serviceMap}))
		})
		It("Should have called ipAddrAdd for ClusterIP and ExternalIPs", func() {
			Expect((func() []string {
				ret := []string{}
				for _, addr := range mockedLinuxNetworking.ipAddrAddCalls() {
					ret = append(ret, addr.IP.String())
				}
				return ret
			})()).To(
				ConsistOf("10.0.0.1", "1.1.1.1", "2.2.2.2"))
		})
		It("Should have called ipvsDelService for pre-existing fooSvc1 fooSvc2", func() {
			Expect(fmt.Sprintf("%v", mockedLinuxNetworking.ipvsDelServiceCalls())).To(
				Equal(
					fmt.Sprintf("[{%p} {%p}]", fooSvc1, fooSvc2)))
		})
		It("Should have called ipvsAddService for ClusterIP and ExternalIPs", func() {
			Expect(func() []string {
				ret := []string{}
				for _, args := range mockedLinuxNetworking.ipvsAddServiceCalls() {
					ret = append(ret, fmt.Sprintf("%v:%v:%v:%v:%v",
						args.Ks.Address.String(), args.Ks.Protocol, args.Ks.Port,
						args.Ks.Flags.Flags&libipvs.IP_VS_SVC_F_PERSISTENT == libipvs.IP_VS_SVC_F_PERSISTENT, args.Ks.SchedName))
				}
				return ret
			}()).To(
				ConsistOf(
					"10.0.0.1:6:8080:false:rr",
					"1.1.1.1:6:8080:false:rr",
					"2.2.2.2:6:8080:false:rr"))
		})
	})
	Context("service no endpoints with loadbalancer IPs", func() {
		var syncErr error
		BeforeEach(func() {
			testcase = &TestCaseSvcEPs{
				&v1core.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:        "LoadBalancer",
						ClusterIP:   "10.0.0.1",
						ExternalIPs: []string{"1.1.1.1", "2.2.2.2"},
						Ports: []v1core.ServicePort{
							{Name: "Port-1", Protocol: "TCP", Port: 8080},
						},
					},
					Status: v1core.ServiceStatus{
						LoadBalancer: v1core.LoadBalancerStatus{
							Ingress: []v1core.LoadBalancerIngress{
								{IP: "10.255.0.1"},
								{IP: "10.255.0.2"},
							},
						},
					},
				},
				&v1core.Endpoints{},
				false,
			}
		})
		JustBeforeEach(func() {
			syncErr = nsc.syncIpvsServices()
		})
		It("Should have called syncIpvsServices OK", func() {
			Expect(syncErr).To(Succeed())
		})
		It("Should have called ipAddrAdd for ClusterIP, ExternalIPs and LoadBalancerIPs", func() {
			Expect((func() []string {
				ret := []string{}
				for _, addr := range mockedLinuxNetworking.ipAddrAddCalls() {
					ret = append(ret, addr.IP.String())
				}
				return ret
			})()).To(
				ConsistOf(
					"10.0.0.1", "1.1.1.1", "2.2.2.2", "10.255.0.1", "10.255.0.2"))
		})
		It("Should have called ipvsAddService for ClusterIP, ExternalIPs and LoadBalancerIPs", func() {
			Expect(func() []string {
				ret := []string{}
				for _, args := range mockedLinuxNetworking.ipvsAddServiceCalls() {
					ret = append(ret, fmt.Sprintf("%v:%v:%v:%v:%v",
						args.Ks.Address.String(), args.Ks.Protocol, args.Ks.Port,
						args.Ks.Flags.Flags&libipvs.IP_VS_SVC_F_PERSISTENT == libipvs.IP_VS_SVC_F_PERSISTENT, args.Ks.SchedName))
				}
				return ret
			}()).To(
				ConsistOf(
					"10.0.0.1:6:8080:false:rr",
					"1.1.1.1:6:8080:false:rr",
					"2.2.2.2:6:8080:false:rr",
					"10.255.0.1:6:8080:false:rr",
					"10.255.0.2:6:8080:false:rr"))
		})
	})
	Context("service no endpoints with loadbalancer IPs with skiplbips annotation", func() {
		var syncErr error
		BeforeEach(func() {
			testcase = &TestCaseSvcEPs{
				&v1core.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
						Annotations: map[string]string{
							"kube-router.io/service.skiplbips": "true",
						},
					},
					Spec: v1core.ServiceSpec{
						Type:        "LoadBalancer",
						ClusterIP:   "10.0.0.1",
						ExternalIPs: []string{"1.1.1.1", "2.2.2.2"},
						Ports: []v1core.ServicePort{
							{Name: "Port-1", Protocol: "TCP", Port: 8080},
						},
					},
					Status: v1core.ServiceStatus{
						LoadBalancer: v1core.LoadBalancerStatus{
							Ingress: []v1core.LoadBalancerIngress{
								{IP: "10.255.0.1"},
								{IP: "10.255.0.2"},
							},
						},
					},
				},
				&v1core.Endpoints{},
				false,
			}
		})
		JustBeforeEach(func() {
			syncErr = nsc.syncIpvsServices()
		})
		It("Should have called syncIpvsServices OK", func() {
			Expect(syncErr).To(Succeed())
		})
		It("Should have called ipAddrAdd only for ClusterIP and ExternalIPs", func() {
			Expect((func() []string {
				ret := []string{}
				for _, addr := range mockedLinuxNetworking.ipAddrAddCalls() {
					ret = append(ret, addr.IP.String())
				}
				return ret
			})()).To(
				ConsistOf(
					"10.0.0.1", "1.1.1.1", "2.2.2.2"))
		})
		It("Should have called ipvsAddService only for ClusterIP and ExternalIPs", func() {
			Expect(func() []string {
				ret := []string{}
				for _, args := range mockedLinuxNetworking.ipvsAddServiceCalls() {
					ret = append(ret, fmt.Sprintf("%v:%v:%v:%v:%v",
						args.Ks.Address.String(), args.Ks.Protocol, args.Ks.Port,
						args.Ks.Flags.Flags&libipvs.IP_VS_SVC_F_PERSISTENT == libipvs.IP_VS_SVC_F_PERSISTENT, args.Ks.SchedName))
				}
				return ret
			}()).To(
				ConsistOf(
					"10.0.0.1:6:8080:false:rr",
					"1.1.1.1:6:8080:false:rr",
					"2.2.2.2:6:8080:false:rr"))
		})
	})
	Context("service no endpoints with loadbalancer without IPs", func() {
		var syncErr error
		BeforeEach(func() {
			testcase = &TestCaseSvcEPs{
				&v1core.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name: "svc-1",
					},
					Spec: v1core.ServiceSpec{
						Type:        "LoadBalancer",
						ClusterIP:   "10.0.0.1",
						ExternalIPs: []string{"1.1.1.1", "2.2.2.2"},
						Ports: []v1core.ServicePort{
							{Name: "Port-1", Protocol: "TCP", Port: 8080},
						},
					},
					Status: v1core.ServiceStatus{
						LoadBalancer: v1core.LoadBalancerStatus{
							Ingress: []v1core.LoadBalancerIngress{
								{Hostname: "foo-bar.zone.elb.example.com"},
							},
						},
					},
				},
				&v1core.Endpoints{},
				false,
			}
		})
		JustBeforeEach(func() {
			syncErr = nsc.syncIpvsServices()
		})
		It("Should have called syncIpvsServices OK", func() {
			Expect(syncErr).To(Succeed())
		})
		It("Should have called ipAddrAdd only for ClusterIP and ExternalIPs", func() {
			Expect((func() []string {
				ret := []string{}
				for _, addr := range mockedLinuxNetworking.ipAddrAddCalls() {
					ret = append(ret, addr.IP.String())
				}
				return ret
			})()).To(
				ConsistOf(
					"10.0.0.1", "1.1.1.1", "2.2.2.2"))
		})
		It("Should have properly ipvsAddService only for ClusterIP and ExternalIPs", func() {
			Expect(func() []string {
				ret := []string{}
				for _, args := range mockedLinuxNetworking.ipvsAddServiceCalls() {
					ret = append(ret, fmt.Sprintf("%v:%v:%v:%v:%v",
						args.Ks.Address.String(), args.Ks.Protocol, args.Ks.Port,
						args.Ks.Flags.Flags&libipvs.IP_VS_SVC_F_PERSISTENT == libipvs.IP_VS_SVC_F_PERSISTENT, args.Ks.SchedName))
				}
				return ret
			}()).To(
				ConsistOf(
					"10.0.0.1:6:8080:false:rr",
					"1.1.1.1:6:8080:false:rr",
					"2.2.2.2:6:8080:false:rr"))
		})
	})
	Context("node has endpoints for service", func() {
		var syncErr error
		BeforeEach(func() {
			testcase = &TestCaseSvcEPs{
				&v1core.Service{
					ObjectMeta: metav1.ObjectMeta{Name: "svc-1", Namespace: "default"},
					Spec: v1core.ServiceSpec{
						Type:        "ClusterIP",
						ClusterIP:   "10.0.0.1",
						ExternalIPs: []string{"1.1.1.1", "2.2.2.2"},
						Ports: []v1core.ServicePort{
							{Name: "Port-1", Protocol: "TCP", Port: 8080},
						},
					},
				},
				&v1core.Endpoints{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-1",
						Namespace: "default",
					},
					Subsets: []v1core.EndpointSubset{
						{
							Addresses: []v1core.EndpointAddress{
								{IP: "172.20.1.1", NodeName: ptrToString("node-1")},
								{IP: "172.20.1.2", NodeName: ptrToString("node-2")},
							},
							Ports: []v1core.EndpointPort{
								{Name: "Port-1", Port: 80, Protocol: "TCP"},
							},
						},
					},
				},
				true,
			}
		})
		JustBeforeEach(func() {
			syncErr = nsc.syncIpvsServices()
		})
		It("Should have called syncIpvsServices OK", func() {
			Expect(syncErr).To(Succeed())
		})
		It("Should have called AddServiceCalls for ClusterIP and ExternalIPs", func() {
			Expect((func() []string {
				ret := []string{}
				for _, args := range mockedLinuxNetworking.ipvsAddServiceCalls() {
					ret = append(ret, fmt.Sprintf("%v:%v:%v:%v:%v",
						args.Ks.Address.String(), args.Ks.Protocol, args.Ks.Port,
						args.Ks.Flags.Flags&libipvs.IP_VS_SVC_F_PERSISTENT == libipvs.IP_VS_SVC_F_PERSISTENT, args.Ks.SchedName))
				}
				return ret
			})()).To(ConsistOf(
				"10.0.0.1:6:8080:false:rr", "1.1.1.1:6:8080:false:rr", "2.2.2.2:6:8080:false:rr"))
		})
		It("Should have added proper Endpoints", func() {
			Expect((func() []string {
				ret := []string{}
				for _, args := range mockedLinuxNetworking.ipvsAddServerCalls() {
					svc := args.Ks
					dst := args.Ep.Destination
					ret = append(ret, fmt.Sprintf("%v:%v->%v:%v",
						svc.Address, svc.Port,
						dst.Address, dst.Port))
				}
				return ret
			})()).To(ConsistOf(
				"10.0.0.1:8080->172.20.1.1:80", "1.1.1.1:8080->172.20.1.1:80", "2.2.2.2:8080->172.20.1.1:80",
				"10.0.0.1:8080->172.20.1.2:80", "1.1.1.1:8080->172.20.1.2:80", "2.2.2.2:8080->172.20.1.2:80",
			))
		})
	})
})

func startInformersForServiceProxy(nsc *NetworkServicesController, clientset kubernetes.Interface) {
	informerFactory := informers.NewSharedInformerFactory(clientset, 0)
	svcInformer := informerFactory.Core().V1().Services().Informer()
	epInformer := informerFactory.Core().V1().Endpoints().Informer()
	podInformer := informerFactory.Core().V1().Pods().Informer()

	go informerFactory.Start(nil)
	informerFactory.WaitForCacheSync(nil)

	nsc.svcLister = svcInformer.GetIndexer()
	nsc.epLister = epInformer.GetIndexer()
	nsc.podLister = podInformer.GetIndexer()
}

func ptrToString(str string) *string {
	return &str
}
