package routing

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"os"
	"syscall"

	"github.com/cloudnativelabs/kube-router/pkg/helpers/api"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/hostnet"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/tools"
	"github.com/cloudnativelabs/kube-router/pkg/metrics"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/golang/glog"
	"github.com/google/go-cmp/cmp"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	gobgp "github.com/osrg/gobgp/server"
	v1core "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

// Refresh the peer relationship with rest of the nodes in the cluster (iBGP peers). Node add/remove
// events should ensure peer relationship with only currently active nodes. In case
// we miss any events from API server this method which is called periodically
// ensures peer relationship with removed nodes is deleted.
func (nrc *NetworkRoutingController) syncInternalPeers() {
	nrc.mu.Lock()
	defer nrc.mu.Unlock()

	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		if nrc.MetricsEnabled {
			metrics.ControllerBGPInternalPeersSyncTime.Observe(endTime.Seconds())
		}
		glog.V(2).Infof("Syncing BGP peers for the node took %v", endTime)
	}()

	nodes := api.GetAllClusterNodes(nrc.nodeLister)
	if nrc.MetricsEnabled {
		metrics.ControllerBPGpeers.Set(float64(len(nodes)))
	}

	removedNodes := make(map[string]bool)
	nrc.activeNodes.Range(func(node, present interface{}) bool {
		removedNodes[node.(string)] = true
		return true
	})

	// establish peer and add Pod CIDRs with current set of nodes
	for _, node := range nodes {
		nodeIP := api.GetNodeIP(node)
		delete(removedNodes, nodeIP.String())

		// skip self
		// or send signal to quit (and restart) if the node changed IP
		if nodeIP.Equal(nrc.GetConfig().GetNodeIP().IP) {
			continue
		} else if node.Name == nrc.GetConfig().GetNodeName() {
			glog.Errorf("Node changed it's IP address (%s -> %s), signalling parent to restart", nrc.GetConfig().GetNodeIP(), nodeIP)
			process, _ := os.FindProcess(nrc.GetConfig().KubeRouterPid)
			process.Signal(syscall.SIGINT)
			return
		}

		// we are rr-client peer only with rr-server
		if _, ok := node.ObjectMeta.Annotations[rrServerAnnotation]; !ok && nrc.bgpRRClient {
			continue
		}

		// if node full mesh is not requested then just peer with nodes with same ASN
		// (run iBGP among same ASN peers)
		if info := nrc.getCheckNodeAsn(node, nodeIP.String()); info != nil {
			glog.Info(info.Error())
			continue
		}

		neighborConfig := &config.Neighbor{
			Config: config.NeighborConfig{
				NeighborAddress: nodeIP.String(),
				PeerAs:          nrc.nodeAsnNumber,
			},
			Transport: config.Transport{
				Config: config.TransportConfig{
					RemotePort: nrc.bgpPort,
				},
			},
		}

		injectGrRestart(nrc.GetConfig(), neighborConfig, true)
		injectAsiSafiConfigs(nodeIP, nrc.GetConfig(), &neighborConfig.AfiSafis)

		// we are rr-server peer with other rr-client with reflection enabled
		if nrc.bgpRRServer {
			if _, ok := node.ObjectMeta.Annotations[rrClientAnnotation]; ok {
				//add rr options with clusterId
				neighborConfig.RouteReflector = config.RouteReflector{
					Config: config.RouteReflectorConfig{
						RouteReflectorClient:    true,
						RouteReflectorClusterId: config.RrClusterIdType(fmt.Sprint(nrc.bgpClusterID)),
					},
					State: config.RouteReflectorState{
						RouteReflectorClient:    true,
						RouteReflectorClusterId: config.RrClusterIdType(fmt.Sprint(nrc.bgpClusterID)),
					},
				}
			}
		}

		prevNeighConfig, active := nrc.activeNodes.Load(nodeIP.String())
		if active && cmp.Equal(prevNeighConfig.(config.Neighbor), *neighborConfig, cmpExclude) {
			continue
		}

		copyNeighborConfig := *neighborConfig
		reset, err := bgpFunc[active](nrc.bgpServer, neighborConfig)
		if err != nil {
			glog.Errorf("Failed to add/update node %s as peer due to %s", nodeIP.String(), err)
			continue
		}
		nrc.activeNodes.Store(nodeIP.String(), copyNeighborConfig)
		if !reset {
			continue
		}

		for _, afisafi := range getAfiSafiTypes(nodeIP) {
			tools.Eval(nrc.bgpServer.SoftResetIn("", bgp.AddressFamilyValueMap[string(afisafi)]))
		}
	}

	// delete the neighbor for the nodes that are removed
	for ip := range removedNodes {
		n := &config.Neighbor{
			Config: config.NeighborConfig{
				NeighborAddress: ip,
				PeerAs:          nrc.defaultNodeAsnNumber,
			},
		}
		if err := nrc.bgpServer.DeleteNeighbor(n); err != nil {
			glog.Errorf("Failed to remove node %s as peer due to %s", ip, err)
		}

		nrc.removeRoutesForNode(hostnet.NewIP(ip).ToIP())
		nrc.activeNodes.Delete(ip)
	}
}

func (nrc *NetworkRoutingController) getCheckNodeAsn(node *v1core.Node, nodeIP string) (ok error) {
	if nrc.GetConfig().FullMeshMode {
		return
	}

	if nodeasn, e := node.ObjectMeta.Annotations[nodeASNAnnotation]; !e {
		ok = tools.NewErrorf("Not peering with the Node %s as ASN number of the node is unknown.", nodeIP)

	} else if asnNo, e := strconv.ParseUint(nodeasn, 0, 32); e != nil {
		ok = tools.NewErrorf("Not peering with the Node %s as ASN number of the node is invalid.", nodeIP)

		// if the nodes ASN number is different from ASN number of current node skip peering
	} else if nrc.nodeAsnNumber != uint32(asnNo) {
		ok = tools.NewErrorf("Not peering with the Node %s as ASN number of the node is different.", nodeIP)

	}

	return
}

// connectToExternalBGPPeers adds all the configured eBGP peers (global or node specific) as neighbours
func connectToExternalBGPPeers(server *gobgp.BgpServer, peerNeighbors []*config.Neighbor, krConfig *options.KubeRouterConfig, peerMultihopTtl uint8) error {
	for _, n := range peerNeighbors {

		injectGrRestart(krConfig, n, false)
		injectAsiSafiConfigs(net.ParseIP(n.Config.NeighborAddress), krConfig, &n.AfiSafis)

		if peerMultihopTtl > 1 {
			n.EbgpMultihop = config.EbgpMultihop{
				Config: config.EbgpMultihopConfig{
					Enabled:     true,
					MultihopTtl: peerMultihopTtl,
				},
				State: config.EbgpMultihopState{
					Enabled:     true,
					MultihopTtl: peerMultihopTtl,
				},
			}
		}
		err := server.AddNeighbor(n)
		peerConfig := n.Config
		if err != nil {
			return fmt.Errorf("Error peering with peer router %q due to: %s",
				peerConfig.NeighborAddress, err)
		}
		glog.V(2).Infof("Successfully configured %s in ASN %v as BGP peer to the node",
			peerConfig.NeighborAddress, peerConfig.PeerAs)
	}
	return nil
}

// Does validation and returns neighbor configs
func newGlobalPeers(ips []net.IP, ports []uint16, asns []uint32, passwords []string) (
	[]*config.Neighbor, error) {
	peers := make([]*config.Neighbor, 0)

	// Validations
	if len(ips) != len(asns) {
		return nil, errors.New("Invalid peer router config. " +
			"The number of IPs and ASN numbers must be equal.")
	}

	if len(ips) != len(passwords) && len(passwords) != 0 {
		return nil, errors.New("Invalid peer router config. " +
			"The number of passwords should either be zero, or one per peer router." +
			" Use blank items if a router doesn't expect a password.\n" +
			"Example: \"pass,,pass\" OR [\"pass\",\"\",\"pass\"].")
	}

	if len(ips) != len(ports) && len(ports) != 0 {
		return nil, errors.New("Invalid peer router config. " +
			"The number of ports should either be zero, or one per peer router." +
			" If blank items are used, it will default to standard BGP port, " +
			strconv.Itoa(options.DEFAULT_BGP_PORT) + "\n" +
			"Example: \"port,,port\" OR [\"port\",\"\",\"port\"].")
	}

	for i := 0; i < len(ips); i++ {
		if !((asns[i] >= 1 && asns[i] <= 23455) ||
			(asns[i] >= 23457 && asns[i] <= 63999) ||
			(asns[i] >= 64512 && asns[i] <= 65534) ||
			(asns[i] >= 131072 && asns[i] <= 4199999999) ||
			(asns[i] >= 4200000000 && asns[i] <= 4294967294)) {
			return nil, fmt.Errorf("Reserved ASN number \"%d\" for global BGP peer",
				asns[i])
		}

		peer := &config.Neighbor{
			Config: config.NeighborConfig{
				NeighborAddress: ips[i].String(),
				PeerAs:          asns[i],
			},
			Transport: config.Transport{
				Config: config.TransportConfig{
					RemotePort: options.DEFAULT_BGP_PORT,
				},
			},
		}

		if len(ports) != 0 {
			peer.Transport.Config.RemotePort = ports[i]
		}

		if len(passwords) != 0 {
			peer.Config.AuthPassword = passwords[i]
		}

		peers = append(peers, peer)
	}

	return peers, nil
}

func (nrc *NetworkRoutingController) newNodeEventHandler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node := obj.(*v1core.Node)
			nodeIP := api.GetNodeIP(node)

			glog.V(2).Infof("Received node %s added update from watch API so peer with new node", nodeIP)
			nrc.OnNodeUpdate(node)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			// we are interested only node add/delete, so skip update
			nrc.OnNodeUpdate(oldObj.(*v1core.Node))
		},
		DeleteFunc: func(obj interface{}) {
			node := obj.(*v1core.Node)
			nodeIP := api.GetNodeIP(node)

			glog.Infof("Received node %s removed update from watch API, so remove node from peer", nodeIP)
			nrc.OnNodeUpdate(node)
		},
	}
}

// OnNodeUpdate Handle updates from Node watcher. Node watcher calls this method whenever there is
// new node is added or old node is deleted. So peer up with new node and drop peering
// from old node
func (nrc *NetworkRoutingController) OnNodeUpdate(node *v1core.Node) {
	if !nrc.bgpServerStarted {
		return
	}

	// update export policies so that NeighborSet gets updated with new set of nodes
	err := nrc.AddPolicies()
	if err != nil {
		glog.Errorf("Error adding BGP policies: %s", err.Error())
	}

	if nrc.GetConfig().EnableiBGP {
		nrc.syncInternalPeers()
	}

	// skip if first round of disableSourceDestinationCheck() is not done yet, this is to prevent
	// all the nodes for all the node add update trying to perfrom disableSourceDestinationCheck
	if nrc.disableSrcDstCheck && nrc.initSrcDstCheckDone && nrc.ec2IamAuthorized {
		nrc.disableSourceDestinationCheck([]*v1core.Node{node})
	}
}
