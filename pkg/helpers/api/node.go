package api

import (
	"encoding/json"
	"fmt"
	"net"
	"os"

	"strings"

	"github.com/cloudnativelabs/kube-router/pkg/helpers/tools"
	"github.com/golang/glog"
	"github.com/mattbaird/jsonpatch"
	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

func GetAllClusterNodes(ndLister cache.Indexer) (out []*apiv1.Node) {
	for _, obj := range ndLister.List() {
		out = append(out, obj.(*apiv1.Node))
	}
	return
}

// GetNodeObject returns the node API object for the node
func GetNodeObject(clientset kubernetes.Interface, hostnameOverride string) (*apiv1.Node, error) {
	// assuming kube-router is running as pod, first check env NODE_NAME
	nodeName := os.Getenv("NODE_NAME")
	if nodeName != "" {
		node, err := clientset.Core().Nodes().Get(nodeName, metav1.GetOptions{})
		if err == nil {
			return node, nil
		}
	}

	// if env NODE_NAME is not set then check if node is register with hostname
	hostName, _ := os.Hostname()
	node, err := clientset.Core().Nodes().Get(hostName, metav1.GetOptions{})
	if err == nil {
		return node, nil
	}

	// if env NODE_NAME is not set and node is not registered with hostname, then use host name override
	if hostnameOverride != "" {
		node, err = clientset.Core().Nodes().Get(hostnameOverride, metav1.GetOptions{})
		if err == nil {
			return node, nil
		}
	}

	return nil, fmt.Errorf("Failed to identify the node by NODE_NAME, hostname or --hostname-override")
}

func AnnotateNode(clientset kubernetes.Interface, node *apiv1.Node, key, value string) *apiv1.Node {
	annotations := node.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}

	oldJson, err := marshalJsonNode(annotations)
	if err != nil {
		return node
	}

	annotations[key] = value
	newJson, err := marshalJsonNode(annotations)
	if err != nil {
		return node
	}

	patch, err := jsonpatch.CreatePatch(oldJson, newJson)
	if err != nil {
		glog.Error(err)
		return node
	}

	bytePatch, _ := json.MarshalIndent(patch, "", "  ")

	newNode, err := clientset.CoreV1().Nodes().Patch(node.Name, types.JSONPatchType, bytePatch)
	if err != nil {
		glog.Error(err)
		return node
	}

	return newNode
}

func marshalJsonNode(annotations map[string]string) (out []byte, err error) {
	out, err = json.Marshal(apiv1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: annotations,
		},
	})
	if err != nil {
		glog.Error(err)
	}
	return
}

const (
	PriorityMax = 100
	PriorityMin = 0
)

var nodeAddressTypePriorityMap = map[apiv1.NodeAddressType]int{
	apiv1.NodeInternalIP:  PriorityMax,
	apiv1.NodeInternalDNS: 95,
	apiv1.NodeExternalIP:  50,
	apiv1.NodeExternalDNS: 45,
	apiv1.NodeHostName:    PriorityMin,
}

func resolveAndParseNodeIP(nodeIP string) net.IP {
	var resolvedIPs []string
	if resolvedIPs, _ = net.LookupHost(nodeIP); len(resolvedIPs) == 0 {
		return nil
	}
	return net.ParseIP(resolvedIPs[0])
}

func parseNodeIP(nodeIP string) (ip net.IP) {
	// if the string is IP, return it
	if ip = net.ParseIP(nodeIP); ip != nil {
		return
	}

	// otherwise, assume Name and try to resolve + parse it
	if ip = resolveAndParseNodeIP(nodeIP); ip == nil && !strings.Contains(nodeIP, ".") {
		return
	}

	// if still not success, try to isolate hostname from FQDN and retry same
	// action as before
	return resolveAndParseNodeIP(strings.Split(nodeIP, ".")[0])
}

// GetNodeIP returns the most valid external facing IP address for a node.
// Order of preference:
// 1. NodeInternalIP
// 2. NodeExternalIP (Only set on cloud providers usually)
func GetNodeIP(node *apiv1.Node) (address net.IP) {
	var err error
	if address, err = GetNodeIPwError(node); err != nil {
		glog.Error(err.Error())
	}
	return address
}

func GetNodeIPwError(node *apiv1.Node) (address net.IP, err error) {
	var priorityCurrent = -1

	for _, nodeAddress := range node.Status.Addresses {
		if nodeAddressTypePriorityMap[nodeAddress.Type] == PriorityMax {
			return parseNodeIP(nodeAddress.Address), nil
		}

		if nodeAddressTypePriorityMap[nodeAddress.Type] < priorityCurrent {
			continue
		}

		if ip := parseNodeIP(nodeAddress.Address); ip != nil {
			priorityCurrent = nodeAddressTypePriorityMap[nodeAddress.Type]
			address = ip
		}
	}
	if address != nil {
		return
	}
	err = tools.NewErrorf("No suitable or resolvable address found for node %s", node.Name)
	return
}
