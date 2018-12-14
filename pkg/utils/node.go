package utils

import (
	"errors"
	"fmt"
	"net"
	"os"

	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

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

// GetNodeIP returns the most valid external facing IP address for a node.
// Order of preference:
// 1. NodeInternalIP
// 2. NodeExternalIP (Only set on cloud providers usually)
func GetNodeIP(node *apiv1.Node) (net.IP, error) {
	var address *apiv1.NodeAddress
	for _, nodeAddress := range node.Status.Addresses {
		if nodeAddress.Type == apiv1.NodeInternalIP {
			return net.ParseIP(nodeAddress.Address), nil
		}
		if nodeAddress.Type == apiv1.NodeExternalIP {
			address = &nodeAddress
		}
	}
	if address != nil {
		return net.ParseIP(address.Address), nil
	}
	return nil, errors.New("host IP unknown")
}
