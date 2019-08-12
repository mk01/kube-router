package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"strings"

	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/cni/plugins/ipam/host-local/backend/allocator"
	"k8s.io/client-go/kubernetes"
)

const (
	podCIDRAnnotation = "kube-router.io/pod-cidr"
)

// GetPodCidrFromCniSpec gets pod CIDR allocated to the node from CNI spec file and returns it
func GetPodCidrFromCniSpec(cniConfFilePath string) (*net.IPNet, error) {
	var err error
	var ipamConfig *allocator.IPAMConfig

	if strings.HasSuffix(cniConfFilePath, ".conflist") {
		var confList *libcni.NetworkConfigList
		confList, err = libcni.ConfListFromFile(cniConfFilePath)
		if err != nil {
			return nil, fmt.Errorf("Failed to load CNI config list file: %s", err.Error())
		}
		for _, conf := range confList.Plugins {
			if conf.Network.IPAM.Type != "" {
				ipamConfig, _, err = allocator.LoadIPAMConfig(conf.Bytes, "")
				if err != nil {
					return nil, fmt.Errorf("Failed to get IPAM details from the CNI conf file: %s", err.Error())
				}
				break
			}
		}
	} else {
		netconfig, err := libcni.ConfFromFile(cniConfFilePath)
		if err != nil {
			return nil, fmt.Errorf("Failed to load CNI conf file: %s", err.Error())
		}
		ipamConfig, _, err = allocator.LoadIPAMConfig(netconfig.Bytes, "")
		if err != nil {
			return nil, fmt.Errorf("Failed to get IPAM details from the CNI conf file: %s", err.Error())
		}
	}
	ipn := net.IPNet(ipamConfig.Subnet)
	return &ipn, nil
}

// UpdateCNIWithValues inserts the pod CIDR allocated to the node by kubernetes controlller manager
// and stored it in the CNI specification
func UpdateCNIWithValues(cniConfFilePath string, kubeInterface string, fn func(map[string]interface{}, interface{}) bool, value interface{}) error {
	file, err := ioutil.ReadFile(cniConfFilePath)
	if err != nil {
		return fmt.Errorf("Failed to load CNI conf file: %s", err.Error())
	}

	var config interface{}
	if err = json.Unmarshal(file, &config); err != nil {
		return fmt.Errorf("Failed to parse JSON from CNI conf file: %s", err.Error())
	}

	valueUpdated := false
	if strings.HasSuffix(cniConfFilePath, ".conflist") {
		configMap := config.(map[string]interface{})
		for key := range configMap {
			if key != "plugins" {
				continue
			}
			// .conflist file has array of plug-in config. Find the one with ipam key
			// and insert the CIDR for the node
			pluginConfigs := configMap["plugins"].([]interface{})
			for _, pluginConfig := range pluginConfigs {
				pluginConfigTyped := pluginConfig.(map[string]interface{})
				if pluginConfigTyped["bridge"] != kubeInterface {
					continue
				}
				if valueUpdated = fn(pluginConfigTyped, value); valueUpdated {
					break
				}
			}
		}

	} else {
		valueUpdated = fn(config.(map[string]interface{}), value)
	}

	if !valueUpdated {
		return fmt.Errorf("Failed to insert subnet value into CNI conf file: %s as CNI file is invalid.", cniConfFilePath)
	}

	configJSON, _ := json.Marshal(config)
	err = ioutil.WriteFile(cniConfFilePath, configJSON, 0644)
	if err != nil {
		return fmt.Errorf("Failed to insert subnet value into CNI conf file: %s", err.Error())
	}
	return nil
}

func UpdateSubnet(pluginConfigMap map[string]interface{}, cidr interface{}) bool {
	if val, ok := pluginConfigMap["ipam"]; ok {
		val.(map[string]interface{})["subnet"] = cidr.(string)
		return true
	}
	return false
}

func UpdateMtu(pluginConfigMap map[string]interface{}, mtu interface{}) bool {
	pluginConfigMap["mtu"] = mtu.(int)
	return true
}

// GetPodCidrFromNodeSpec reads the pod CIDR allocated to the node from API node object and returns it
func GetPodCidrFromNodeSpec(clientset kubernetes.Interface, hostnameOverride string) (*net.IPNet, error) {
	node, err := GetNodeObject(clientset, hostnameOverride)
	if err != nil {
		return &net.IPNet{}, fmt.Errorf("Failed to get pod CIDR allocated for the node due to: " + err.Error())
	}

	var ipNet *net.IPNet
	if cidr, ok := node.Annotations[podCIDRAnnotation]; ok {
		if _, ipNet, err = net.ParseCIDR(cidr); err != nil {
			return &net.IPNet{}, fmt.Errorf("error parsing pod CIDR in node annotation: %v", err.Error())
		}

		return ipNet, nil
	}

	if _, ipNet, err = net.ParseCIDR(node.Spec.PodCIDR); err != nil {
		return &net.IPNet{}, fmt.Errorf("node.Spec.PodCIDR not set for node: %v", node.Name)
	}

	return ipNet, nil
}
