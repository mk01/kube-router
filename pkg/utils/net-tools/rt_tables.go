package netutils

import (
	"errors"
	"fmt"
	"github.com/cloudnativelabs/kube-router/pkg/utils"
	"github.com/golang/glog"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

type RouteTableCheck struct {
	Cmd    []string
	Output string
}

type RouteTableType struct {
	Desc        string
	Id          string
	Name        string
	Cmd         []string
	ForChecking RouteTableCheck
	CmdDisable  []string
	ForProto    ProtocolMapType
}

type RouteTableMapType map[string]RouteTableType

type RouteTableManager struct {
	customRouteTables RouteTableMapType
}

func NewRouteTableManager(tables *RouteTableMapType) *RouteTableManager {
	return &RouteTableManager{*tables}
}

func (rtm *RouteTableManager) setupRouteTable() error {
	b, err := ioutil.ReadFile("/etc/iproute2/rt_tables")
	if err != nil {
		return errors.New("Failed to list kernel route tables: " + err.Error())
	}

	rts := string(b) + "\n"
	toAdd := make([]string, 0)
	for _, rt := range rtm.customRouteTables {
		if !strings.Contains(rts, rt.Name) {
			toAdd = append(toAdd, "\n"+rt.Id+"\t"+rt.Name+"\n")
		}
	}
	if len(toAdd) == 0 {
		return nil
	}

	f, err := os.OpenFile("/etc/iproute2/rt_tables", os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return errors.New("Failed to open kernel route table file for writing " + err.Error())
	}
	defer f.Close()

	for _, rt := range toAdd {
		if _, err = f.WriteString(rt); err != nil {
			return errors.New("Failed add route table " + rt + ": " + err.Error())
		}
	}
	return nil
}

func (rtm *RouteTableManager) setupCustomRouteTable(inet []string, rt *RouteTableType) error {
	args := append(inet, rt.ForChecking.Cmd...)
	out, err := exec.Command(utils.GetPath("ip"), args...).Output()
	if err != nil || !strings.Contains(string(out), rt.ForChecking.Output) {
		if err = rtm.setupRouteTable(); err == nil {
			out, err = exec.Command(utils.GetPath("ip"), args...).Output()
		}
	}
	if err != nil {
		return errors.New("Failed to create " + rt.Name + " route table: " + err.Error() + " #cmdrun: " + fmt.Sprint(args))
	}
	if !strings.Contains(string(out), rt.ForChecking.Output) {
		args = append(inet, rt.Cmd...)
		if err = exec.Command(utils.GetPath("ip"), args...).Run(); err != nil {
			return errors.New("Failed to run: " + strings.Join(args, " ") + ": " + err.Error())
		}
	}
	return nil
}

func (rtm *RouteTableManager) wrap(f func([]string, *RouteTableType) error, rt *RouteTableType) (err error) {
	var proto = UsedTcpProtocols
	if rt.ForProto != nil && len(rt.ForProto) > 0 {
		proto = rt.ForProto
	}
	err = proto.ForEach(func(p Proto) error {
		return f([]string{NewIP(p).ProtocolCmdParam().Inet}, rt)
	})
	return
}

func (rtm *RouteTableManager) disable(inet []string, rt *RouteTableType) (err error) {
	args := append(inet, "route", "flush", "table", rt.Name)
	err = exec.Command(utils.GetPath("ip"), args...).Run()
	if err == nil && rt.CmdDisable != nil {
		args = append(inet, rt.CmdDisable...)
		err = exec.Command(utils.GetPath("ip"), args...).Run()
	}
	return
}

func (rtm *RouteTableManager) Setup(activated bool) (err error) {
	for _, rt := range rtm.customRouteTables {
		if err != nil {
			break
		}
		switch activated {
		case true:
			err = rtm.wrap(rtm.setupCustomRouteTable, &rt)
		default:
			err = rtm.wrap(rtm.disable, &rt)
		}
	}
	if err != nil {
		glog.Error(err)
	}
	return
}
