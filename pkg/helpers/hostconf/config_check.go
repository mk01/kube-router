package hostconf

import (
	"github.com/cloudnativelabs/kube-router/pkg/controllers"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/tools"
	"github.com/golang/glog"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const recordLifeType = time.Second

type ConfigCheck struct {
	Cmd  string
	Args []string
}

type configEntity struct {
	ConfigCheck
	hash       uint64
	watchers   map[controllers.ControllerType]byte
	willExpire time.Time
}

type ConfigCheckType struct {
	sync.Mutex
	allChecks    []*configEntity
	forceNextRun map[controllers.ControllerType]bool
}

var checks ConfigCheckType

func init() {
	checks.allChecks = make([]*configEntity, 0)
	checks.forceNextRun = make(map[controllers.ControllerType]bool)
}

func (cct *ConfigCheckType) runCheck(controller controllers.ControllerType, configCheck *configEntity) {
	var out []byte
	var hash uint64
	var err error

	if _, ok := configCheck.watchers[controller]; !ok {
		return
	}

	timeNow := time.Now()
	if configCheck.willExpire.After(timeNow) {
		return
	}
	if out, err = exec.Command(configCheck.Cmd, configCheck.Args...).Output(); err != nil {
		glog.Errorf("error getting machine state, Cmd: %s, error: %s",
			strings.Join(append([]string{configCheck.Cmd}, configCheck.Args...), " "), err.Error())
		return
	}
	configCheck.willExpire = timeNow.Add(recordLifeType)

	if hash = tools.GetHash64(string(out)); hash == configCheck.hash {
		return
	}

	configCheck.hash = hash
	for watcher := range configCheck.watchers {
		configCheck.watchers[watcher] |= 1
	}
	return
}

func GetConfigChecker() *ConfigCheckType {
	return &checks
}

func (cct *ConfigCheckType) ForceNextRun(controller controllers.ControllerType) {
	cct.forceNextRun[controller] = true
}

func (cct *ConfigCheckType) GetForceNextRun(controller controllers.ControllerType) bool {
	return cct.forceNextRun[controller]
}

func (cct *ConfigCheckType) GetCheckResult(controller controllers.ControllerType) (changed bool) {
	start := time.Now()
	cct.Lock()

	for _, configCheck := range cct.allChecks {
		cct.runCheck(controller, configCheck)
	}

	defer func() {
		cct.forceNextRun[controller] = false
		cct.Unlock()
		glog.V(2).Info("GetCheckResult took ", time.Since(start))
	}()

	var result byte
	var forceRun = cct.forceNextRun[controller]

	for _, configCheck := range cct.allChecks {
		if _, ok := configCheck.watchers[controller]; !ok {
			continue
		}

		result |= configCheck.watchers[controller]
		configCheck.watchers[controller] = 0
	}

	return result != 0 || forceRun
}

func (cct *ConfigCheckType) Register(controller controllers.ControllerType, newCheck ConfigCheck) {
	cct.Lock()
	defer cct.Unlock()
	for _, check := range cct.allChecks {
		if check.ConfigCheck.equals(newCheck) {
			check.watchers[controller] = 0
			return
		}
	}
	newEntity := configEntity{
		ConfigCheck: newCheck,
		watchers:    make(map[controllers.ControllerType]byte),
	}
	newEntity.watchers[controller] = 0
	cct.allChecks = append(cct.allChecks, &newEntity)
}

func (self *ConfigCheck) equals(other ConfigCheck) bool {
	if self.Cmd == other.Cmd && len(self.Args) == len(other.Args) {
		for i := range self.Args {
			if self.Args[i] != other.Args[i] {
				return false
			}
		}
		return true
	}
	return false
}
