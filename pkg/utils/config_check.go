package utils

import (
	"github.com/cloudnativelabs/kube-router/pkg/controllers"
	"github.com/golang/glog"
	"os/exec"
	"strings"
	"time"
)

const recordLifeType time.Duration = time.Second

type ConfigCheck struct {
	Cmd  string
	Args []string
}

type configEntity struct {
	ConfigCheck
	hash       uint64
	watchers   map[controllers.Controller]byte
	willExpire time.Time
}

type ConfigCheckType struct {
	allChecks []*configEntity
	*ChannelLockType
	forceNextRun map[controllers.Controller]bool
}

var checks ConfigCheckType

func init() {
	checks.allChecks = make([]*configEntity, 0)
	checks.forceNextRun = make(map[controllers.Controller]bool)
	checks.ChannelLockType = NewChanLock()
}

func (self *ConfigCheckType) runCheck(controller controllers.Controller) (err error) {
	var out []byte
	var hash uint64

	self.Lock()
	for _, configCheck := range self.allChecks {
		if _, ok := configCheck.watchers[controller]; !ok {
			continue
		}

		timeNow := time.Now()
		if configCheck.willExpire.After(timeNow) {
			continue
		}
		if out, err = exec.Command(configCheck.Cmd, configCheck.Args...).Output(); err != nil {
			glog.Errorf("error getting machine state, Cmd: %s, error: %s",
				strings.Join(append([]string{configCheck.Cmd}, configCheck.Args...), " "), err.Error())
			continue
		}
		configCheck.willExpire = timeNow.Add(recordLifeType)

		if hash = DoHash64(string(out)); hash == configCheck.hash {
			continue
		}

		configCheck.hash = hash
		for watcher := range configCheck.watchers {
			configCheck.watchers[watcher] |= 1
		}
	}
	self.Unlock()
	return nil
}

func GetConfigChecker() *ConfigCheckType {
	return &checks
}

func (self *ConfigCheckType) ForceNextRun(controller controllers.Controller) {
	self.forceNextRun[controller] = true
}

func (self *ConfigCheckType) GetCheckResult(controller controllers.Controller) (changed bool) {
	start := time.Now()
	self.runCheck(controller)
	self.Lock()

	var result byte
	var forceRun = self.forceNextRun[controller]

	for _, configCheck := range self.allChecks {
		if _, ok := configCheck.watchers[controller]; !ok {
			continue
		}

		result |= configCheck.watchers[controller]
		configCheck.watchers[controller] = 0
	}
	self.Unlock()
	glog.V(0).Info("GetCheckResult took ", time.Since(start))

	self.forceNextRun[controller] = false
	return result != 0 || forceRun
}

func (self *ConfigCheckType) Register(controller controllers.Controller, newCheck ConfigCheck) {
	self.Lock()
	defer self.Unlock()
	for _, check := range self.allChecks {
		if check.ConfigCheck.equals(newCheck) {
			check.watchers[controller] = 0
			return
		}
	}
	newEntity := configEntity{
		ConfigCheck: newCheck,
		watchers:    make(map[controllers.Controller]byte),
	}
	newEntity.watchers[controller] = 0
	self.allChecks = append(self.allChecks, &newEntity)
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
