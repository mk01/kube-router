package hostconf

import (
	"fmt"
	"github.com/golang/glog"
	"io/ioutil"
	"os"
	"strconv"
)

type SysctlError struct {
	err    string
	option string
	value  int
	fatal  bool
}

type SysCtlConfigRuleType struct {
	Path  string
	Value int
}

type SysCtlConfigRuleListType []*SysCtlConfigRuleType

// Error return the error as string
func (e *SysctlError) Error() string {
	return fmt.Sprintf("Sysctl %s=%d : %s", e.option, e.value, e.err)
}

// IsFatal was the error fatal and reason to exit kube-router
func (e *SysctlError) IsFatal() bool {
	return e.fatal
}

func (sctl *SysCtlConfigRuleListType) Apply() (err error) {
	var errs []error
	for i := range *sctl {
		if err = (*sctl)[i].SetValue(); err != nil {
			errs = append(errs, err)
		}
	}
	return errs[len(errs)-1]
}

// SetValue sets a sysctl value
func (c *SysCtlConfigRuleType) SetValue() *SysctlError {
	glog.V(2).Infof("SysCtl: writing %d to %s", c.Value, c.Path)

	sysctlPath := fmt.Sprintf("/proc/sys/%s", c.Path)
	if _, err := os.Stat(sysctlPath); err != nil {
		if os.IsNotExist(err) {
			return &SysctlError{"option not found, Does your kernel version support this feature?", c.Path, c.Value, false}
		}
		return &SysctlError{"stat error: " + err.Error(), c.Path, c.Value, true}
	}

	err := ioutil.WriteFile(sysctlPath, []byte(strconv.Itoa(c.Value)), 0640)
	if err != nil {
		return &SysctlError{"could not set due to: " + err.Error(), c.Path, c.Value, true}
	}
	return nil
}
