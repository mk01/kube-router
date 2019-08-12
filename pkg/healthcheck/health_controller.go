package healthcheck

import (
	"net/http"
	"strconv"
	"time"

	"fmt"
	"github.com/cloudnativelabs/kube-router/pkg/controllers"
	"github.com/cloudnativelabs/kube-router/pkg/helpers/tools"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/golang/glog"
)

//HealthController reports the health of the controller loops as a http endpoint
type HealthController struct {
	controllers.Controller
	controllers.RegisterType

	Healthy   int
	Status    map[string]*HealthStats
	regCntrls []string
}

//HealthStats holds the latest heartbeats
type HealthStats struct {
	Alive      time.Time
	AliveTTL   time.Duration
	SyncPeriod time.Duration

	ExtraInfo fmt.Stringer
}

var healthChan chan *controllers.ControllerHeartbeat

//SendHeartBeat sends a heartbeat on the passed channel
func SendHeartBeat(controller controllers.ControllerType, internalData fmt.Stringer) {
	heartbeat := controllers.ControllerHeartbeat{
		Component:     controller,
		LastHeartBeat: time.Now(),
		Data:          internalData,
	}
	healthChan <- &heartbeat
}

func (hc *HealthController) String() (out string) {

	for _, pController := range hc.regCntrls {
		controller := hc.Status[pController]
		out += fmt.Sprintf("\n%s last alive %s ago\n", pController, time.Since(controller.Alive))
		if controller.ExtraInfo != nil {
			out += fmt.Sprintf("\t\t%s\n", controller.ExtraInfo.String())
		}
	}
	return out + "\n"
}

func (hc *HealthController) writeResponse(w http.ResponseWriter, status int) {
}

//Handler writes HTTP responses to the health path
func (hc *HealthController) Handler(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(hc.Healthy)
	w.Write([]byte(http.StatusText(hc.Healthy) + "\n"))
}

//Handler writes HTTP responses to the health path
func (hc *HealthController) HandlerWithDetails(w http.ResponseWriter, req *http.Request) {
	hc.Handler(w, req)
	w.Write([]byte(hc.String()))
}

//HandleHeartbeat handles received heartbeats on the health channel
func (hc *HealthController) HandleHeartbeat(beat *controllers.ControllerHeartbeat) {
	if beat == nil {
		return
	}
	glog.V(3).Infof("Received heartbeat from %s", beat.Component.GetControllerName())

	cntrl := beat.Component.GetControllerName()
	if hc.Status[cntrl].AliveTTL == 0 {
		hc.Status[cntrl].AliveTTL = time.Since(hc.Status[cntrl].Alive)
	}
	hc.Status[cntrl].Alive = beat.LastHeartBeat
	hc.Status[cntrl].ExtraInfo = beat.Data
}

// CheckHealth evaluates the time since last heartbeat to decide if the controller is running or not
func (hc *HealthController) CheckHealth() bool {
	health := http.StatusOK
	graceTime := time.Duration(1500 * time.Millisecond)

	for controller, healthStat := range hc.Status {
		if time.Since(healthStat.Alive) > healthStat.SyncPeriod+healthStat.AliveTTL+graceTime {
			glog.Error(controller + " heartbeat missed")
			health = http.StatusInternalServerError
		}
	}
	hc.Healthy = health
	return hc.Healthy == http.StatusOK
}

//RunServer starts the HealthController's server
func (hc *HealthController) run(stopCh <-chan struct{}) (err error) {
	var httpServer *tools.HttpStartStopWrapper
	var shutdown bool

	go hc.checkHealth(&shutdown)

	if hc.GetConfig().HealthPort > 0 {
		httpServer = &tools.HttpStartStopWrapper{
			Server: &http.Server{
				Addr:    ":" + strconv.Itoa(int(hc.GetConfig().HealthPort)),
				Handler: http.DefaultServeMux,
			},
		}
		http.HandleFunc("/healthz", hc.Handler)
		http.HandleFunc("/healthz/detailed", hc.HandlerWithDetails)
		go httpServer.ServeAndLogReturn()
	}

	t := time.NewTicker(5 * time.Second)

	for !shutdown {
		select {
		case <-stopCh:
			glog.Infof("Shutting down %s", hc.GetControllerName())
			shutdown = true
		case heartbeat := <-healthChan:
			hc.HandleHeartbeat(heartbeat)
		case <-t.C:
			SendHeartBeat(hc, nil)
		}
	}

	glog.Infof("Shutting down %s... almost done", hc.GetControllerName())
	return httpServer.ShutDown()
}

func (hc *HealthController) Register(cntr controllers.ControllerType) {
	cntrl := cntr.GetControllerName()
	if hc.Status[cntrl] == nil {
		hc.Status[cntrl] = &HealthStats{Alive: time.Now(), SyncPeriod: cntr.GetSyncPeriod()}
		hc.regCntrls = append(hc.regCntrls, cntrl)
	}
}

//NewHealthController creates a new health controller and returns a reference to it
func NewHealthController(channel chan *controllers.ControllerHeartbeat, config *options.KubeRouterConfig) *HealthController {
	hc := &HealthController{
		Status:    make(map[string]*HealthStats),
		regCntrls: make([]string, 0),
		Healthy:   http.StatusOK,
	}
	healthChan = channel
	hc.Init("HealthCheck controller", time.Duration(5*time.Second), config, hc.run)
	return hc
}

func (hc *HealthController) checkHealth(stopped *bool) {
	for range time.Tick(2 * time.Second) {
		if *stopped {
			return
		}
		hc.CheckHealth()
	}
}
