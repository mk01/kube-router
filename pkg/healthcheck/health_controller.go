package healthcheck

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"fmt"
	"github.com/cloudnativelabs/kube-router/pkg/controllers"
	"github.com/cloudnativelabs/kube-router/pkg/options"
	"github.com/golang/glog"
	"golang.org/x/net/context"
)

var CONTROLLER_NAME = []string{"HealthCheck controller", "HC"}

//HealthController reports the health of the controller loops as a http endpoint
type HealthController struct {
	HealthPort  uint16
	HTTPEnabled bool
	Healthy     bool
	Status      map[controllers.Controller]*HealthStats
	regCntrls   []controllers.Controller
	Config      *options.KubeRouterConfig
}

//HealthStats is holds the latest heartbeats
type HealthStats struct {
	Name       string
	Alive      time.Time
	AliveTTL   time.Duration
	SyncPeriod time.Duration

	ExtraInfo fmt.Stringer
}

//SendHeartBeat sends a heartbeat on the passed channel
func SendHeartBeat(channel chan<- *controllers.ControllerHeartbeat, controller controllers.Controller, internalData fmt.Stringer) {
	heartbeat := controllers.ControllerHeartbeat{
		Component:     controller,
		LastHeartBeat: time.Now(),
		Data:          internalData,
	}
	channel <- &heartbeat
}

func (hc *HealthController) String() (out string) {

	for _, pController := range hc.regCntrls {
		controller := hc.Status[pController]
		out += fmt.Sprintf("\n%s last alive %s ago\n", controller.Name, time.Since(controller.Alive))
		if controller.ExtraInfo != nil {
			out += fmt.Sprintf("\t\t%s\n", controller.ExtraInfo.String())
		}
	}
	return out + "\n"
}

//Handler writes HTTP responses to the health path
func (hc *HealthController) Handler(w http.ResponseWriter, req *http.Request) {
	if hc.Healthy {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(hc.String()))
		w.Write([]byte("OK\n"))
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(hc.String()))
		w.Write([]byte("Unhealthy"))
	}
}

//HandleHeartbeat handles received heartbeats on the health channel
func (hc *HealthController) HandleHeartbeat(beat *controllers.ControllerHeartbeat) {
	if beat == nil {
		return
	}
	glog.V(3).Infof("Received heartbeat from %s", hc.Status[beat.Component].Name)

	if hc.Status[beat.Component].AliveTTL == 0 {
		hc.Status[beat.Component].AliveTTL = time.Since(hc.Status[beat.Component].Alive)
	}
	hc.Status[beat.Component].Alive = beat.LastHeartBeat
	hc.Status[beat.Component].ExtraInfo = beat.Data
}

// CheckHealth evaluates the time since last heartbeat to decide if the controller is running or not
func (hc *HealthController) CheckHealth() bool {
	health := 1
	graceTime := time.Duration(1500 * time.Millisecond)

	for _, controller := range hc.Status {
		if time.Since(controller.Alive) > controller.SyncPeriod+controller.AliveTTL+graceTime {
			glog.Error(controller.Name + " heartbeat missed")
			health &= 0
		}
	}
	hc.Healthy = health == 1
	return hc.Healthy
}

func (hc *HealthController) GetData() ([]string, time.Duration) {
	return CONTROLLER_NAME, time.Duration(5 * time.Second)
}

//RunServer starts the HealthController's server
func (hc *HealthController) Run(healthChan chan *controllers.ControllerHeartbeat, stopCh <-chan struct{}, wg *sync.WaitGroup) error {
	defer wg.Done()
	srv := &http.Server{Addr: ":" + strconv.Itoa(int(hc.HealthPort)), Handler: http.DefaultServeMux}
	http.HandleFunc("/healthz", hc.Handler)
	if (hc.Config.HealthPort > 0) && (hc.Config.HealthPort <= 65535) {
		hc.HTTPEnabled = true
		go func() {
			if err := srv.ListenAndServe(); err != nil {
				// cannot panic, because this probably is an intentional close
				glog.Errorf("Health controller error: %s", err)
			}
		}()
	} else if hc.Config.MetricsPort > 65535 {
		glog.Errorf("Metrics port must be over 0 and under 65535, given port: %d", hc.Config.MetricsPort)
	} else {
		hc.HTTPEnabled = false
	}

	go hc.checkHealth()

	t := time.NewTicker(5 * time.Second)
	shutdown := false

	for !shutdown {
		select {
		case <-stopCh:
			glog.Infof("Shutting down HealthController RunCheck")
			shutdown = true
		case heartbeat := <-healthChan:
			hc.HandleHeartbeat(heartbeat)
		case <-t.C:
			SendHeartBeat(healthChan, hc, nil)
		}
	}

	glog.Infof("Shutting down health controller")
	if hc.HTTPEnabled {
		if err := srv.Shutdown(context.Background()); err != nil {
			glog.Errorf("could not shutdown: %v", err)
		}
	}
	return nil
}

func (hc *HealthController) SetAlive(cntr controllers.Controller) {
	if hc.Status[cntr] == nil {
		name, syncPeriod := cntr.GetData()
		hc.Status[cntr] = &HealthStats{Name: name[0], Alive: time.Now(), SyncPeriod: syncPeriod}
		hc.regCntrls = append(hc.regCntrls, cntr)
	}
}

//NewHealthController creates a new health controller and returns a reference to it
func NewHealthController(config *options.KubeRouterConfig) (*HealthController, error) {
	hc := HealthController{
		Config:     config,
		HealthPort: config.HealthPort,
		Status:     make(map[controllers.Controller]*HealthStats),
		regCntrls:  make([]controllers.Controller, 0),
	}
	return &hc, nil
}

func (hc *HealthController) checkHealth() {
	for range time.Tick(2 * time.Second) {
		hc.CheckHealth()
	}
}
