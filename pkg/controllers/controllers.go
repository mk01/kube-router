package controllers

import (
	"sync"

	"fmt"
	"time"
)

//ControllerHeartbeat is the structure to hold the heartbeats sent by controllers
type ControllerHeartbeat struct {
	Component     Controller
	LastHeartBeat time.Time
	Data          fmt.Stringer
}

type Controller interface {
	GetData() ([]string, time.Duration)
	Run(chan *ControllerHeartbeat, <-chan struct{}, *sync.WaitGroup) error
}
