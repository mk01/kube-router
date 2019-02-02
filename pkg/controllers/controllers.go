package controllers

import (
	"sync"

	"github.com/cloudnativelabs/kube-router/pkg/healthcheck"
)

type Controller interface {
	GetName() string
	Run(chan<- *healthcheck.ControllerHeartbeat, <-chan struct{}, *sync.WaitGroup) error
}
