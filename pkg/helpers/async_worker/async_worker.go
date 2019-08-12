package async_worker

import (
	"github.com/golang/glog"
	"sync"
	"sync/atomic"
)

type (
	ManagerType interface {
		AddWorkerRoutine(WorkerType, string)
		StopWorkerManager()

		isStopped() bool
		done()
	}

	WorkerType interface {
		StartWorker()
		StopWorker()

		IsStopped() bool
		GetName() string
		Done()

		Initialize(ManagerType, string)
	}

	Manager struct {
		sync.Mutex
		workers []WorkerType
		stopped int32

		wg sync.WaitGroup
	}

	Worker struct {
		manager ManagerType
		name    string
	}
)

func (mn *Manager) AddWorkerRoutine(worker WorkerType, name string) {
	mn.Lock()
	defer mn.Unlock()

	worker.Initialize(mn, name)
	mn.workers = append(mn.workers, worker)

	glog.V(3).Infof("calling start on %s", name)
	mn.wg.Add(1)

	worker.StartWorker()
}

func (mn *Manager) StopWorkerManager() {
	if !atomic.CompareAndSwapInt32(&mn.stopped, 0, 1) {
		return
	}

	for _, worker := range mn.workers {
		glog.V(3).Infof("calling stop on %s", worker.GetName())
		worker.StopWorker()
	}
	mn.wg.Wait()
}

func (mn *Manager) isStopped() bool {
	return atomic.LoadInt32(&mn.stopped) == 1
}

func (mn *Manager) done() {
	mn.wg.Done()
}

func (wk *Worker) IsStopped() bool {
	return wk.manager.isStopped()
}

func (wk *Worker) Initialize(manager ManagerType, name string) {
	wk.manager = manager
	wk.name = name
}

func (wk *Worker) GetName() string {
	return wk.name
}

func (wk *Worker) Done() {
	wk.manager.done()
}

func (wk *Worker) StopWorker() {
}
