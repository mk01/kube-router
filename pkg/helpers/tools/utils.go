package tools

import (
	"reflect"
	"sync"

	"github.com/golang/glog"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/net/context"
	"hash/fnv"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"net"
	"net/http"
	"os/exec"
	"strings"
)

type ApiTransaction struct {
	ObjMeta v1.Object
	Old     interface{}
	New     interface{}
}

type Listener interface {
	OnUpdate(instance interface{})
}

type ListenerFunc func(instance interface{})

func (f ListenerFunc) OnUpdate(instance interface{}) {
	f(instance)
}

var pathsToUtils sync.Map

func GetExecPath(util string) string {
	if path, _ := pathsToUtils.Load(util); path != nil {
		return path.(string)
	}
	path, err := exec.LookPath(util)
	if err != nil {
		glog.Fatalf("Utils: can't get path to executable %s: %s ", util, err.Error())
	}
	pathsToUtils.Store(util, path)
	return path
}

// reads only UP interfaces while completely excluding PtP and Loopback
func FilterInterfaces(p net.Interface) bool {
	return p.Flags&(net.FlagLoopback|net.FlagPointToPoint|net.FlagUp) == net.FlagUp
}

// Broadcaster holds the details of registered listeners
type Broadcaster struct {
	listenerLock sync.RWMutex
	listeners    []Listener
}

// NewBroadcaster returns an instance of Broadcaster object
func NewBroadcaster() *Broadcaster {
	return &Broadcaster{}
}

// Add lets to register a listener
func (b *Broadcaster) Add(listener Listener) {
	b.listenerLock.Lock()
	defer b.listenerLock.Unlock()
	b.listeners = append(b.listeners, listener)
}

// Notify notifies an update to registered listeners
func (b *Broadcaster) Notify(instance interface{}) {
	b.listenerLock.RLock()
	listeners := b.listeners
	b.listenerLock.RUnlock()
	for _, listener := range listeners {
		go listener.OnUpdate(instance)
	}
}

type HttpStartStopWrapper struct {
	*http.Server
}

func (hw *HttpStartStopWrapper) ServeAndLogReturn() {
	if err := hw.ListenAndServe(); err != http.ErrServerClosed {
		glog.Errorf("Health controller error: %s", err)
	}
}

func (hw *HttpStartStopWrapper) ShutDown() (err error) {
	return EvalPass(hw.Shutdown(context.Background()))
}

func CheckElementInArrayByFunction(element interface{}, array interface{}, fn func(a, b interface{}) bool) (ok bool) {
	ok, _ = findElementInArray(element, array, fn)
	return ok
}

func CheckForElementInArray(element interface{}, array interface{}, options ...cmp.Option) (ok bool) {
	ok, _ = FindElementInArray(element, array, options...)
	return
}

func FindElementInArray(element interface{}, array interface{}, options ...cmp.Option) (ok bool, i int) {
	return findElementInArray(element, array, func(a, b interface{}) bool {
		return cmp.Equal(a, b, options...)
	})
}

func findElementInArray(element interface{}, array interface{}, fn func(a, b interface{}) bool) (ok bool, i int) {
	arrayAccess := reflect.Indirect(reflect.ValueOf(array))
	switch arrayAccess.Kind() {
	case reflect.Slice, reflect.Array:
		for ; i < arrayAccess.Len(); i++ {
			if ok := fn(element, arrayAccess.Index(i).Interface()); ok {
				return ok, i
			}
		}
	}
	return
}

func SymmetricHasPrefix(a string, b string) bool {
	if len(a)&len(b) == 0 {
		return false
	}
	if len(a) > len(b) {
		return strings.HasPrefix(a, b)
	}
	return strings.HasPrefix(b, a)
}

func GetHash(input string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(input))
	return h.Sum32()
}

func GetHash64(input string) uint64 {
	h := fnv.New64()
	h.Write([]byte(input))
	return h.Sum64()
}
