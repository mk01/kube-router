package utils

import (
	"reflect"
	"sync"

	"github.com/golang/glog"
	"github.com/google/go-cmp/cmp"
	"hash/fnv"
	"os/exec"
	"strings"
	"net"
)

type ApiTransaction struct {
	Old interface{}
	New interface{}
}

type ChannelLockType chan int

type Listener interface {
	OnUpdate(instance interface{})
}

type ListenerFunc func(instance interface{})

func (f ListenerFunc) OnUpdate(instance interface{}) {
	f(instance)
}

type pathsToUtilsType map[string]string

var pathsToUtils pathsToUtilsType

func init() {
	var err error
	pathsToUtils = make(map[string]string)
	for _, util := range []string{"ip", "ip6tables", "iptables", "ipset"} {
		pathsToUtils[util], err = exec.LookPath(util)
		if err != nil {
			glog.Error("Utils: can't get path to " + util + " err: " + err.Error())
		}
	}
}

func GetPath(util string) string {
	return pathsToUtils[util]
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

func CheckForElementInArray(element interface{}, array interface{}, options ...cmp.Option) (ok bool) {
	ok, _ = FindElementInArray(element, array, options...)
	return
}

func FindElementInArray(element interface{}, array interface{}, options ...cmp.Option) (ok bool, i int) {
	arrayAccess := reflect.Indirect(reflect.ValueOf(array))
	switch arrayAccess.Kind() {
	case reflect.Slice, reflect.Array:
		for ; i < arrayAccess.Len(); i++ {
			if ok := cmp.Equal(element, arrayAccess.Index(i).Interface(), options...); ok {
				return ok, i
			}
		}
	}
	return
}

func SymetricHasPrefix(a string, b string) bool {
	if len(a)*len(b) == 0 {
		return false
	}
	if len(a) > len(b) {
		return strings.HasPrefix(a, b)
	}
	return strings.HasPrefix(b, a)
}

func DoHash(input string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(input))
	return h.Sum32()
}

func DoHash64(input string) uint64 {
	h := fnv.New64()
	h.Write([]byte(input))
	return h.Sum64()
}

func (cl *ChannelLockType) Lock() {
	(*cl) <- 1
}

func (cl *ChannelLockType) Unlock() {
	<-(*cl)
}

func NewChanLock(arg ...int) *ChannelLockType {
	capacity := 1
	if len(arg) > 0 {
		capacity = arg[0]
	}
	var ll = make(ChannelLockType, capacity)
	return &ll
}
