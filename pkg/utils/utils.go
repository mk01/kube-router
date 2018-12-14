package utils

import (
	"net"
	"reflect"
	"sync"

	"github.com/google/go-cmp/cmp"
	"hash/fnv"
)

type ChannelLockType chan int

type Listener interface {
	OnUpdate(instance interface{})
}

type ListenerFunc func(instance interface{})

func (f ListenerFunc) OnUpdate(instance interface{}) {
	f(instance)
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

func DoHash(input *[]byte) uint32 {
	h := fnv.New32a()
	h.Write(*input)
	return h.Sum32()
}

func (cl *ChannelLockType) Lock() {
	*cl <- 1
}

func (cl *ChannelLockType) Unlock() {
	<-(*cl)
}

func NewChanLock() *ChannelLockType {
	var ll = make(ChannelLockType, 1)
	return &ll
}