package common

import (
	"github.com/google/go-cmp/cmp"
	"hash/fnv"
	"reflect"
)

type ChannelLockType chan int

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
