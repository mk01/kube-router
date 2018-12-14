package main

import (
	"fmt"
	"net"
	"syscall"
	//"os"
	"github.com/mqliang/libipvs"
	"github.com/docker/libnetwork/ipvs"
)

func main() {
	var hh *ipvs.Handle

        hh, _ = ipvs.New("")
//        if err != nil {
//                panic(err)
//        }

	h, err := libipvs.New()
	if err != nil {
		panic(err)
	}
//	if err := h.Flush(); err != nil {
//		panic(err)
//	}

	info, err := h.GetInfo()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%#v\n", info)

	svcs, err := h.ListServices()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%#v\n", svcs)

	svcipvs := ipvs.Service{
		Address:       net.ParseIP("172.192.168.30"),
		AddressFamily: syscall.AF_INET,
		Protocol:      syscall.IPPROTO_TCP,
		Port:          80,
		SchedName:	"rr",
	}

	svc := libipvs.Service{
		Address:       net.ParseIP("172.192.168.1"),
		AddressFamily: syscall.AF_INET,
		Protocol:      libipvs.Protocol(syscall.IPPROTO_TCP),
		Port:          80,
		SchedName:     libipvs.RoundRobin,
		Flags: libipvs.Flags{0, ^uint32(0)},
	}

//        if err := hh.NewService(&svcipvs); err != nil {
//                panic(err)
//        }

	svc2 := libipvs.Service{
		Address:       net.ParseIP("172.192.168.2"),
		AddressFamily: syscall.AF_INET,
		Protocol:      libipvs.Protocol(syscall.IPPROTO_TCP),
		Port:          80,
		SchedName:     libipvs.RoundRobin,
	}

	if err := h.UpdateService(&svc); err != nil {
		//panic(err)
	}

	if err := h.NewService(&svc2); err != nil {
		//panic(err)
	}

	svcsipvs, err := hh.GetServices()
	if err != nil {
		panic(err)
	}
	for _, a := range svcsipvs {
		fmt.Printf("%#v    prvy\n", *a)
		dsts, _ := hh.GetDestinations(a)
		for _, dst := range dsts {
			fmt.Printf("%#v    prvy\n", dst)
		}
	}

	        
        if err := hh.NewService(&svcipvs); err != nil {
		fmt.Println(err)
                //panic(err)
        }

	//os.Exit(0)
	dst := libipvs.Destination{
		Address:       net.ParseIP("172.192.100.1"),
		AddressFamily: syscall.AF_INET,
		Port:          80,
	}

	if err := h.NewDestination(&svc, &dst); err != nil {
		panic(err)
	}

        if err := h.UpdateDestination(&svc, &dst); err != nil {
                panic(err)
        }

        dsts, err := h.ListDestinations(&svc)
        if err != nil {
                panic(err)
        }
        fmt.Printf("%#v\n", dsts)

	if err := h.NewDestination(&svc2, &dst); err != nil {
		panic(err)
	}

        dsts, err = h.ListDestinations(&svc2)
        if err != nil {
                panic(err)
        }
        fmt.Println(dsts[0])

	dsts, err = h.ListDestinations(&svc)
	if err != nil {
		panic(err)
	}
	fmt.Println(dsts[0])
}
