package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
	}

	ifname := os.Args[1]

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	stop := make(chan struct{})
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer close(sig)
	go func(stop chan struct{}) {
		<-sig
		fmt.Fprint(os.Stderr, "Stopping...")
		close(stop)
	}(stop)

	var wg sync.WaitGroup
	wg.Add(1)

	go func(iface *net.Interface, stop chan struct{}) {
		defer wg.Done()
		if err := scan(iface, stop); err != nil {
			log.Printf("interface %v: %v", iface.Name, err)
		}
	}(iface, stop)

	wg.Wait()

	fmt.Fprintln(os.Stderr, "done.")
}

func printHelp() {
	fmt.Fprintf(os.Stderr, "usage: %s interface\n", os.Args[0])
	os.Exit(1)
}

func scan(iface *net.Interface, stop chan struct{}) error {
	var addr *net.IPNet
	if addrs, err := iface.Addrs(); err != nil {
		return err
	} else {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					addr = &net.IPNet{
						IP:   ip4,
						Mask: ipnet.Mask[len(ipnet.Mask)-4:],
					}
					break
				}
			}
		}
	}

	if addr == nil {
		return errors.New("no good IP network found")
	} else if addr.IP[0] == 127 {
		return errors.New("skipping localhost")
	} else if addr.Mask[0] != 0xff || addr.Mask[1] != 0xff {
		return errors.New("mask means network is to large")
	}
	log.Printf("Using network range %v for interface %v", addr, iface.Name)

	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	readARP(handle, iface, stop)

	return nil
}

func readARP(handle *pcap.Handle, iface *net.Interface, stop chan struct{}) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)

			switch {
			case arp.Operation == layers.ARPRequest && !bytes.Equal(arp.SourceProtAddress, []byte{0, 0, 0, 0}):
				// arp request
				log.Printf("[ARP REQUEST   ] IP %v is at %v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
			case arp.Operation == layers.ARPReply && !bytes.Equal(arp.DstHwAddress, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}):
				// arp reply
				log.Printf("[ARP REPLY     ] IP %v is at %v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
			case bytes.Equal(arp.SourceProtAddress, []byte{0, 0, 0, 0}):
				// arp probe
				log.Printf("[ARP PROBE     ] IP %v asked from %v", net.IP(arp.DstProtAddress), net.HardwareAddr(arp.SourceHwAddress))
			case bytes.Equal(arp.SourceProtAddress, arp.DstProtAddress):
				log.Printf("[GRATUITOUS ARP] IP %v used by %v", net.IP(arp.DstProtAddress), net.HardwareAddr(arp.SourceHwAddress))
			}
		}
	}
}
