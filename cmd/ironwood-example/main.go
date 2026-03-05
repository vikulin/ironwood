package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	iwc "github.com/Arceliar/ironwood/encrypted"
	iwn "github.com/Arceliar/ironwood/network"
	iws "github.com/Arceliar/ironwood/signed"
	iwt "github.com/Arceliar/ironwood/types"

	"log"
	"net/http"
	_ "net/http/pprof"
)

var ifname = flag.String("ifname", "\000", "interface name to bind to")
var pprof = flag.String("pprof", "", "listen to pprof on this port")
var enc = flag.Bool("enc", false, "encrypt traffic (must be enabled on all nodes)")
var sign = flag.Bool("sign", false, "sign traffic (must be enabled on all nodes)")

func main() {
	flag.Parse()
	if pprof != nil && *pprof != "" {
		go func() {
			log.Println(http.ListenAndServe(*pprof, nil))
		}()
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	domain := iwt.NewDomain("", pub)
	var pc iwt.PacketConn
	var opts []iwn.Option
	var doNotify2 func(key ed25519.PublicKey)
	doNotify1 := func(key ed25519.PublicKey) {
		doNotify2(key)
	}
	opts = append(opts, iwn.WithBloomTransform(func(key iwt.Domain) iwt.Domain {
		var newKey iwt.PublicKey
		copy(newKey[:], transformKey(key.Key[:]))
		return iwt.Domain{Name: key.Name, Key: newKey}
	}))
	opts = append(opts, iwn.WithPathNotify(func(key iwt.Domain) {
		doNotify1(key.Key[:])
	}))
	if *enc && *sign {
		panic("TODO a useful error message (can't use both -unenc and -sign)")
	} else if *enc {
		pc, _ = iwc.NewPacketConn(priv, domain, opts...)
	} else if *sign {
		pc, _ = iws.NewPacketConn(priv, domain, opts...)
	} else {
		pc, _ = iwn.NewPacketConn(priv, domain, opts...)
	}
	defer pc.Close()
	doNotify2 = func(key ed25519.PublicKey) {
		domain := iwt.NewDomain("", key)
		putKey(domain)
		flushBuffer(pc, domain) // Ugly hack, we need the pc for flushBuffer to work
	}
	// get address and pc.SetOutOfBandHandler
	localAddr := pc.LocalAddr()
	addr := localAddr.(iwt.Addr)
	pubKey := addr.Key[:]
	addrBytes, _ := getAddr(iwt.Domain(addr))
	// open tun/tap and assign address
	ip := net.IP(addrBytes[:])
	fmt.Println("Our IP address is", ip.String())
	if ifname != nil && *ifname != "none" {
		tun := setupTun(*ifname, ip.String()+"/8")
		// read/write between tun/tap and packetconn
		go tunReader(tun, pc)
		go tunWriter(tun, pc)
	}
	// open multicast and start adding peers
	mc := newMulticastConn()
	go mcSender(mc, pubKey)
	go mcListener(mc, pubKey, pc)
	// listen for TCP, pass connections to packetConn.HandleConn
	go listenTCP(pc)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}
