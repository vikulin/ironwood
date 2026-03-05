package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/eknkc/basex"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"

	iwt "github.com/Arceliar/ironwood/types"
)

// Domain name characters for Base37 encoding (RiV-mesh address transformation).
const domainNameCharacters = "0123456789abcdefghijklmnopqrstuvwxyz-"

func setupTun(ifname, address string) tun.Device {
	dev, err := tun.CreateTUN(ifname, 1500)
	if err != nil {
		panic(err)
	}
	nladdr, err := netlink.ParseAddr(address)
	if err != nil {
		panic(err)
	}
	name, err := dev.Name()
	if err != nil {
		panic(err)
	}
	nlintf, err := netlink.LinkByName(name)
	if err != nil {
		panic(err)
	} else if err := netlink.AddrAdd(nlintf, nladdr); err != nil {
		panic(err)
	} else if err := netlink.LinkSetMTU(nlintf, 1500); err != nil {
		panic(err)
	} else if err := netlink.LinkSetUp(nlintf); err != nil {
		panic(err)
	}
	return dev
}

const tunOffsetBytes = 4

func tunReader(dev tun.Device, pc iwt.PacketConn) {
	localAddr := pc.LocalAddr()
	addr := localAddr.(iwt.Addr)
	addrBytes, _ := getAddr(iwt.Domain(addr))
	buf := make([]byte, 2048)
	for {
		n, err := dev.Read(buf, tunOffsetBytes)
		if err != nil {
			panic(err)
		}
		if n <= tunOffsetBytes {
			panic("tunOffsetBytes")
		}
		bs := buf[tunOffsetBytes : tunOffsetBytes+n]
		if len(bs) < 40 {
			panic("undersized packet")
		}
		var srcAddr, dstAddr [16]byte
		copy(srcAddr[:], bs[8:24])
		copy(dstAddr[:], bs[24:40])
		if srcAddr != addrBytes {
			//panic("wrong source address")
			continue
		}
		if dstAddr[0] != 0xfd {
			//panic("wrong dest subnet")
			continue
		}
		destDomain, isGood := getKey(dstAddr)
		if !isGood {
			pc.SendLookup(destDomain)
			pushBufMsg(dstAddr, bs)
			continue
		}
		if !checkKey(dstAddr, destDomain.Key[:]) {
			continue
		}
		dest := iwt.Addr(destDomain)
		n, err = pc.WriteTo(bs, dest)
		if err != nil {
			panic(err)
		}
		if n != len(bs) {
			panic("failed to write full packet to packetconn")
		}
	}
}

func tunWriter(dev tun.Device, pc net.PacketConn) {
	localAddr := pc.LocalAddr()
	addr := localAddr.(iwt.Addr)
	addrBytes, _ := getAddr(iwt.Domain(addr))
	rawBuf := make([]byte, 2048)
	for {
		buf := rawBuf
		n, remote, err := pc.ReadFrom(buf[tunOffsetBytes:])
		if err != nil {
			panic(err)
		}
		if n < 40 {
			panic("undersized packet")
		}
		buf = buf[:tunOffsetBytes+n]
		bs := buf[tunOffsetBytes : tunOffsetBytes+n]
		var srcAddr, dstAddr [16]byte
		copy(srcAddr[:], bs[8:24])
		copy(dstAddr[:], bs[24:40])
		if srcAddr[0] != 0xfd {
			fmt.Println(net.IP(srcAddr[:]).String()) // FIXME
			panic("wrong source subnet")
			continue
		}
		if dstAddr[0] != 0xfd {
			panic("wrong dest subnet")
			continue
		}
		if dstAddr != addrBytes {
			panic("wrong dest addr")
			continue
		}
		remoteAddr := remote.(iwt.Addr)
		remoteKey := remoteAddr.Key[:]
		if !checkKey(srcAddr, remoteKey) {
			continue
		}
		//putKey(remoteKey)
		n, err = dev.Write(buf, tunOffsetBytes)
		if err != nil {
			panic(err)
		}
		if n != len(buf) {
			panic("wrong number of bytes written")
		}
	}
}

var keyMutex sync.Mutex
var keyMap map[[16]byte]*keyInfo

type keyInfo struct {
	key   ed25519.PublicKey
	timer *time.Timer
}

func putKey(domain iwt.Domain) {
	addr, ok := getAddr(domain)
	if !ok {
		return
	}
	info := new(keyInfo)
	info.key = ed25519.PublicKey(append([]byte(nil), domain.Key[:]...))
	info.timer = time.AfterFunc(time.Minute, func() {
		keyMutex.Lock()
		defer keyMutex.Unlock()
		delete(keyMap, addr)
	})
	keyMutex.Lock()
	defer keyMutex.Unlock()
	if keyMap == nil {
		keyMap = make(map[[16]byte]*keyInfo)
	}
	if old, isIn := keyMap[addr]; isIn {
		old.timer.Stop()
	}
	keyMap[addr] = info
}

// getKey returns the Domain for the given address: from keyMap if known (Name from decode, Key from cache), otherwise the decoded domain (name only).
func getKey(addr [16]byte) (iwt.Domain, bool) {
	keyMutex.Lock()
	info := keyMap[addr]
	keyMutex.Unlock()
	decoded, ok := getDomainFromAddr(addr)
	if !ok {
		return iwt.Domain{}, false
	}
	if info != nil {
		var k iwt.PublicKey
		copy(k[:], info.key)
		return iwt.Domain{Name: decoded.Name, Key: k}, true
	}
	return decoded, false
}

func checkKey(addr [16]byte, key ed25519.PublicKey) bool {
	keyMutex.Lock()
	info := keyMap[addr]
	keyMutex.Unlock()
	return info != nil && bytes.Equal(info.key, key)
}

// truncateTrailingZeros returns data without trailing zero bytes (RiV-mesh style).
func truncateTrailingZeros(data []byte) []byte {
	length := len(data)
	for length > 0 && data[length-1] == 0 {
		length--
	}
	return data[:length]
}

// encodeToIPv6 encodes domain name to IPv6 address bytes using Base37 (RiV-mesh style).
func encodeToIPv6(prefix [1]byte, name []byte) ([16]byte, error) {
	str := string(truncateTrailingZeros(name))
	if len(str) > 23 {
		return [16]byte{}, fmt.Errorf("input data is too long for an IPv6 address")
	}
	encoder, err := basex.NewEncoding(domainNameCharacters)
	if err != nil {
		return [16]byte{}, err
	}
	var ipv6Bytes [16]byte
	copy(ipv6Bytes[:], prefix[:])
	decoded, err := encoder.Decode(str)
	if err != nil {
		return [16]byte{}, errors.New("Base37 decode error in string: " + str)
	}
	copy(ipv6Bytes[1:], decoded)
	return ipv6Bytes, nil
}

// decodeIPv6 decodes IPv6 address bytes back to domain name (RiV-mesh style).
func decodeIPv6(addr [16]byte) ([]byte, error) {
	encoder, err := basex.NewEncoding(domainNameCharacters)
	if err != nil {
		return nil, err
	}
	encodedData := truncateTrailingZeros(addr[1:])
	return []byte(encoder.Encode(encodedData)), nil
}

// getAddr returns the IPv6 address for a domain using Domain name transformation (RiV-mesh style).
// Prefix is 0xfd (fd00::/8). The rest is derived from domain.Name via Base37 encoding.
func getAddr(domain iwt.Domain) ([16]byte, bool) {
	prefix := [1]byte{0xfd}
	addr, err := encodeToIPv6(prefix, domain.Name[:])
	if err != nil {
		return [16]byte{}, false
	}
	return addr, true
}

// getDomainFromAddr decodes an address back to a Domain (name only; key is zeroed).
func getDomainFromAddr(addr [16]byte) (iwt.Domain, bool) {
	name, err := decodeIPv6(addr)
	if err != nil {
		return iwt.Domain{}, false
	}
	var nameArr [32]byte
	copy(nameArr[:], name)
	return iwt.Domain{Name: iwt.Name(nameArr), Key: iwt.PublicKey{}}, true
}

func transformKey(key ed25519.PublicKey) ed25519.PublicKey {
	// With name-based addressing we cannot derive a key from an address; use identity.
	return key
}

// Buffer traffic while waiting for a key

var bufMutex sync.Mutex
var bufMap map[[16]byte]*bufInfo

type bufInfo struct {
	msg   []byte
	timer *time.Timer
}

func pushBufMsg(addr [16]byte, msg []byte) {
	info := new(bufInfo)
	info.msg = append(info.msg, msg...)
	bufMutex.Lock()
	defer bufMutex.Unlock()
	if bufMap == nil {
		bufMap = make(map[[16]byte]*bufInfo)
	}
	old := bufMap[addr]
	bufMap[addr] = info
	info.timer = time.AfterFunc(time.Minute, func() {
		bufMutex.Lock()
		defer bufMutex.Unlock()
		if n := bufMap[addr]; n == info {
			delete(bufMap, addr)
		}
	})
	if old != nil {
		old.timer.Stop()
	}
}

func popBufMsg(addr [16]byte) []byte {
	bufMutex.Lock()
	defer bufMutex.Unlock()
	if info := bufMap[addr]; info != nil {
		info.timer.Stop()
		return info.msg
	}
	return nil
}

const (
	oobKeyReq = 1
	oobKeyRes = 2
)

func flushBuffer(pc net.PacketConn, destDomain iwt.Domain) {
	addr, ok := getAddr(destDomain)
	if !ok {
		return
	}
	if bs := popBufMsg(addr); bs != nil {
		dest := iwt.Addr(destDomain)
		n, err := pc.WriteTo(bs, dest)
		if err != nil {
			panic(err)
		}
		if n != len(bs) {
			panic("failed to write full packet to packetconn")
		}
	}
}
