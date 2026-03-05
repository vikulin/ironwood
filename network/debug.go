package network

import (
	"crypto/ed25519"
	"net"
	"time"

	"github.com/Arceliar/ironwood/types"
	"github.com/Arceliar/phony"
)

type Debug struct {
	c *core
}

func (d *Debug) init(c *core) {
	d.c = c
}

type DebugLabelInfo struct {
	Sig    []byte
	Domain types.Domain
	Root   types.Domain
	Seq    uint64
	Beacon uint64
	Path   []uint64
}

type DebugSelfInfo struct {
	Domain         types.Domain
	RoutingEntries uint64
}
type DebugPeerInfo struct {
	Domain   types.Domain
	Root     types.Domain
	Coords   []uint64
	Port     uint64
	Cost     uint64
	Priority uint8
	RX       uint64
	TX       uint64
	Updated  time.Time
	Conn     net.Conn
	Latency  time.Duration
}

type DebugTreeInfo struct {
	Domain   types.Domain
	Parent   types.Domain
	Sequence uint64
}

type DebugPathInfo struct {
	Domain   types.Domain
	Path     []uint64
	Sequence uint64
}

type DebugBloomInfo struct {
	Domain types.Domain
	Send   [bloomFilterU]uint64
	Recv   [bloomFilterU]uint64
}

type DebugLookupInfo struct {
	Domain types.Domain
	Path   []uint64
	Target types.Domain
}

func (d *Debug) GetSelf() (info DebugSelfInfo) {
	info.Domain = d.c.crypto.Domain
	phony.Block(&d.c.router, func() {
		info.RoutingEntries = uint64(len(d.c.router.infos))
	})
	return
}

func (d *Debug) GetPeers() (infos []DebugPeerInfo) {
	costs := map[*peer]uint64{}
	phony.Block(&d.c.router, func() {
		for p, c := range d.c.router.costs {
			costs[p] = c
		}
	})
	phony.Block(&d.c.peers, func() {
		for _, peers := range d.c.peers.peers {
			for peer := range peers {
				var info DebugPeerInfo
				info.Port = uint64(peer.port)
				info.Cost = uint64(costs[peer])
				info.Domain = types.Domain(peer.domain)
				info.Priority = peer.prio
				info.Conn = peer.conn
				if rtt := peer.srrt.Sub(peer.srst).Round(time.Millisecond / 100); rtt > 0 {
					info.Latency = rtt
				}
				infos = append(infos, info)
			}
		}
	})
	return
}

func (d *Debug) GetTree() (infos []DebugTreeInfo) {
	phony.Block(&d.c.router, func() {
		var zeros [ed25519.PublicKeySize]byte
		for key, dinfo := range d.c.router.infos {
			var info DebugTreeInfo
			info.Domain = types.Domain{Key: zeros, Name: key}
			info.Parent = types.Domain(dinfo.parent)
			info.Sequence = dinfo.seq
			infos = append(infos, info)
		}
	})
	return
}

func (d *Debug) GetPaths() (infos []DebugPathInfo) {
	phony.Block(&d.c.router, func() {
		var zeros [ed25519.PublicKeySize]byte
		for key, pinfo := range d.c.router.pathfinder.paths {
			var info DebugPathInfo
			info.Domain = types.Domain{Key: zeros, Name: key}
			info.Path = make([]uint64, 0, len(pinfo.path))
			for _, port := range pinfo.path {
				info.Path = append(info.Path, uint64(port))
			}
			info.Sequence = pinfo.seq
			infos = append(infos, info)
		}
	})
	return
}

func (d *Debug) GetBlooms() (infos []DebugBloomInfo) {
	phony.Block(&d.c.router, func() {
		var zeros [ed25519.PublicKeySize]byte
		for key, binfo := range d.c.router.blooms.blooms {
			var info DebugBloomInfo
			info.Domain = types.Domain{Key: zeros, Name: key}
			copy(info.Send[:], binfo.send.filter.BitSet().Bytes())
			copy(info.Recv[:], binfo.recv.filter.BitSet().Bytes())
			infos = append(infos, info)
		}
	})
	return
}

func (d *Debug) SetDebugLookupLogger(logger func(DebugLookupInfo)) {
	phony.Block(&d.c.router, func() {
		d.c.router.pathfinder.logger = func(lookup *pathLookup) {
			info := DebugLookupInfo{
				Domain: lookup.source,
				Path:   make([]uint64, 0, len(lookup.from)),
				Target: lookup.dest,
			}
			for _, p := range lookup.from {
				info.Path = append(info.Path, uint64(p))
			}
			logger(info)
		}
	})
}
