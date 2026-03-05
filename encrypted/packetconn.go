package encrypted

import (
	"crypto/ed25519"
	"net"

	"github.com/Arceliar/phony"

	"github.com/Arceliar/ironwood/network"
	"github.com/Arceliar/ironwood/types"
)

type PacketConn struct {
	actor phony.Inbox
	*network.PacketConn
	secretEd  edPriv
	secretBox boxPriv
	sessions  sessionManager
	network   netManager
	Debug     Debug
}

// NewPacketConn returns a *PacketConn struct which implements the types.PacketConn interface.
func NewPacketConn(secret ed25519.PrivateKey, domain types.Domain, options ...network.Option) (*PacketConn, error) {
	npc, err := network.NewPacketConn(secret, domain, options...)
	if err != nil {
		return nil, err
	}
	pc := &PacketConn{PacketConn: npc}
	copy(pc.secretEd[:], secret[:])
	pc.secretBox = *pc.secretEd.toBox()
	pc.sessions.init(pc)
	pc.network.init(pc)
	pc.Debug.init(pc)
	return pc, nil
}

func (pc *PacketConn) ReadFrom(p []byte) (n int, from net.Addr, err error) {
	pc.network.read()
	info := <-pc.network.readCh
	if info.err != nil {
		err = info.err
		return
	}
	f := types.Domain{
		Key:  info.from.Key,
		Name: info.from.Name,
	}
	n, from = len(info.data), types.Addr(f)
	if n > len(p) {
		n = len(p)
	}
	copy(p, info.data[:n])
	freeBytes(info.data)
	return
}

func (pc *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	select {
	case <-pc.network.closed:
		return 0, types.ErrClosed
	default:
	}
	dest, ok := addr.(types.Addr)
	if !ok || len(dest.Key) != edPubSize {
		return 0, types.ErrBadAddress
	}
	if uint64(len(p)) > pc.MTU() {
		return 0, types.ErrOversizedMessage
	}
	destDomain := types.Domain(dest)
	n = len(p)
	pc.sessions.writeTo(destDomain, append(allocBytes(0), p...))
	return
}

// MTU returns the maximum transmission unit of the PacketConn, i.e. maximum safe message size to send over the network.
func (pc *PacketConn) MTU() uint64 {
	return pc.PacketConn.MTU() - sessionTrafficOverhead
}
