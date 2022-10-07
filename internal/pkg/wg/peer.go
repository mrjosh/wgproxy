package wg

import (
	"context"
	"net"
	"os"
	"sync"
)

const MaxSegmentSize = (1 << 16) - 1 // largest possible UDP datagram

type Peer struct {
	FriendlyName string         `json:"friendly_name"`
	IPAddress    net.Addr       `json:"ip_address"`
	PublicKey    NoisePublicKey `json:"public_key"`
	ctx          context.Context
	localConn    *net.UDPConn
	remoteConn   net.Conn
	logger       *Logger
}

func NewPeer(logger *Logger, conn *net.UDPConn, addr net.Addr, pk NoisePublicKey) (*Peer, error) {
	return &Peer{
		localConn: conn,
		IPAddress: addr,
		PublicKey: pk,
		logger:    logger,
	}, nil
}

func (p *Peer) SetLocalConn(conn *net.UDPConn) error {
	if p.localConn == nil {
		p.localConn = conn
	}
	return nil
}

func (p *Peer) WriteToRemote(buf []byte) error {
	if _, err := p.remoteConn.Write(buf); err != nil {
		return err
	}
	return nil
}

func (p *Peer) Listen() error {

	wgRemoteIP := os.Getenv("WG_REMOTE_IP")
	if wgRemoteIP == "" {
		p.logger.Errorf("WG_REMOTE_IP is empty")
		os.Exit(1)
	}

	var err error
	p.remoteConn, err = net.Dial("udp", wgRemoteIP)
	if err != nil {
		return err
	}

	go func() {

		for {

			buf := make([]byte, MaxSegmentSize)
			n, err := p.remoteConn.Read(buf)
			if err != nil {
				p.logger.Errorf(err.Error())
				return
			}

			if _, err := p.localConn.WriteTo(buf[:n], p.IPAddress); err != nil {
				p.logger.Errorf(err.Error())
				return
			}

		}

	}()

	return nil
}

func (p *Peer) Close() error {
	if err := p.localConn.Close(); err != nil {
		return err
	}
	if err := p.remoteConn.Close(); err != nil {
		return err
	}
	return nil
}

type Peers struct {
	mu    sync.RWMutex
	peers map[string]*Peer
}

func NewPeers() *Peers {
	return &Peers{
		peers: make(map[string]*Peer, 0),
	}
}

func (p *Peers) Exists(peerAddr net.Addr) (*Peer, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, peer := range p.peers {
		if peer.IPAddress.String() == peerAddr.String() {
			return peer, true
		}
	}
	return nil, false
}

func (p *Peers) Add(peer *Peer) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.peers[peer.PublicKey.String()]; ok {
		return false
	}
	p.peers[peer.PublicKey.String()] = peer
	return true
}

func (p *Peers) Remove(peer *Peer) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	p.peers[peer.PublicKey.String()].Close()
	delete(p.peers, peer.PublicKey.String())
}
