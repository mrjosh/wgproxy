package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/mrjosh/wgproxy/internal/pkg/wg"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	logger *wg.Logger
)

func main() {

	logger = wg.NewLogger(wg.LogLevelVerbose, fmt.Sprintf("(%s) ", "wg0"))

	wgPrivateKey := os.Getenv("PRIVATE_KEY")
	if wgPrivateKey == "" {
		logger.Errorf("PRIVATE_KEY is empty")
		os.Exit(1)
	}

	privateKeyStr, err := base64.StdEncoding.DecodeString(wgPrivateKey)
	if err != nil {
		logger.Errorf("could not read privatekey")
		os.Exit(1)
	}

	privateKey := hex.EncodeToString(privateKeyStr)

	var sk wg.NoisePrivateKey
	if err := sk.FromMaybeZeroHex(privateKey); err != nil {
		logger.Errorf(err.Error())
		return
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 13232})
	if err != nil {
		logger.Errorf(err.Error())
		return
	}

	// Retrieve port.
	laddr := conn.LocalAddr()
	if _, err := net.ResolveUDPAddr(laddr.Network(), laddr.String()); err != nil {
		logger.Errorf(err.Error())
		return
	}
	defer conn.Close()

	logger.Verbosef("ListeningUDP on 0.0.0.0:13232")

	if err := handle(&sk, conn); err != nil {
		logger.Errorf(err.Error())
		return
	}

}

func handle(sk *wg.NoisePrivateKey, conn *net.UDPConn) error {

	peersPool := wg.NewPeers()

	for {

		var (
			n           int
			currentPeer *wg.Peer
			buf         = make([]byte, wg.MaxSegmentSize)
		)

		n, addr, err := conn.ReadFrom(buf[:])
		if err != nil {
			return err
		}

		// wireguard message type
		msgType := binary.LittleEndian.Uint32(buf[:4])

		if msgType == wg.MessageInitiationType {

			var msg wg.MessageInitiation
			reader := bytes.NewReader(buf[:n])
			err := binary.Read(reader, binary.LittleEndian, &msg)
			if err != nil {
				return errors.New(fmt.Sprintf("Failed to decode initiation message: %v", err))
			}

			var (
				chainKey [blake2s.Size]byte
				hash     [blake2s.Size]byte
			)

			publicKey := sk.PublicKey()

			wg.MixHash(&hash, &wg.InitialHash, publicKey[:])
			wg.MixHash(&hash, &hash, msg.Ephemeral[:])

			wg.MixKey(&chainKey, &wg.InitialChainKey, msg.Ephemeral[:])

			var peerPK wg.NoisePublicKey
			var key [chacha20poly1305.KeySize]byte
			ss := sk.SharedSecret(msg.Ephemeral)
			if wg.IsZero(ss[:]) {
				return errors.New("SharedSecret: ss=ItsZero")
			}

			wg.KDF2(&chainKey, &key, chainKey[:], ss[:])

			aead, err := chacha20poly1305.New(key[:])
			if err != nil {
				return err
			}

			_, err = aead.Open(peerPK[:0], wg.ZeroNonce[:], msg.Static[:], hash[:])
			if err != nil {
				return err
			}

			currentPeer, err = wg.NewPeer(logger, conn, addr, peerPK)

			if peersPool.Add(currentPeer) {
				logger.Verbosef(
					"(%s) [%s] - NewPeer",
					currentPeer.IPAddress.String(),
					currentPeer.PublicKey.String(),
				)
				currentPeer.Listen()
			}

		}

		if peer, ok := peersPool.Exists(addr); ok {
			if err := peer.WriteToRemote(buf[:n]); err != nil {
				logger.Errorf(err.Error())
			}
		}

	}
}
