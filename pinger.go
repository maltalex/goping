package main

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/maltalex/goping/pingsocket"
	"math/rand"
	"net"
	"time"
)

const (
	MaxPacketSize = 64 * 1024
	MinPacketSize = 20 /*ip*/ + 8 /*icmp*/
)

var (
	ErrTimeout          = pingsocket.TIMEOUTERR
	ErrUnexpectedPacket = errors.New("unexpected packet")
)

type receiveResult struct {
	recvTime time.Time
	source   net.IP
	ttl      uint8
	id       uint16
	seq      uint16
	len      uint16
	err      error
}

type pinger struct {
	socket      pingsocket.Pingsocket
	id          uint16
	destination net.IP
	payload     []byte
	seqChan     chan uint16
	resultChan  chan receiveResult
}

func newPinger(socket pingsocket.Pingsocket, destination net.IP, id uint16, payloadLength int) *pinger {
	payload := make([]byte, payloadLength)
	_, _ = rand.Read(payload) //always returns nil error according to doc
	return &pinger{
		socket:      socket,
		destination: destination,
		payload:     payload,
		id:          id,
		seqChan:     make(chan uint16),
		resultChan:  make(chan receiveResult, 1), //buffer of 1 to avoid goroutine leak
	}
}

func (p *pinger) send(seq uint16) (err error) {
	serBuff := gopacket.NewSerializeBuffer()
	icmp := layers.ICMPv4{TypeCode: 0x0800 /*echo request*/, Id: p.id, Seq: seq}
	if err = gopacket.SerializeLayers(serBuff, serOptions, &icmp, gopacket.Payload(p.payload)); err != nil {
		return fmt.Errorf("error serializing ICMPv4 packet: %v", err)
	}
	return p.socket.SendTo(serBuff.Bytes(), p.destination)
}

func (p *pinger) startReceiver() {
	go func() {
		buffer := make([]byte, MaxPacketSize)
		for seq := range p.seqChan {
			n, source, err := p.socket.Recvfrom(buffer)
			receiveTime := time.Now()
			if err != nil || n < MinPacketSize || n > MaxPacketSize {
				p.resultChan <- receiveResult{recvTime: receiveTime, err: err}
				continue
			}
			parsedPacket := gopacket.NewPacket(buffer[0:n], layers.LayerTypeIPv4, gopacket.NoCopy)
			ipLayer := parsedPacket.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				p.resultChan <- receiveResult{recvTime: receiveTime, err: ErrUnexpectedPacket}
				continue
			}
			ip := ipLayer.(*layers.IPv4)
			if !ip.SrcIP.Equal(p.destination) { //Check source IP
				p.resultChan <- receiveResult{recvTime: receiveTime, err: ErrUnexpectedPacket}
				continue
			}
			icmpLayer := parsedPacket.Layer(layers.LayerTypeICMPv4)
			if icmpLayer == nil {
				p.resultChan <- receiveResult{recvTime: receiveTime, err: ErrUnexpectedPacket}
				continue
			}
			icmp := icmpLayer.(*layers.ICMPv4)
			if icmp.TypeCode.Type() != 0 || icmp.TypeCode.Code() != 0 || //Echo Reply
				icmp.Seq != seq || icmp.Id != p.id { //Check seq and id
				p.resultChan <- receiveResult{recvTime: receiveTime, err: ErrUnexpectedPacket}
				continue
			}
			p.resultChan <- receiveResult{
				recvTime: receiveTime,
				source:   source,
				len:      ip.Length - uint16(ip.IHL)*4,
				id:       icmp.Id,
				seq:      icmp.Seq,
				ttl:      ip.TTL,
			}
		} //seqChan closed
		close(p.resultChan)
	}()
}
