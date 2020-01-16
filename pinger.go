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

	serOptionsIpv6 = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: false,
	}
	serOptionsIpv4 = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
)

type ReceiveResult struct {
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
	ipv4        bool
	id          uint16
	destination net.IP
	payload     []byte
	seqChan     chan uint16
	resultChan  chan ReceiveResult
}

func NewPinger(destination net.IP, payloadLength int) *pinger {
	payload := make([]byte, payloadLength)
	rand.Seed(time.Now().UnixNano())
	_, _ = rand.Read(payload) //always returns nil error according to doc

	return &pinger{
		ipv4:        destination.To4() != nil,
		destination: destination,
		payload:     payload,
		id:          uint16(rand.Uint32()),
		seqChan:     make(chan uint16),
		resultChan:  make(chan ReceiveResult, 1), //buffer of 1 to avoid goroutine leak
	}
}

func (p *pinger) Init(ttl uint8, timeout time.Duration) (err error) {
	if p.ipv4 {
		p.socket, err = pingsocket.NewIPv4()
	} else {
		p.socket, err = pingsocket.NewIPv6()
	}
	if err != nil {
		return fmt.Errorf("failed to create socket: %v", err)
	}
	if err := p.socket.SetTTL(uint8(ttl)); err != nil {
		return fmt.Errorf("failed to set socket TTL to %v: %v", ttl, err)
	}
	if err := p.socket.SetReadTimeout(timeout); err != nil {
		return fmt.Errorf("failed to set read timeout to %v: %v", timeout, err)
	}
	return nil
}

func (p *pinger) Send(seq uint16) (err error) {
	serBuff := gopacket.NewSerializeBuffer()
	if p.ipv4 {
		icmp := &layers.ICMPv4{TypeCode: 0x0800 /*echo request*/, Id: p.id, Seq: seq}
		if err = gopacket.SerializeLayers(serBuff, serOptionsIpv4, icmp, gopacket.Payload(p.payload)); err != nil {
			return fmt.Errorf("error serializing ICMPv4 packet: %v", err)
		}
	} else {
		icmp := &layers.ICMPv6{TypeCode: 0x8000 /*echo request*/}
		echo := &layers.ICMPv6Echo{Identifier: p.id, SeqNumber: seq}
		if err = gopacket.SerializeLayers(serBuff, serOptionsIpv6, icmp, echo, gopacket.Payload(p.payload)); err != nil {
			return fmt.Errorf("error serializing ICMPv6 packet: %v", err)
		}
	}
	return p.socket.SendTo(serBuff.Bytes(), p.destination)
}

func (p *pinger) StartReceiver() {
	if p.ipv4 {
		go func() {
			p.ipv4Receiver()
		}()
	} else {
		go func() {
			p.ipv6Receiver()
		}()
	}
}

func (p *pinger) ipv6Receiver() {
	buffer := make([]byte, MaxPacketSize)
	for seq := range p.seqChan {
		n, source, err := p.socket.Recvfrom(buffer)
		receiveTime := time.Now()
		if err != nil || n < MinPacketSize || n > MaxPacketSize {
			p.resultChan <- ReceiveResult{recvTime: receiveTime, err: err}
			continue
		}
		//recvfrom on an IPv6 raw socket dosen't return the IP header (rfc3542)
		parsedPacket := gopacket.NewPacket(buffer[0:n], layers.LayerTypeICMPv6, gopacket.NoCopy)
		icmpLayer := parsedPacket.Layer(layers.LayerTypeICMPv6)
		if icmpLayer == nil {
			p.resultChan <- ReceiveResult{recvTime: receiveTime, err: ErrUnexpectedPacket}
			continue
		}
		echoLayer := parsedPacket.Layer(layers.LayerTypeICMPv6Echo)
		if echoLayer == nil {
			p.resultChan <- ReceiveResult{recvTime: receiveTime, err: ErrUnexpectedPacket}
			continue
		}
		echo := echoLayer.(*layers.ICMPv6Echo)
		if echo.SeqNumber != seq || echo.Identifier != p.id { //Check seq and id
			p.resultChan <- ReceiveResult{recvTime: receiveTime, err: ErrUnexpectedPacket}
			continue
		}
		p.resultChan <- ReceiveResult{
			recvTime: receiveTime,
			source:   source,
			len:      uint16(len(echo.Payload)),
			id:       echo.Identifier,
			seq:      echo.SeqNumber,
			//ttl:      ip.TTL, //TODO use recvMsg to get ttl
		}
	}
	close(p.resultChan)
	_ = p.socket.Close()
}

func (p *pinger) ipv4Receiver() {
	buffer := make([]byte, MaxPacketSize)
	for seq := range p.seqChan {
		n, source, err := p.socket.Recvfrom(buffer)
		receiveTime := time.Now()
		if err != nil || n < MinPacketSize || n > MaxPacketSize {
			p.resultChan <- ReceiveResult{recvTime: receiveTime, err: err}
			continue
		}
		parsedPacket := gopacket.NewPacket(buffer[0:n], layers.LayerTypeIPv4, gopacket.NoCopy)
		ipLayer := parsedPacket.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			p.resultChan <- ReceiveResult{recvTime: receiveTime, err: ErrUnexpectedPacket}
			continue
		}
		ip := ipLayer.(*layers.IPv4)
		if !ip.SrcIP.Equal(p.destination) { //Check source IP
			p.resultChan <- ReceiveResult{recvTime: receiveTime, err: ErrUnexpectedPacket}
			continue
		}
		icmpLayer := parsedPacket.Layer(layers.LayerTypeICMPv4)
		if icmpLayer == nil {
			p.resultChan <- ReceiveResult{recvTime: receiveTime, err: ErrUnexpectedPacket}
			continue
		}
		icmp := icmpLayer.(*layers.ICMPv4)
		if icmp.TypeCode.Type() != 0 || icmp.TypeCode.Code() != 0 || //Echo Reply
			icmp.Seq != seq || icmp.Id != p.id { //Check seq and id
			p.resultChan <- ReceiveResult{recvTime: receiveTime, err: ErrUnexpectedPacket}
			continue
		}
		p.resultChan <- ReceiveResult{
			recvTime: receiveTime,
			source:   source,
			len:      ip.Length - uint16(ip.IHL)*4,
			id:       icmp.Id,
			seq:      icmp.Seq,
			ttl:      ip.TTL,
		}
	}
	close(p.resultChan)
	_ = p.socket.Close()
}
