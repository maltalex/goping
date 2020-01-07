package pingsocket

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"time"
)

const (
	MaxPacketSize = 64 * 1024
	MinPacketSize = 20 /*ip*/ + 8 /*icmp*/
)

type Pingsocket interface {
	SetTTL(ttl uint8) error
	SetReadTimeout(duration time.Duration) error
	SendTo(packet []byte, destination net.IP) error
	Recvfrom(buf []byte) (n int, from net.IP, err error)
}

type receiverResult struct {
	Ipv4     *layers.IPv4
	Icmp     *layers.ICMPv4
	RecvTime time.Time
	Err      error
}

type Receiver struct {
	socket     Pingsocket
	SignalChan chan bool
	ResultChan chan receiverResult
	buffer     []byte
}

func NewReceiver(socket Pingsocket) *Receiver {
	return &Receiver{
		socket:     socket,
		SignalChan: make(chan bool),
		ResultChan: make(chan receiverResult, 1), //buffer of 1 to avoid goroutine leak
		buffer:     make([]byte, MaxPacketSize),
	}
}

//TODO handle IPV6
func (r *Receiver) Start() {
	go func() {
		for range r.SignalChan {
			n, _, err := r.socket.Recvfrom(r.buffer)
			if err != nil || n < MinPacketSize || n > MaxPacketSize {
				r.ResultChan <- receiverResult{Err: err}
				continue
			}
			result := receiverResult{RecvTime: time.Now()}
			packet := gopacket.NewPacket(r.buffer[0:n], layers.LayerTypeIPv4, gopacket.NoCopy) //Nocopy! Buffer reused
			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				result.Ipv4 = ip
				if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
					icmp, _ := icmpLayer.(*layers.ICMPv4)
					result.Icmp = icmp
				}
			}
			r.ResultChan <- result
		}
		close(r.ResultChan)
	}()
}
