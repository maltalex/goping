package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/maltalex/goping/pingsocket"
	"math"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"time"
)

const (
	minSleepBetweenPings = 10 * time.Millisecond
	maxPacketSize        = 64 * 1024
	minPacketSize        = 20 /*ip*/ + 8 /*icmp*/

	usage = "Usage: goping [options] <destination>"
)

var (
	serOptions = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	timeoutParam  = flag.Int("W", 1, "Timeout, in seconds")
	intervalParam = flag.Float64("i", 1, "Interval between pings, in seconds")
	countParam    = flag.Int("c", -1, "Number of pings to send")
	ttlParam      = flag.Int("t", 64, "TTL")
	sizeParam     = flag.Int("s", 56, "Payload size")
	quietParam    = flag.Bool("q", false, "Quiet mode")
)

func main() {
	flag.Parse()
	if flag.NArg() != 1 ||
		*timeoutParam <= 0 ||
		*intervalParam < 0 ||
		*ttlParam <= 0 || *ttlParam > 255 ||
		*sizeParam < 0 || *sizeParam > maxPacketSize-minPacketSize {
		fmt.Println(usage)
		flag.PrintDefaults()
		os.Exit(-1)
	}
	destinationParam := flag.Arg(0)
	destinationAddress, err := net.ResolveIPAddr("ip4", destinationParam)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to resolve destinationParam %s. Error: %v", destinationParam, err)
		os.Exit(-2)
	}
	destinationIp := destinationAddress.IP
	fmt.Printf("PING %v (%v) %v(%v) bytes of data.\n",
		destinationParam,
		destinationIp,
		*sizeParam,
		*sizeParam+minPacketSize)
	interval := time.Duration(float64(time.Second) * (*intervalParam))
	if err := pingIpv4(destinationIp, *sizeParam, *countParam, *ttlParam, *timeoutParam, interval, *quietParam); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to execute pingIpv4. Error: %v", err)
		os.Exit(-3)
	}
}

func pingIpv4(destinationIp net.IP, payloadLen, count, ttl, timeoutSec int, interval time.Duration, quiet bool) error {
	interruptChannel := make(chan os.Signal, 1)
	signal.Notify(interruptChannel, os.Interrupt)

	socket, err := pingsocket.NewIPv4()
	if err != nil {
		return err
	}
	if err = socket.SetTTL(uint8(ttl)); err != nil {
		return err
	}
	if err = socket.SetReadTimeout(time.Duration(timeoutSec) * time.Second); err != nil {
		return err
	}
	id := uint16(rand.Int())
	stats := pingStats{}
	startTime := time.Now()
	recv := newReceiver(socket)
	recv.start()
pingLoop:
	for i := 0; count < 0 || i < count; i++ {
		packet, err := generateEchoRequest(payloadLen, id, uint16(i)+1)
		if err != nil {
			return err
		}
		sendTime := time.Now()
		nextSendTime := sendTime.Add(interval)
		err = socket.SendTo(packet, destinationIp)
		if err != nil {
			return err
		}
		stats.sent()
		receivedResponse := false
		for {
			recv.signalChan <- true //signal to receiver
			select {
			case <-interruptChannel:
				break pingLoop //Interrupted, stop pinging
			case rec := <-recv.resultChan: //received something!
				if rec.err != nil {
					if rec.err == pingsocket.TIMEOUTERR {
						break
					}
					return err
				}
				if rec.ipv4 == nil || rec.icmp == nil {
					break
				}
				if !rec.ipv4.SrcIP.Equal(destinationIp) { //Check source IP
					break
				}
				if !(rec.icmp.TypeCode.Type() == 0 && rec.icmp.TypeCode.Code() == 0) { //ICMP echo reply
					break
				}
				if rec.icmp.Seq == uint16(i)+1 && rec.icmp.Id == id { //Id and seq#
					rtt := rec.recvTime.Sub(sendTime)
					stats.received(rtt)
					receivedResponse = true
					if !quiet {
						fmt.Printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.1f ms\n",
							rec.ipv4.Length-uint16(rec.ipv4.IHL)*4,
							rec.ipv4.SrcIP,
							rec.icmp.Seq,
							rec.ipv4.TTL,
							float64(rtt.Microseconds())/1000,
						)
					}
				}
			}
			if receivedResponse || interval == 0 || time.Now().After(nextSendTime) {
				break
			}
		}
		if sleepToNextInterval := nextSendTime.Sub(time.Now()); sleepToNextInterval >= minSleepBetweenPings {
			select {
			case <-interruptChannel:
				break pingLoop
			case <-time.After(sleepToNextInterval):
				continue pingLoop
			}
		}
	}
	close(recv.signalChan)
	fmt.Printf("---- %v ping statistics ---\n%v", destinationIp, stats.stats(time.Now().Sub(startTime)))
	return nil
}

func generateEchoRequest(payloadLen int, id, seq uint16) (buf []byte, err error) {
	payload := make([]byte, payloadLen)
	_, err = rand.Read(payload)
	sbuf := gopacket.NewSerializeBuffer()
	if err != nil {
		return
	}
	icmp := layers.ICMPv4{
		TypeCode: 0x0800, //echo request
		Id:       id,
		Seq:      seq,
	}
	err = gopacket.SerializeLayers(sbuf, serOptions, &icmp, gopacket.Payload(payload))
	return sbuf.Bytes(), err
}

type pingStats struct {
	nsent, nreceived                 int
	rttMin, rttMax, rttSum, rttSumSq float64
}

func (ps *pingStats) received(rtt time.Duration) {
	rttMillis := float64(rtt.Microseconds()) / 1000
	if ps.nreceived == 0 || ps.rttMax < rttMillis {
		ps.rttMax = rttMillis
	}
	if ps.nreceived == 0 || ps.rttMin > rttMillis {
		ps.rttMin = rttMillis
	}
	ps.nreceived++
	ps.rttSum += rttMillis
	ps.rttSumSq += rttMillis * rttMillis
}

func (ps *pingStats) sent() {
	ps.nsent++
}

func (ps *pingStats) stats(totalTime time.Duration) string {
	nreceived := float64(ps.nreceived)
	packetLoss := 100.0 * (ps.nsent - ps.nreceived) / ps.nsent
	rttAvg := ps.rttSum / nreceived
	rttStdDev := math.Sqrt(ps.rttSumSq/nreceived - (ps.rttSum/nreceived)*(ps.rttSum/nreceived))
	return fmt.Sprintf("%v packets transmitted, %v received, %v%% packet loss, time %vms\n"+
		"rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
		ps.nsent,
		ps.nreceived,
		packetLoss,
		totalTime.Milliseconds(),
		ps.rttMin,
		rttAvg,
		ps.rttMax,
		rttStdDev,
	)
}

type receiverResult struct {
	ipv4     *layers.IPv4
	icmp     *layers.ICMPv4
	recvTime time.Time
	err      error
}

type receiver struct {
	socket     pingsocket.IPv4
	signalChan chan bool
	resultChan chan receiverResult
	buffer     []byte
}

func newReceiver(socket pingsocket.IPv4) *receiver {
	return &receiver{
		socket:     socket,
		signalChan: make(chan bool),
		resultChan: make(chan receiverResult, 1), //buffer of 1 to avoid goroutine leak
		buffer:     make([]byte, maxPacketSize),
	}
}

func (r *receiver) start() {
	go func() {
		for range r.signalChan {
			n, _, err := r.socket.Recvfrom(r.buffer)
			if err != nil || n < minPacketSize || n > maxPacketSize {
				r.resultChan <- receiverResult{err: err}
				continue
			}
			result := receiverResult{recvTime: time.Now()}
			packet := gopacket.NewPacket(r.buffer[0:n], layers.LayerTypeIPv4, gopacket.NoCopy) //Nocopy! Buffer reused
			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				result.ipv4 = ip
				if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
					icmp, _ := icmpLayer.(*layers.ICMPv4)
					result.icmp = icmp
				}
			}
			r.resultChan <- result
		}
		close(r.resultChan)
	}()
}
