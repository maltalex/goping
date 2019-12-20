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
)

func main() {
	flag.Parse()
	if flag.NArg() != 1 ||
		*timeoutParam <= 0 ||
		*intervalParam < 0.2 ||
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
	if err := pingIpv4(destinationIp, *sizeParam, *countParam, *ttlParam, *timeoutParam, interval); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to execute pingIpv4. Error: %v", err)
		os.Exit(-3)
	}
}

func pingIpv4(destinationIp net.IP, payloadLen, count, ttl, timeoutSec int, interval time.Duration) error {
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
	buf := make([]byte, maxPacketSize)
	id := uint16(rand.Int())
	stats := pingStats{}
	startTime := time.Now()
LOOP:
	for i := 0; count < 0 || i < count; i++ {
		select {
		case <-interruptChannel:
			break LOOP //Interrupted, break loop
		default:
		}
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
		for time.Now().Before(nextSendTime) {
			n, _, err := socket.Recvfrom(buf)
			switch err {
			case pingsocket.TIMEOUTERR: //Timeout, try again if there's time
				continue
			case nil: //NO-OP
			default: //unexpected error, return
				return err
			}
			rtt := time.Now().Sub(sendTime)
			if n >= minPacketSize && n <= maxPacketSize &&
				parseAndPrintICMPv4(buf[0:n], id, uint16(i)+1, destinationIp, rtt) {
				stats.received(rtt)
				break
			}
		}
		if sleepToNextInterval := nextSendTime.Sub(time.Now()); sleepToNextInterval >= minSleepBetweenPings {
			time.Sleep(sleepToNextInterval)
		}
	}
	fmt.Printf("---- %v ping statistics ---\n%v", destinationIp, stats.stats(time.Now().Sub(startTime)))
	return nil
}

func parseAndPrintICMPv4(buf []byte, expectedId, expectedSeq uint16, expectedSource net.IP, rtt time.Duration) bool {
	packet := gopacket.NewPacket(buf, layers.LayerTypeIPv4, gopacket.Default)
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		if !ip.SrcIP.Equal(expectedSource) {
			return false
		}
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			if icmp.TypeCode.Type() != 0 || icmp.TypeCode.Code() != 0 { //Echo Reply
				return false
			}
			if icmp.Seq != expectedSeq || icmp.Id != expectedId {
				return false
			}
			fmt.Printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.1f ms\n",
				ip.Length-uint16(ip.IHL)*4,
				ip.SrcIP,
				icmp.Seq,
				ip.TTL,
				float64(rtt.Microseconds())/1000,
			)
			return true
		}
	}
	return false
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
		"rtt min/avg/max/mdev = %2.3f/%2.3f/%2.3f/%2.3f ms\n",
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
