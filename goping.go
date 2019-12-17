package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/maltalex/goping/pingsocket"
	"math/rand"
	"net"
	"os"
	"time"
)

const (
	minSleepBetweenPings = 10 * time.Millisecond
	maxPacketSize        = 64 * 1024
	minPacketSize        = 20 /*ip*/ + 8 /*icmp*/

	usage = "Usage: goping [options] <destination>"
)

var (
	ErrNameResolution = errors.New("could not resolve destination")

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
	destination := flag.Arg(0)
	destinationAddress, err := resolveIPv4(destination)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to resolve destination %s. Error: %v", destination, err)
		os.Exit(-2)
	}
	if err := ping(destinationAddress, *sizeParam, *countParam, *ttlParam, *timeoutParam, time.Duration(float64(time.Second)*(*intervalParam))); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to execute ping. Error: %v", err)
		os.Exit(-3)
	}
}

func ping(destinationAddress [4]byte, payloadLen, count, ttl, timeoutSec int, interval time.Duration) error {
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
	destIp := net.IPv4(destinationAddress[0], destinationAddress[1], destinationAddress[2], destinationAddress[3])
	for i := 0; count < 0 || i < count; i++ {
		packet, err := generateEchoRequest(payloadLen, id, uint16(i)+1)
		if err != nil {
			return err
		}
		sendTime := time.Now()
		nextSendTime := sendTime.Add(interval)
		err = socket.SendTo(packet, destinationAddress)
		if err != nil {
			return err
		}
		for time.Now().Before(nextSendTime) {
			n, _, err := socket.Recvfrom(buf)
			switch err {
			case pingsocket.TIMEOUTERR: //Timeout, try again if there's time
				break
			case nil: //NO-OP
			default: //unexpected error, return
				return err
			}
			if n >= minPacketSize && n <= maxPacketSize && parseAndPrintICMPv4(buf[0:n], id, uint16(i)+1, destIp, sendTime) {
				break // some other ICMP
			}
		}
		if sleepToNextInterval := nextSendTime.Sub(time.Now()); sleepToNextInterval >= minSleepBetweenPings {
			time.Sleep(sleepToNextInterval)
		}
	}
	return nil
}

func resolveIPv4(name string) (address [4]byte, err error) {
	res, err := net.ResolveIPAddr("ip4", name)
	if err != nil || res.IP.To4() == nil {
		err = ErrNameResolution
		return
	}
	ipLen := len(res.IP)
	for i := 0; i < 4; i++ {
		address[i] = res.IP[ipLen-4+i]
	}
	return
}

func parseAndPrintICMPv4(buf []byte, expectedId, expectedSeq uint16, expectedSource net.IP, sendTime time.Time) bool {
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
			rtt := float64(time.Now().Sub(sendTime).Microseconds()) / 1000
			fmt.Printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.1f ms\n", ip.Length-uint16(ip.IHL)*4, ip.SrcIP, icmp.Seq, ip.TTL, rtt)
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
