package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
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
		*sizeParam < 0 || *sizeParam > MaxPacketSize-MinPacketSize {
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
	interval := time.Duration(float64(time.Second) * (*intervalParam))
	interruptChannel := make(chan os.Signal, 1)
	signal.Notify(interruptChannel, os.Interrupt)
	fmt.Printf("PING %v (%v) %v(%v) bytes of data.\n",
		destinationParam,
		destinationAddress.IP,
		*sizeParam,
		*sizeParam+MinPacketSize)

	if err := ping(
		interruptChannel,
		destinationAddress.IP,
		*sizeParam,
		*countParam,
		*ttlParam,
		*timeoutParam,
		interval,
		*quietParam); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to execute pingIpv4. Error: %v", err)
		os.Exit(-3)
	}
}

func ping(interruptChannel chan os.Signal,
	destinationIp net.IP,
	payloadLen, count, ttl, timeoutSec int,
	interval time.Duration,
	quiet bool) (err error) {

	socket, err := pingsocket.NewIPv4()
	if err != nil {
		return err
	}
	if err := socket.SetTTL(uint8(ttl)); err != nil {
		return err
	}
	if err := socket.SetReadTimeout(time.Duration(timeoutSec) * time.Second); err != nil {
		return err
	}
	pinger := newPinger(socket, destinationIp, uint16(rand.Uint32()), payloadLen)
	var stats pingStats
	startTime := time.Now()
	pinger.startReceiver()
pingLoop:
	for i := 0; count < 0 || i < count; i++ {
		if err := pinger.send(uint16(i) + 1); err != nil {
			return err
		}
		sendTime := time.Now()
		nextSendTime := sendTime.Add(interval)
		stats.sent()

		receivedResponse := false
		for {
			pinger.seqChan <- uint16(i) + 1
			select {
			case <-interruptChannel:
				break pingLoop //Interrupted, stop pinging
			case received := <-pinger.resultChan: //received something!
				if received.err != nil {
					if received.err == ErrUnexpectedPacket || received.err == ErrTimeout {
						break //break select
					}
					return err
				}
				rtt := received.recvTime.Sub(sendTime)
				stats.received(rtt)
				receivedResponse = true
				if quiet {
					break
				}
				fmt.Printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.1f ms\n",
					received.len,
					received.source,
					received.seq,
					received.ttl,
					float64(rtt.Microseconds())/1000,
				)
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
	close(pinger.seqChan)
	_ = socket.Close()
	fmt.Printf("---- %v ping statistics ---\n%v", destinationIp, stats.stats(time.Now().Sub(startTime)))
	return nil
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
