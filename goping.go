package main

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/windows"
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"
	"unsafe"
)

const (
	usage              = `Usage: [-c count] [-s payload size] <destination>`
	maxPacketSize      = 64 * 1024
	defaultPayloadSize = 56
	defaultCount       = -1
	defaultTTL         = 64
	defaultTimeoutSec  = 1
	defaultInterval    = 1 * time.Second
)

var (
	ErrUnknownSwitch  = errors.New("unknown switch")
	ErrShowUsage      = errors.New("bad command line arguments")
	ErrBadParameter   = errors.New("invalid parameter")
	ErrNameResolution = errors.New("could not resolve destination")

	serOptions = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
)

func main() {
	dest, payloadLen, count, ttl, timeoutSec, interval, err := parseArgs()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n%s", err, usage)
		os.Exit(-1)
	}
	destinationAddress, err := resolveIPv4(dest)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to resolve destination %s", dest)
		os.Exit(-2)
	}
	if err := ping(destinationAddress, payloadLen, count, ttl, timeoutSec, interval); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to execute ping. Error: %v", err)
		os.Exit(-3)
	}
}

func ping(destinationAddress [4]byte, payloadLen, count, ttl, timeoutSec int, interval time.Duration) error {
	fd, err := Socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
	if err != nil {
		return err
	}
	var ttl8 = uint8(ttl)
	err = windows.Setsockopt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_TTL, &ttl8, 1)
	var timeoutMs = int64(1000 * timeoutSec)
	err = windows.Setsockopt(windows.Handle(fd), windows.SOL_SOCKET, 0x1006, (*byte)(unsafe.Pointer(&timeoutMs)), 4)
	if err != nil {
		return err
	}
	buf := make([]byte, maxPacketSize)
	id := uint16(rand.Int())
	destination := SockaddrInet4{
		Addr: destinationAddress,
	}
	destIp := net.IPv4(destinationAddress[0], destinationAddress[1], destinationAddress[2], destinationAddress[3])
	for i := 0; count < 0 || i < count; i++ {
		packet, err := generateEchoRequest(payloadLen, id, uint16(i)+1)
		if err != nil {
			return err
		}
		sendTime := time.Now()
		nextSendTime := sendTime.Add(interval)
		err = Sendto(fd, packet, 0, &destination)
		if err != nil {
			return err
		}
		for time.Now().Before(nextSendTime) {
			n, _, err := Recvfrom(fd, buf, 0)
			switch err {
			case windows.WSAETIMEDOUT:
				break
			case nil: //NO-OP
			default:
				return err
			}
			if n >= 0 && n <= maxPacketSize && parseAndPrintICMPv4(buf[0:n], id, uint16(i)+1, destIp, sendTime) {
				break // some other ICMP
			}
		}
		if sleepToNextInterval := nextSendTime.Sub(time.Now()); sleepToNextInterval.Microseconds() > 0 {
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

func parseArgs() (dest string, payloadSize, count, ttl, timeoutSec int, interval time.Duration, err error) {
	dest, payloadSize, count, ttl, timeoutSec, interval = "", defaultPayloadSize, defaultCount, defaultTTL, defaultTimeoutSec, defaultInterval
	argCount := len(os.Args)
	if argCount < 2 {
		return
	}
	dest = os.Args[argCount-1]
	for i := 1; i < argCount-1 && err == nil; i++ {
		if os.Args[i][0] == '-' {
			switch os.Args[i][1] {
			case 's':
				if payloadSize, err = parseIntArgument(i, argCount); payloadSize < 0 || payloadSize > 16*1024-8 {
					err = ErrBadParameter
				}
			case 't':
				if ttl, err = parseIntArgument(i, argCount); ttl < 1 || ttl > 255 {
					err = ErrBadParameter
				}
			case 'c':
				if count, err = parseIntArgument(i, argCount); err != nil || count < 1 {
					err = ErrBadParameter
				}
			case 'W':
				if timeoutSec, err = parseIntArgument(i, argCount); err != nil || timeoutSec < 1 {
					err = ErrBadParameter
				}
			case 'i':
				floatInterval, e := parseFloatArgument(i, argCount)
				if e != nil || floatInterval <= 0 || floatInterval > 60 {
					err = ErrBadParameter
				}
				interval = time.Duration(float64(time.Second) * floatInterval)
			default:
				err = ErrUnknownSwitch
			}
		}
	}
	return
}

func parseIntArgument(index, argCount int) (value int, err error) {
	value, err = 0, ErrShowUsage
	if index+1 < argCount-1 {
		if value, err = strconv.Atoi(os.Args[index+1]); err != nil {
			err = ErrBadParameter
		}
	}
	return
}

func parseFloatArgument(index, argCount int) (value float64, err error) {
	value, err = 0, ErrShowUsage
	if index+1 < argCount-1 {
		if value, err = strconv.ParseFloat(os.Args[index+1], 32); err != nil {
			err = ErrBadParameter
		}
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
			if icmp.TypeCode.Type() != 0 || icmp.TypeCode.Code() != 0 {
				return false
			}
			if icmp.Seq != expectedSeq && icmp.Id != expectedId {
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
		TypeCode: 0x0800,
		Id:       id,
		Seq:      seq,
	}
	err = gopacket.SerializeLayers(sbuf, serOptions, &icmp, gopacket.Payload(payload))
	return sbuf.Bytes(), err
}
