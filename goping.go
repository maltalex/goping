package main

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"
)

const (
	usage              = `Usage: [-c count] [-s payload size] <destination>`
	defaultPayloadSize = 56
	defaultCount       = 4
	defaultSleep       = 1 * time.Second
)

var (
	ErrUnknownSwitch  = errors.New("unknown switch")
	ErrShowUsage      = errors.New("bad command line arguments")
	ErrBadParameter   = errors.New("invalid parameter")
	ErrNameResolution = errors.New("could not resolve destination")
)

func main() {
	dest, payloadLen, count, sleepDuration, err := parseArgs()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n%s", err, usage)
		os.Exit(-1)
	}
	destinationAddress, err := resolveIPv4(dest)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to resolve destination %s", dest)
		os.Exit(-2)
	}
	if err := ping(destinationAddress, payloadLen, count, sleepDuration); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to execute ping. Error: %v", err)
		os.Exit(-3)
	}
}

func ping(destinationAddress [4]byte, payloadLen int, count int, sleepDuration time.Duration) error {
	fd, err := Socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
	if err != nil {
		return err
	}
	destAddress := SockaddrInet4{
		Addr: destinationAddress,
	}
	buf := make([]byte, 1500)
	id := rand.Int()
	for i := 0; i < count; i++ {
		sendTime := time.Now()
		packet, err := generateEchoRequest(payloadLen, uint16(id), uint16(i)+1)
		if err != nil {
			return err
		}
		err = Sendto(fd, packet, 0, &destAddress)
		if err != nil {
			return err
		}
		n, _, err := Recvfrom(fd, buf, 0)
		if err != nil {
			return err
		}
		rtt := float32(time.Now().UnixNano()-sendTime.UnixNano()) / 1e6
		parseAndPrintICMPv4(buf[0:n], rtt)
		time.Sleep(sleepDuration)
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

func parseArgs() (dest string, payloadSize int, count int, sleepDuration time.Duration, err error) {
	dest = ""
	payloadSize = defaultPayloadSize
	argCount := len(os.Args)
	if argCount < 2 {
		return "", defaultPayloadSize, defaultCount, defaultSleep, ErrShowUsage
	}

	dest = os.Args[argCount-1]
	for i := 1; i < argCount-1; i++ {
		currentArg := os.Args[i]
		if currentArg[0] == '-' {
			switch currentArg[1] {
			case 's':
				if payloadSize, err = parseIntNumericArgument(i, argCount); payloadSize < 0 || payloadSize > 16*1024-8 {
					err = ErrBadParameter
					return
				}
			case 'c':
				if count, err = parseIntNumericArgument(i, argCount); err != nil || count <= 0 {
					err = ErrBadParameter
					return
				}
			case 'i':
				floatInterval, e := parseFloatNumericArgument(i, argCount)
				if e != nil || floatInterval <= 0 || floatInterval > 60 {
					err = ErrBadParameter
					return
				}
				sleepDuration = time.Duration(float64(time.Second) * floatInterval)
			default:
				err = ErrUnknownSwitch
			}
		}
	}
	return
}

func parseIntNumericArgument(index, argCount int) (value int, err error) {
	if index+1 < argCount-1 {
		value, err = strconv.Atoi(os.Args[index+1])
		if err != nil {
			err = ErrBadParameter
		}
		return
	}
	return 0, ErrShowUsage
}

func parseFloatNumericArgument(index, argCount int) (value float64, err error) {
	if index+1 < argCount-1 {
		value, err = strconv.ParseFloat(os.Args[index+1], 32)
		if err != nil {
			err = ErrBadParameter
		}
		return
	}
	return 0, ErrShowUsage
}

func parseAndPrintICMPv4(buf []byte, rtt float32) {
	packet := gopacket.NewPacket(buf, layers.LayerTypeIPv4, gopacket.Default)
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			fmt.Printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.1f ms\n", ip.Length-uint16(ip.IHL)*4, ip.SrcIP, icmp.Seq, ip.TTL, rtt)
		}
	}
}

func generateEchoRequest(payloadLen int, id, seq uint16) (buf []byte, err error) {
	icmp := &layers.ICMPv4{
		TypeCode: 0x0800,
		Id:       id,
		Seq:      seq,
	}
	sbuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	payload := make([]byte, payloadLen)
	for i := 0; i < payloadLen; i++ {
		payload[i] = byte(rand.Int())
	}
	err = gopacket.SerializeLayers(sbuf, opts, icmp, gopacket.Payload(payload))
	return sbuf.Bytes(), err
}
