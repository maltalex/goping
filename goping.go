package main

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/windows"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
)

const (
	usage              = `Usage: [-c count] [-s payload size] <destination>`
	defaultPayloadSize = 56
	defaultCount       = -1
)

var (
	ErrUnknownSwitch  = errors.New("unknown switch")
	ErrShowUsage      = errors.New("bad command line arguments")
	ErrBadParameter   = errors.New("invalid parameter")
	ErrNameResolution = errors.New("could not resolve destination")
)

func main() {
	dest, payloadLen, count, err := parseArgs()
	fmt.Printf("dest: %v  payload len: %v  count: %v err: %v\n", dest, payloadLen, count, err)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n%s", err, usage)
		os.Exit(-1)
	}

	destinationAddress, err := resolveIPv4(dest)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to resolve destination %s", dest)
		os.Exit(-2)
	}

	packet, err := generateEchoRequest(payloadLen)
	fd, err := Socket(windows.AF_INET, windows.SOCK_RAW, 1)
	if err != nil {
		fmt.Print(err.Error())
	}
	destAddress := SockaddrInet4{
		Addr: destinationAddress,
	}
	err = Sendto(fd, packet, 0, &destAddress)
	if err != nil {
		log.Fatal("Sendto:", err)
	}

	buf := make([]byte, 1500)
	n, _, _ := Recvfrom(fd, buf, 0)
	parseAndPrintICMPv4(buf[0:n])
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

func parseArgs() (dest string, payloadSize int, count int, err error) {
	dest = ""
	payloadSize = defaultPayloadSize
	argCount := len(os.Args)
	if argCount < 2 {
		return "", defaultPayloadSize, defaultCount, ErrShowUsage
	}

	dest = os.Args[argCount-1]
	for i := 1; i < argCount-1; i++ {
		currentArg := os.Args[i]
		if currentArg[0] == '-' {
			switch currentArg[1] {
			case 's':
				payloadSize, err = parseNumericArgument(i, argCount)
				if payloadSize < 0 || payloadSize > 16*1024-8 {
					err = ErrBadParameter
				}
			case 'c':
				count, err = parseNumericArgument(i, argCount)
				if err != nil || count <= 0 {
					err = ErrBadParameter
				}
			default:
				err = ErrUnknownSwitch
			}
		}
	}
	return
}

func parseNumericArgument(index, argCount int) (value int, err error) {
	if index+1 < argCount-1 {
		value, err = strconv.Atoi(os.Args[index+1])
		if err != nil {
			err = ErrBadParameter
		}
		return
	}
	return 0, ErrShowUsage
}

func parseAndPrintICMPv4(buf []byte) {
	packet := gopacket.NewPacket(buf, layers.LayerTypeIPv4, gopacket.Default)
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		fmt.Printf("Source %v TTL %v\n", ip.SrcIP, ip.TTL)
	}
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		fmt.Printf("Seq %v Id %v\n", icmp.Seq, icmp.Id)
	}
}

func generateEchoRequest(payloadLen int) (buf []byte, err error) {
	icmp := &layers.ICMPv4{
		TypeCode: 0x0800,
		Id:       0,
		Seq:      0,
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
