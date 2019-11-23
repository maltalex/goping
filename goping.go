package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/windows"
	"log"
	"math/rand"
)

func main() {
	packet, err := generateEchoRequest(100)
	fd, err := Socket(windows.AF_INET, windows.SOCK_RAW, 1)
	if err != nil {
		fmt.Print(err.Error())
	}
	destAddress := SockaddrInet4{
		Port: 0,
		Addr: [4]byte{10, 0, 0, 1},
	}
	err = Sendto(fd, packet, 0, &destAddress)
	if err != nil {
		log.Fatal("Sendto:", err)
	}

	buf := make([]byte, 1500)
	n, _, _ := Recvfrom(fd, buf, 0)
	parseAndPrintICMPv4(buf[0:n])
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
