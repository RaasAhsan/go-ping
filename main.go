package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

type ICMP struct {
	Type        uint8
	Code        uint8
	Checksum    uint16
	Identifier  uint16
	SequenceNum uint16
	Data        uint32
}

// RFC: https://www.rfc-editor.org/rfc/rfc792.html

func CalculateChecksum(data []byte) uint16 {
	var checksum uint16
	var index int
	for index < len(data) {
		if index == len(data)-1 {
			checksum += uint16(data[index])
			index += 1
		} else {
			checksum += (uint16(data[index]) << 8) + uint16(data[index+1])
			index += 2
		}
	}
	return ^checksum
}

func main() {
	remoteAddr, _ := net.ResolveIPAddr("ip4", "142.251.116.138")

	conn, err := net.DialIP("ip4:icmp", nil, remoteAddr)
	if err != nil {
		fmt.Println(err)
		return
	}

	var seq uint16
	for {
		Ping(conn, seq)
		time.Sleep(time.Duration(1) * time.Second)
		seq += 1
	}
}

func Ping(conn *net.IPConn, seq uint16) {
	var buf bytes.Buffer
	var msg ICMP

	msg.Type = 8
	msg.Code = 0
	msg.Checksum = 0
	msg.SequenceNum = seq
	msg.Data = 1337

	binary.Write(&buf, binary.BigEndian, msg)

	msg.Checksum = CalculateChecksum(buf.Bytes())
	buf.Reset()
	binary.Write(&buf, binary.BigEndian, msg)

	fmt.Println(buf)

	_, err := conn.Write(buf.Bytes())
	if err != nil {
		fmt.Println(err)
		return
	}

	// fmt.Println(n)

	rbuf := make([]byte, 100)
	conn.SetReadDeadline(time.Now().Add(time.Duration(3) * time.Second))
	read, _, err := conn.ReadFromIP(rbuf)
	if err != nil {
		fmt.Println(err)
		return
	}

	// fmt.Println(read)
	// fmt.Println(rbuf)

	var reply ICMP
	binary.Read(bytes.NewReader(rbuf[:read]), binary.BigEndian, &reply)

	// TODO: Validate checksum

	// fmt.Println(reply)
	fmt.Println(reply.SequenceNum)
}
