package main

// Mostly based on https://github.com/golang/net/blob/master/icmp/ping_test.go
// All ye beware, there be dragons below...

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"log"
	"net"
	"os"
	"time"
)

const (
	// From https://godoc.org/golang.org/x/net/internal/iana,
	// can't import "internal" packages
	AttemptsCount = 3
	MaxTTL = 64
	MaxWaitSec = 10
	ProtocolIPv4ICMP = 1
	ProtocolIPv6ICMP = 58
)

func hexDump(title string, data []byte) {
	if len(title) == 0 {
		title = "DUMP"
	}

	title = fmt.Sprintf("%s (%d bytes)", title, len(data))
	log.Printf("----------- %s ----------->>>", title)
	log.Printf("\n%s", hex.Dump(data))
	log.Printf("<<<-------- %s --------------", title)
}

func buildICMP(t icmp.Type, size int) ([]byte, error) {
	var buf bytes.Buffer

	template := []byte("iXasthurICMP!")
	for count := size / len(template); count > 0; count-- {
		buf.Write(template)
	}

	if diff := size - buf.Len(); diff > 0 {
		buf.Write(template[:diff])
	}

	msg := icmp.Message{
		Type: t,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: buf.Bytes(),
		},
	}

	return msg.Marshal(nil)
}

func Ping(addr string, b []byte, ttl int, attempts int) ([]time.Duration, []net.Addr, *ipv4.ICMPType, error) {
	var err error

	// Creates listening socket
	var connection net.PacketConn
	connection, err = net.ListenPacket("ip4:icmp", "0.0.0.0")

	if err != nil {
		return []time.Duration{}, []net.Addr{}, nil, err
	}
	defer connection.Close()

	// Get the real IP of the target if needed
	var destination *net.IPAddr
	destination, err = net.ResolveIPAddr("ip4", addr)

	if err != nil {
		return []time.Duration{0}, []net.Addr{}, nil, err
	}

	// Configures connection
	err = connection.SetReadDeadline(time.Now().Add(MaxWaitSec * time.Second))
	if err != nil {
		return []time.Duration{0}, []net.Addr{}, nil, err
	}

	// Sets TTL
	p := ipv4.NewPacketConn(connection)
	p.SetTTL(ttl)


	var durationsArray []time.Duration
	var peersArray []net.Addr
	var peer net.Addr
	var msg *icmp.Message
	var reply []byte
	var replyLength int
	var t ipv4.ICMPType = ipv4.ICMPTypeTimeExceeded

	for i := 0; i<attempts; i++ {
		// Sends ICMP Package
		start := time.Now()
		n, err := connection.WriteTo(b, destination)
		if err != nil {
			return []time.Duration{0}, []net.Addr{}, nil, err
		} else if n != len(b) {
			return []time.Duration{0}, []net.Addr{}, nil, fmt.Errorf("got %v; want %v", n, len(b))
		}

		// Reads from socket
		reply = make([]byte, 1500)
		replyLength, peer, err = connection.ReadFrom(reply)

		if err != nil {
			return []time.Duration{0}, []net.Addr{}, nil, err
		}
		duration := time.Since(start)

		durationsArray = append(durationsArray,duration)
		peersArray = append(peersArray,peer)

		// Parses last ICMP message
		msg, err = icmp.ParseMessage(ProtocolIPv4ICMP, reply[:replyLength])
		if err != nil {
			return []time.Duration{0}, []net.Addr{}, nil, err
		}

		if msg.Type == ipv4.ICMPTypeEchoReply {
			t = ipv4.ICMPTypeEchoReply
		}
	}


	switch t {
	case ipv4.ICMPTypeEchoReply:
		// Reached destination
		return durationsArray, peersArray, &t, nil
	case ipv4.ICMPTypeTimeExceeded:
		// TTL Exceeded
		return durationsArray, peersArray, &t, nil
	default:
		// Invalid ICMPType
		return []time.Duration{0}, []net.Addr{}, nil, fmt.Errorf("got %+v from %v; Invalid ICMPType", msg, peer)
	}
}

func ping(addr string, ttl int) bool {
	msg, _ := buildICMP(ipv4.ICMPTypeEcho,56)
	durationsArray, peersArray, t, err := Ping(addr, msg, ttl, AttemptsCount)

	var peersAreIdentical bool = true
	for i := 0; i<len(peersArray)-1; i++ {
		if peersArray[i].String() != peersArray[i+1].String(){
			peersAreIdentical = false
		}
	}

	if err == nil {
		if t != nil {
			switch *t {
			case ipv4.ICMPTypeEchoReply:
				if peersAreIdentical {
					ptr, _ := net.LookupAddr(peersArray[0].String())
					log.Printf("%3d %10s    Reached %16v %v", ttl, durationsArray, peersArray[0], ptr)
				} else {
					log.Printf("%3d %10s    Reached %16v", ttl, durationsArray, peersArray)
				}
				return true
			case ipv4.ICMPTypeTimeExceeded:
				if peersAreIdentical {
					ptr, _ := net.LookupAddr(peersArray[0].String())
					log.Printf("%3d %10s  TTLExc at %16v %v", ttl, durationsArray, peersArray[0], ptr)
				} else {
					log.Printf("%3d %10s  TTLExc at %16v", ttl, durationsArray, peersArray)
				}
				return false
			default:
				return false
			}
		}
	} else {
		log.Printf("%3d ERROR: %s", ttl, err)
		return false
	}
	return false
}

func tracert(addr string) {
	log.Printf("Tracing route to %s with MaxTTL = %d", addr, MaxTTL)
	for i := 1; i <= MaxTTL; i++ {
		if ping(addr, i) {
			break
		}
	}
	log.Printf("Ended tracert")
}

func main() {
	tracert("8.8.8.8")
}
