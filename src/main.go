package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	AttemptsCount = 3
	MaxTTL = 64
	MaxWaitSec = 4
	MsgLength = 56

	// From https://godoc.org/golang.org/x/net/internal/iana
	ProtocolIPv4ICMP = 1
	ProtocolIPv6ICMP = 58
)

func hexDump(title string, data []byte) {
	if len(title) == 0 {
		title = "DUMP"
	}


	title = fmt.Sprintf("%s (%d bytes)", title, len(data))
	fmt.Printf("----------- %s ----------->>>", title)
	fmt.Printf("\n%s", hex.Dump(data))
	fmt.Printf("<<<-------- %s --------------\n", title)
}

func buildICMP(t icmp.Type, size int) ([]byte, error) {
	var buf bytes.Buffer

	template := []byte("ICMP!")
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

func socExchange(destination *net.IPAddr, b []byte, ttl int, attempts int) ([]time.Duration, []net.Addr, *ipv4.ICMPType, error) {
	var err error

	// Creates listening socket
	var connection net.PacketConn
	connection, err = net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return []time.Duration{}, []net.Addr{}, nil, err
	}
	defer connection.Close()

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

		//fmt.Print("\n")
		//var dumpTitle = strconv.Itoa(i+1) + ": ICMP TO BE SENT TTL = " + strconv.Itoa(ttl)
		//hexDump(dumpTitle, b)

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

		//fmt.Print("\n")
		//dumpTitle = strconv.Itoa(i+1) + ": ICMP REPLY"
		//hexDump(dumpTitle, reply[:replyLength])

		duration := time.Since(start)

		durationsArray = append(durationsArray,duration)
		peersArray = append(peersArray,peer)

		// Parses ICMP message
		msg, err = icmp.ParseMessage(ProtocolIPv4ICMP, reply[:replyLength])
		if err != nil {
			return []time.Duration{0}, []net.Addr{}, nil, err
		}

		//hexDump("", reply[:replyLength])
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

func createPeersString(peersArray []net.Addr) string {
	var peersAreIdentical bool = true
	for i := 0; i<len(peersArray)-1; i++ {
		if peersArray[i].String() != peersArray[i+1].String(){
			peersAreIdentical = false
		}
	}

	if peersAreIdentical {
		peersArray = []net.Addr{peersArray[0]}
	}

	var buffStr string = "["
	for i := 0; i<len(peersArray);i++ {
		ptr, _ := net.LookupAddr(peersArray[0].String())
		var ptrStr string = ""
		if len(ptr)>0{
			ptrStr = " ("
			for j := 0; j<len(ptr); j++ {
				ptrStr = ptrStr + ptr[j][:len(ptr[j])-1] + "  "
			}
			ptrStr = ptrStr[:len(ptrStr)-2]
			ptrStr = ptrStr + ")"
		}
		buffStr = buffStr + peersArray[i].String() + ptrStr + "  "
	}
	buffStr = buffStr[:len(buffStr)-2]
	buffStr = buffStr + "]"
	return buffStr
}

func ping(dest *net.IPAddr, ttl int) bool {
	msg, _ := buildICMP(ipv4.ICMPTypeEcho,MsgLength)
	durationsArray, peersArray, t, err := socExchange(dest, msg, ttl, AttemptsCount)

	if err == nil {
		if t != nil {
			switch *t {
			case ipv4.ICMPTypeEchoReply:
				fmt.Printf("%3d %13s     Reached  %s\n", ttl, durationsArray, createPeersString(peersArray))
				return true
			case ipv4.ICMPTypeTimeExceeded:
				fmt.Printf("%3d %13s   TTLExc at  %s\n", ttl, durationsArray, createPeersString(peersArray))
				return false
			default:
				return false
			}
		}
	} else {
		fmt.Printf("%3d ERROR: %s\n", ttl, err)
		return false
	}
	return false
}

func tracert(addr string) {
	fmt.Printf("Tracing route to %s with MaxTTL = %d\n", addr, MaxTTL)
	// Get the real IP of the target if needed
	destination, err := net.ResolveIPAddr("ip4", addr)
	if err != nil {
		fmt.Printf("Invalid address %s\n", addr)
		return
	}

	for i := 1; i <= MaxTTL; i++ {
		if ping(destination, i) {
			break
		}
	}

	fmt.Printf("Ended tracert\n")
}

func main() {
	if len(os.Args) == 2 {
		var input string = os.Args[1]
		tracert(input)
	} else {
		fmt.Printf("Usage: 1 param - address\n")
	}
}
