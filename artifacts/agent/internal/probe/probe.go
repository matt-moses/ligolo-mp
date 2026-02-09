package probe

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/ttpreport/ligolo-mp-agent/internal/protocol"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ProbeTarget probes a single target IP using the specified method
func ProbeTarget(target string, method string, tcpPorts []int32, udpPort int32, timeoutMs int32) protocol.ProbeResult {
	timeout := time.Duration(timeoutMs) * time.Millisecond

	switch method {
	case "icmp":
		return ProbeICMP(target, timeout)
	case "tcp":
		return ProbeTCP(target, tcpPorts, timeout)
	case "udp":
		return ProbeUDP(target, udpPort, timeout)
	case "auto":
		// Try ICMP first
		if result := ProbeICMP(target, timeout); result.IsReachable {
			return result
		}
		// Fallback to TCP
		if result := ProbeTCP(target, tcpPorts, timeout); result.IsReachable {
			return result
		}
		// Fallback to UDP
		if result := ProbeUDP(target, udpPort, timeout); result.IsReachable {
			return result
		}
		// All failed
		return protocol.ProbeResult{
			Target:      target,
			IsReachable: false,
			Error:       "all probe methods failed",
		}
	default:
		return protocol.ProbeResult{
			Target:      target,
			IsReachable: false,
			Error:       fmt.Sprintf("unknown probe method: %s", method),
		}
	}
}

// ProbeICMP attempts an ICMP echo request
func ProbeICMP(target string, timeout time.Duration) protocol.ProbeResult {
	start := time.Now()

	// Create ICMP connection
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return protocol.ProbeResult{
			Target:      target,
			IsReachable: false,
			Error:       fmt.Sprintf("icmp listen failed: %v", err),
		}
	}
	defer conn.Close()

	// Set deadline
	conn.SetDeadline(time.Now().Add(timeout))

	// Create echo request
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   1,
			Seq:  1,
			Data: []byte("LIGOLO-PROBE"),
		},
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return protocol.ProbeResult{
			Target:      target,
			IsReachable: false,
			Error:       fmt.Sprintf("icmp marshal failed: %v", err),
		}
	}

	// Resolve target
	addr, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		return protocol.ProbeResult{
			Target:      target,
			IsReachable: false,
			Error:       fmt.Sprintf("resolve failed: %v", err),
		}
	}

	// Send ping
	_, err = conn.WriteTo(msgBytes, addr)
	if err != nil {
		return protocol.ProbeResult{
			Target:      target,
			IsReachable: false,
			Error:       fmt.Sprintf("icmp send failed: %v", err),
		}
	}

	// Wait for reply
	reply := make([]byte, 1500)
	n, peer, err := conn.ReadFrom(reply)
	if err != nil {
		return protocol.ProbeResult{
			Target:      target,
			IsReachable: false,
			Error:       fmt.Sprintf("icmp timeout: %v", err),
		}
	}

	latency := time.Since(start)

	// Parse reply
	rm, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), reply[:n])
	if err != nil {
		return protocol.ProbeResult{
			Target:      target,
			IsReachable: false,
			Error:       fmt.Sprintf("icmp parse failed: %v", err),
		}
	}

	if rm.Type == ipv4.ICMPTypeEchoReply && peer.(*net.IPAddr).IP.Equal(addr.IP) {
		return protocol.ProbeResult{
			Target:      target,
			IsReachable: true,
			LatencyMs:   int32(latency.Milliseconds()),
			Method:      "icmp",
		}
	}

	return protocol.ProbeResult{
		Target:      target,
		IsReachable: false,
		Error:       "icmp reply mismatch",
	}
}

// ProbeTCP attempts TCP connections on common ports
func ProbeTCP(target string, ports []int32, timeout time.Duration) protocol.ProbeResult {
	// Default ports if not specified
	if len(ports) == 0 {
		ports = []int32{22, 80, 135, 139, 443, 445, 3389, 8080}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for _, port := range ports {
		start := time.Now()

		var d net.Dialer
		addr := fmt.Sprintf("%s:%d", target, port)
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			continue // Try next port
		}
		conn.Close()

		latency := time.Since(start)
		return protocol.ProbeResult{
			Target:      target,
			IsReachable: true,
			LatencyMs:   int32(latency.Milliseconds()),
			Method:      fmt.Sprintf("tcp:%d", port),
		}
	}

	return protocol.ProbeResult{
		Target:      target,
		IsReachable: false,
		Error:       fmt.Sprintf("all tcp ports unreachable: %v", ports),
	}
}

// ProbeUDP attempts a UDP probe (DNS query on port 53)
func ProbeUDP(target string, port int32, timeout time.Duration) protocol.ProbeResult {
	// Default to DNS port
	if port == 0 {
		port = 53
	}

	start := time.Now()

	addr := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return protocol.ProbeResult{
			Target:      target,
			IsReachable: false,
			Error:       fmt.Sprintf("udp dial failed: %v", err),
		}
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	// Send simple DNS query (query for ".")
	query := []byte{
		0x00, 0x01, // Transaction ID
		0x01, 0x00, // Flags (standard query)
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answers: 0
		0x00, 0x00, // Authority: 0
		0x00, 0x00, // Additional: 0
		0x00,       // Root
		0x00, 0x01, // Type: A
		0x00, 0x01, // Class: IN
	}

	_, err = conn.Write(query)
	if err != nil {
		return protocol.ProbeResult{
			Target:      target,
			IsReachable: false,
			Error:       fmt.Sprintf("udp write failed: %v", err),
		}
	}

	// Wait for response
	reply := make([]byte, 512)
	_, err = conn.Read(reply)
	if err != nil {
		return protocol.ProbeResult{
			Target:      target,
			IsReachable: false,
			Error:       fmt.Sprintf("udp timeout: %v", err),
		}
	}

	latency := time.Since(start)
	return protocol.ProbeResult{
		Target:      target,
		IsReachable: true,
		LatencyMs:   int32(latency.Milliseconds()),
		Method:      fmt.Sprintf("udp:%d", port),
	}
}
