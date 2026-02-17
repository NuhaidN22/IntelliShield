package main

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// FlowFeatures represents extracted features from network traffic
type FlowFeatures struct {
	// Basic packet info
	Timestamp       time.Time
	SourceIP        string
	DestinationIP   string
	SourcePort      uint16
	DestinationPort uint16
	Protocol        string

	// Size features
	PacketLength  int
	HeaderLength  int
	PayloadLength int

	// Protocol flags
	IsTCP  bool
	IsUDP  bool
	IsICMP bool

	// TCP specific features
	TCPFlags string // SYN, ACK, FIN, RST, PSH, URG
	HasSYN   bool
	HasACK   bool
	HasFIN   bool
	HasRST   bool

	// Timing
	InterArrivalTime float64 // Time since last packet (milliseconds)
}

// FeatureExtractor extracts features from packets
type FeatureExtractor struct {
	lastPacketTime time.Time
}

// NewFeatureExtractor creates a new feature extractor
func NewFeatureExtractor() *FeatureExtractor {
	return &FeatureExtractor{
		lastPacketTime: time.Now(),
	}
}

// Extract extracts features from a single packet
func (fe *FeatureExtractor) Extract(packet gopacket.Packet) *FlowFeatures {
	features := &FlowFeatures{
		Timestamp:    packet.Metadata().Timestamp,
		PacketLength: len(packet.Data()),
	}

	// Calculate inter-arrival time (time since last packet)
	if !fe.lastPacketTime.IsZero() {
		features.InterArrivalTime = float64(packet.Metadata().Timestamp.Sub(fe.lastPacketTime).Milliseconds())
	}
	fe.lastPacketTime = packet.Metadata().Timestamp

	// Extract network layer (IP)
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		features.SourceIP = ip.SrcIP.String()
		features.DestinationIP = ip.DstIP.String()
		features.HeaderLength = int(ip.IHL) * 4
		features.Protocol = ip.Protocol.String()
	}

	// Extract transport layer (TCP/UDP)
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		features.IsTCP = true
		features.SourcePort = uint16(tcp.SrcPort)
		features.DestinationPort = uint16(tcp.DstPort)

		// Extract TCP flags
		features.HasSYN = tcp.SYN
		features.HasACK = tcp.ACK
		features.HasFIN = tcp.FIN
		features.HasRST = tcp.RST

		// Build flag string
		features.TCPFlags = fe.buildTCPFlagString(tcp)

		// Calculate payload length
		if app := packet.ApplicationLayer(); app != nil {
			features.PayloadLength = len(app.Payload())
		}
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		features.IsUDP = true
		features.SourcePort = uint16(udp.SrcPort)
		features.DestinationPort = uint16(udp.DstPort)

		// Calculate payload length
		if app := packet.ApplicationLayer(); app != nil {
			features.PayloadLength = len(app.Payload())
		}
	}

	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		features.IsICMP = true
	}

	return features
}

// buildTCPFlagString creates a string representation of TCP flags
func (fe *FeatureExtractor) buildTCPFlagString(tcp *layers.TCP) string {
	flags := ""
	if tcp.SYN {
		flags += "SYN "
	}
	if tcp.ACK {
		flags += "ACK "
	}
	if tcp.FIN {
		flags += "FIN "
	}
	if tcp.RST {
		flags += "RST "
	}
	if tcp.PSH {
		flags += "PSH "
	}
	if tcp.URG {
		flags += "URG "
	}
	return flags
}

// ExtractBatch processes multiple packets and returns aggregated features
func (fe *FeatureExtractor) ExtractBatch(packets []gopacket.Packet) []*FlowFeatures {
	features := make([]*FlowFeatures, 0, len(packets))

	for _, packet := range packets {
		if feature := fe.Extract(packet); feature != nil {
			features = append(features, feature)
		}
	}

	return features
}
