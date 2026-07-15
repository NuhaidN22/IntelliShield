package main

import (
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
)

// PacketBuffer collects packets before processing them in batches
type PacketBuffer struct {
	packets      []gopacket.Packet
	features     []*FlowFeatures
	mu           sync.Mutex
	maxSize      int           // Max number of packets to buffer
	flushTimeout time.Duration // Time before auto-flush
	extractor    *FeatureExtractor
}

// NewPacketBuffer creates a new packet buffer
func NewPacketBuffer(maxSize int, flushTimeout time.Duration) *PacketBuffer {
	return &PacketBuffer{
		packets:      make([]gopacket.Packet, 0, maxSize),
		features:     make([]*FlowFeatures, 0, maxSize),
		maxSize:      maxSize,
		flushTimeout: flushTimeout,
		extractor:    NewFeatureExtractor(),
	}
}

// Add adds a packet to the buffer
func (pb *PacketBuffer) Add(packet gopacket.Packet) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	// Extract features from packet
	feature := pb.extractor.Extract(packet)

	// Add to buffer
	pb.packets = append(pb.packets, packet)
	pb.features = append(pb.features, feature)
}

// IsFull checks if buffer is full
func (pb *PacketBuffer) IsFull() bool {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	return len(pb.packets) >= pb.maxSize
}

// Size returns current buffer size
func (pb *PacketBuffer) Size() int {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	return len(pb.packets)
}

// Flush returns all buffered features and clears the buffer
func (pb *PacketBuffer) Flush() []*FlowFeatures {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	// Copy features
	features := make([]*FlowFeatures, len(pb.features))
	copy(features, pb.features)

	// Clear buffers
	pb.packets = pb.packets[:0]
	pb.features = pb.features[:0]

	return features
}

// StartAutoFlush automatically flushes buffer at regular intervals
// StartAutoFlush automatically flushes buffer at regular intervals
func (pb *PacketBuffer) StartAutoFlush(processFunc func([]*FlowFeatures) bool, stopChan <-chan bool) {
	ticker := time.NewTicker(pb.flushTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-stopChan:
			// Final flush before stopping
			if pb.Size() > 0 {
				features := pb.Flush()
				processFunc(features)
			}
			log.Println("Auto-flush stopped")
			return

		case <-ticker.C:
			// Regular flush
			if pb.Size() > 0 {
				features := pb.Flush()
				log.Printf("Auto-flushing %d packets", len(features))
				processFunc(features)
			}
		}
	}
}
// GetStats returns buffer statistics
type BufferStats struct {
	CurrentSize int
	MaxSize     int
	Utilization float64 // Percentage of buffer used
}

func (pb *PacketBuffer) GetStats() BufferStats {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	size := len(pb.packets)
	utilization := float64(size) / float64(pb.maxSize) * 100.0

	return BufferStats{
		CurrentSize: size,
		MaxSize:     pb.maxSize,
		Utilization: utilization,
	}
}
