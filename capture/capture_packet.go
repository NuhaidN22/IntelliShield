package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// PacketCapture handles the network packet capturing
type PacketCapture struct {
	handle       *pcap.Handle // Connection to network interface
	packetSource *gopacket.PacketSource
	deviceName   string // Network interface name (e.g., "eth0", "wlan0")
}

// NewPacketCapture creates a new packet capture instance
func NewPacketCapture(deviceName string) (*PacketCapture, error) {
	// Open the network device for packet capture
	// Parameters:
	// - deviceName: network interface to listen on
	// - 1600: snapshot length (max bytes to capture per packet)
	// - true: promiscuous mode (capture all packets, not just ones sent to us)
	// - 30 * time.Second: read timeout
	handle, err := pcap.OpenLive(deviceName, 1600, true, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("error opening device %s: %v", deviceName, err)
	}

	// Create a packet source to read packets from the handle
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	return &PacketCapture{
		handle:       handle,
		packetSource: packetSource,
		deviceName:   deviceName,
	}, nil
}

// Start begins capturing packets and sends them to a channel
func (pc *PacketCapture) Start(packetChan chan<- gopacket.Packet, stopChan <-chan bool) {
	log.Printf("Starting packet capture on device: %s", pc.deviceName)

	// Read packets in a loop
	for {
		select {
		case <-stopChan:
			// Stop signal received
			log.Println("Stopping packet capture...")
			return
		case packet := <-pc.packetSource.Packets():
			// New packet captured
			if packet != nil {
				// Send packet to processing channel
				packetChan <- packet
			}
		}
	}
}

// Close shuts down the packet capture
func (pc *PacketCapture) Close() {
	if pc.handle != nil {
		pc.handle.Close()
		log.Println("Packet capture closed")
	}
}

// ListDevices returns all available network interfaces
func ListDevices() ([]pcap.Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("error finding devices: %v", err)
	}
	return devices, nil
}

// PrintDevices prints all available network interfaces
func PrintDevices() error {
	devices, err := ListDevices()
	if err != nil {
		return err
	}

	fmt.Println("\n=== Available Network Interfaces ===")
	for i, device := range devices {
		fmt.Printf("\n[%d] %s\n", i+1, device.Name)
		if device.Description != "" {
			fmt.Printf("    Description: %s\n", device.Description)
		}

		// Print IP addresses
		for _, address := range device.Addresses {
			fmt.Printf("    IP: %s\n", address.IP)
		}
	}
	fmt.Println("====================================\n")
	return nil
}
