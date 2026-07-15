package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"intellishield/api"
	"intellishield/response"

	"github.com/google/gopacket"
)

// Global variables
var (
	esLogger        *response.ElasticsearchLogger
	mlClient        *api.MLAPIClient
	blockedIPs      = make(map[string]time.Time)
	blockedIPsMutex sync.RWMutex
	autoBlock       = true // Set to true to enable auto-blocking

)

// Whitelist of known safe IPs (Google, CDNs, etc.)
var ipWhitelist = map[string]bool{
	"142.250.182.72": true, // Google
	"192.178.134.94": true, // Cloudflare CDN
	"8.8.8.8":        true, // Google DNS
	"1.1.1.1":        true, // Cloudflare DNS
	// Add more safe IPs as needed
}

func main() {
	log.Println("🛡️  IntelliShield Packet Capture System Starting...")

	// Step 1: Initialize ML API Client
	mlClient = api.NewMLAPIClient("http://ml-server:8000")
	// Check if ML API is running with retry logic
	log.Println("🔗 Checking ML API connection...")
	for i := 0; i < 10; i++ {
		if err := mlClient.HealthCheck(); err == nil {
			log.Println("✅ Connected to ML API successfully!")
			break
		}
		log.Printf("⏳ ML API not ready yet (attempt %d/10), waiting...", i+1)
		time.Sleep(5 * time.Second)
	}

	// Step 1.5: Initialize Elasticsearch logger
	log.Println("📊 Initializing Elasticsearch logger...")
	var err error
	for i := 0; i < 10; i++ {
		esLogger, err = response.NewElasticsearchLogger([]string{"http://elasticsearch:9200"}, "intellishield")
		if err == nil {
			esLogger.CreateIndexMapping()
			break
		}
		log.Printf("⏳ Elasticsearch not ready yet (attempt %d/10), waiting...", i+1)
		time.Sleep(5 * time.Second)
	}

	// Step 2: Check if running as Administrator
	checkAdminPrivileges()

	// Step 3: List available network devices
	fmt.Println("\n📡 Detecting network interfaces...")
	if err := PrintDevices(); err != nil {
		log.Fatalf("Error listing devices: %v", err)
	}

	// Step 4: Choose network interface
	deviceName := selectDevice()

	// Step 5: Create packet capture instance
	capture, err := NewPacketCapture(deviceName)
	if err != nil {
		log.Fatalf("Error creating packet capture: %v", err)
	}
	defer capture.Close()

	// Step 6: Create packet buffer
	buffer := NewPacketBuffer(100, 5*time.Second)

	// Step 7: Create channels
	packetChan := make(chan gopacket.Packet, 1000)
	stopChan := make(chan bool)

	// Step 8: Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Step 9: Start packet capture
	go capture.Start(packetChan, stopChan)

	// Step 10: Start auto-flush
	go buffer.StartAutoFlush(processFeatures, stopChan)

	// Start a simple HTTP health endpoint for container healthchecks
	go func() {
		http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"healthy","service":"intellishield-capture"}`))
		})
		log.Println("HTTP health endpoint listening on :8080")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// Step 11: Process packets
	log.Println("✅ Capture started! Press Ctrl+C to stop.")
	log.Printf("🔒 Auto-blocking: %v (change autoBlock variable to enable/disable)\n", autoBlock)
	packetCount := 0
	attackCount := 0

	go func() {
		for packet := range packetChan {
			packetCount++

			buffer.Add(packet)

			if packetCount%100 == 0 {
				stats := buffer.GetStats()
				log.Printf("📊 Captured: %d packets | Attacks detected: %d | Buffer: %d/%d (%.1f%%)",
					packetCount, attackCount, stats.CurrentSize, stats.MaxSize, stats.Utilization)
			}

			if buffer.IsFull() {
				features := buffer.Flush()
				log.Printf("🔄 Buffer full! Processing %d packets...", len(features))
				attackDetected := processFeatures(features)
				if attackDetected {
					attackCount++
				}
			}
		}
	}()

	// Step 12: Wait for shutdown
	<-sigChan
	log.Println("\n🛑 Shutdown signal received...")

	close(stopChan)
	time.Sleep(1 * time.Second)
	close(packetChan)

	log.Printf("✅ Capture stopped. Total packets: %d | Attacks detected: %d", packetCount, attackCount)

	// Show blocked IPs summary
	showBlockedIPsSummary()
}

func selectDevice() string {
	devices, err := ListDevices()
	if err != nil {
		log.Fatalf("Error getting devices: %v", err)
	}

	if len(devices) == 0 {
		log.Fatal("No network devices found!")
	}

	// Prefer WiFi/Ethernet over Bluetooth - use safe prefix checks
	for _, device := range devices {
		for _, addr := range device.Addresses {
			ip := addr.IP.String()
			if ip == "" {
				continue
			}
			if strings.HasPrefix(ip, "192.168") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.16") {
				log.Printf("✅ Auto-selected device: %s (%s)", device.Name, device.Description)
				log.Printf("   IP Address: %s", ip)
				return device.Name
			}
		}
	}

	log.Printf("⚠️  Using first available device: %s", devices[0].Name)
	return devices[0].Name
}

// processFeatures sends features to ML API and handles attack detection + blocking
func processFeatures(features []*FlowFeatures) bool {
	// 1. Convert FlowFeatures to API format
	apiFeatures := make([]api.PacketFeature, len(features))
	for i, f := range features {
		apiFeatures[i] = api.PacketFeature{
			SourceIP:         f.SourceIP,
			DestIP:           f.DestinationIP,
			SourcePort:       f.SourcePort,
			DestPort:         f.DestinationPort,
			Protocol:         f.Protocol,
			PacketLength:     f.PacketLength,
			PayloadLength:    f.PayloadLength,
			InterArrivalTime: f.InterArrivalTime,
			TCPFlags:         f.TCPFlags,
		}
	}

	// 2. Send to ML API FIRST
	prediction, err := mlClient.Predict(apiFeatures)
	if err != nil {
		log.Printf("⚠️  ML prediction failed: %v", err)
		printBasicStats(features)
		return false
	}

	// 3. NOW check the results and log to Elasticsearch
	if prediction.IsAttack {
		handleAttackDetection(prediction, features) // This function calls esLogger.LogAttack
	} else {
		log.Printf("✅ Traffic appears normal")
		if len(features) > 0 && esLogger != nil {
			esLogger.LogNormalTraffic(
				features[0].SourceIP,
				len(features),
				0,
				prediction.Confidence,
			)
		}
	}

	return prediction.IsAttack
}

// handleAttackDetection processes detected attacks with 3-tier response system
func handleAttackDetection(prediction *api.PredictionResponse, features []*FlowFeatures) {
	log.Printf("\n🚨 ATTACK DETECTED! 🚨")
	log.Printf("  Confidence: %.2f%%", prediction.Confidence*100)

	// Add this inside handleAttackDetection
	if len(features) > 0 && esLogger != nil {
		esLogger.LogAttack(
			features[0].SourceIP,
			features[0].DestinationIP,
			int(features[0].SourcePort),
			int(features[0].DestinationPort),
			features[0].Protocol,
			len(features),
			0, // Total bytes
			prediction.Confidence,
			prediction.Predictions,
			"block",
		)
	}

	// 1. Identify attacker IPs
	attackerIPs := make(map[string]int)
	for _, f := range features {
		attackerIPs[f.SourceIP]++
	}

	log.Printf("\n📍 Attacker IP Addresses:")
	for ip, packetCount := range attackerIPs {
		log.Printf("  • %s (%d packets)", ip, packetCount)
	}

	// 2. Three-Tier Response System
	if prediction.Confidence >= 0.85 {
		// CRITICAL - Auto-block immediately
		log.Printf("\n🔴 THREAT LEVEL: CRITICAL (%.2f%%)", prediction.Confidence*100)
		for ip := range attackerIPs {
			blockIPWithCheck(ip, fmt.Sprintf("Critical threat - %.2f%% confidence", prediction.Confidence*100))
		}

	} else if prediction.Confidence >= 0.60 {
		// HIGH - Block with notification
		log.Printf("\n🟠 THREAT LEVEL: HIGH (%.2f%%)", prediction.Confidence*100)
		for ip := range attackerIPs {
			blockIPWithCheck(ip, fmt.Sprintf("High threat - %.2f%% confidence", prediction.Confidence*100))
		}

	} else if prediction.Confidence >= 0.50 {
		// MEDIUM - Monitor & log only (current case)
		log.Printf("\n🟡 THREAT LEVEL: MEDIUM (%.2f%%)", prediction.Confidence*100)
		log.Printf("  Action: MONITORING ONLY - No blocking")
		log.Printf("  Reason: Confidence below blocking threshold (70%%)")
		if autoBlock {
			log.Printf("  💡 Tip: This might be legitimate traffic (e.g., downloads, streaming)")
		}
		saveAttackLog(attackerIPs, prediction, features, "monitored")

	} else {
		// LOW - Just log
		log.Printf("\n🟢 THREAT LEVEL: LOW (%.2f%%)", prediction.Confidence*100)
		log.Printf("  Action: LOGGED ONLY")
	}

	// 3. Log attack details
	log.Printf("\n📊 Attack Details:")
	if len(features) > 0 {
		log.Printf("  Protocol: %s", features[0].Protocol)
		log.Printf("  Total packets: %d", len(features))
		if len(features) > 1 {
			duration := features[len(features)-1].Timestamp.Sub(features[0].Timestamp).Seconds()
			log.Printf("  Time window: %.2f seconds", duration)
		}
	}

}

// blockIPWithCheck checks whitelist and admin status before blocking
func blockIPWithCheck(ip string, reason string) {
	// Skip localhost
	if ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
		log.Printf("  ⚠️  Skipping localhost (cannot block)")
		return
	}

	// Check whitelist
	if ipWhitelist[ip] {
		log.Printf("  ⚠️  IP %s is WHITELISTED - not blocking", ip)
		log.Printf("     Reason: Known safe IP (Google, CDN, etc.)")
		return
	}

	// Check if already blocked
	blockedIPsMutex.RLock()
	if blockedTime, exists := blockedIPs[ip]; exists {
		blockedIPsMutex.RUnlock()
		log.Printf("  ⚠️  IP %s already blocked (since %s)", ip, blockedTime.Format("15:04:05"))
		return
	}
	blockedIPsMutex.RUnlock()

	// Check auto-block setting
	if !autoBlock {
		log.Printf("  ⚠️  Auto-blocking DISABLED - would block %s", ip)
		log.Printf("     Set autoBlock = true to enable automatic blocking")
		return
	}

	// Perform the block
	if err := blockIP(ip, reason); err != nil {
		log.Printf("  ❌ Failed to block IP %s: %v", ip, err)
	}
}

// blockIP blocks an IP address using Windows Firewall
func blockIP(ip string, reason string) error {
	log.Printf("\n🚫 BLOCKING IP ADDRESS: %s", ip)
	log.Printf("   Reason: %s", reason)

	// Create firewall rule name
	ruleName := fmt.Sprintf("IntelliShield_Block_%s", strings.Replace(ip, ".", "_", -1))

	// Windows Firewall command
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%s", ruleName),
		"dir=in",
		"action=block",
		fmt.Sprintf("remoteip=%s", ip),
	)

	// Execute command
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("   ❌ Failed to block IP: %v", err)
		log.Printf("   Output: %s", string(output))
		log.Printf("   💡 Make sure you're running as Administrator!")
		return err
	}

	log.Printf("   ✅ IP BLOCKED successfully!")
	log.Printf("   📋 Firewall rule: %s", ruleName)

	// Add to blocked IPs list
	blockedIPsMutex.Lock()
	blockedIPs[ip] = time.Now()
	blockedIPsMutex.Unlock()

	return nil
}

// saveAttackLog saves attack details to a file
func saveAttackLog(attackerIPs map[string]int, prediction *api.PredictionResponse, features []*FlowFeatures, action string) {
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("logs/attack_%s.log", timestamp)

	// Create logs directory
	os.MkdirAll("logs", 0755)

	// Create log file
	file, err := os.Create(filename)
	if err != nil {
		log.Printf("⚠️  Could not create log file: %v", err)
		return
	}
	defer file.Close()

	// Write attack details
	file.WriteString(strings.Repeat("=", 70) + "\n")
	file.WriteString("IntelliShield Attack Log\n")
	file.WriteString(strings.Repeat("=", 70) + "\n\n")
	file.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format(time.RFC3339)))
	file.WriteString(fmt.Sprintf("Confidence: %.2f%%\n", prediction.Confidence*100))
	file.WriteString(fmt.Sprintf("Ensemble Score: %.2f\n", prediction.EnsembleScore))
	file.WriteString(fmt.Sprintf("Action Taken: %s\n\n", action))

	file.WriteString("Attacker IP Addresses:\n")
	for ip, count := range attackerIPs {
		file.WriteString(fmt.Sprintf("  - %s (%d packets)\n", ip, count))
	}

	file.WriteString("\nModel Predictions:\n")
	for model, score := range prediction.Predictions {
		file.WriteString(fmt.Sprintf("  - %s: %.2f%%\n", model, score*100))
	}

	file.WriteString("\nSample Packets:\n")
	for i := 0; i < 5 && i < len(features); i++ {
		f := features[i]
		file.WriteString(fmt.Sprintf("  [%d] %s:%d -> %s:%d | %s\n",
			i+1, f.SourceIP, f.SourcePort, f.DestinationIP, f.DestinationPort, f.Protocol))
	}

	file.WriteString("\n" + strings.Repeat("=", 70) + "\n")

	log.Printf("📄 Attack logged to: %s", filename)
}

// checkAdminPrivileges warns if not running as admin
func checkAdminPrivileges() {
	// Try to execute a harmless netsh command to check admin status
	cmd := exec.Command("netsh", "advfirewall", "show", "allprofiles")
	err := cmd.Run()

	if err != nil {
		log.Println("\n⚠️  WARNING: Not running as Administrator!")
		log.Println("   IP blocking will NOT work without admin privileges")
		log.Println("   Right-click Command Prompt → 'Run as Administrator'")
		log.Println("   Continuing with detection only...")
	}
}

// showBlockedIPsSummary shows summary of blocked IPs at shutdown
func showBlockedIPsSummary() {
	blockedIPsMutex.RLock()
	defer blockedIPsMutex.RUnlock()

	if len(blockedIPs) == 0 {
		log.Println("\n📊 No IPs were blocked during this session")
		return
	}

	log.Println("\n" + strings.Repeat("=", 60))
	log.Println("📊 Blocked IPs Summary")
	log.Println(strings.Repeat("=", 60))
	for ip, blockedTime := range blockedIPs {
		duration := time.Since(blockedTime)
		log.Printf("  🚫 %s (blocked %v ago)", ip, duration.Round(time.Second))
	}
	log.Println(strings.Repeat("=", 60))
	log.Println("\n💡 To unblock IPs, run:")
	log.Println("   netsh advfirewall firewall delete rule name=IntelliShield_Block_XXX")
}

// printBasicStats shows basic statistics when ML API is unavailable
func printBasicStats(features []*FlowFeatures) {
	log.Printf("\n=== Basic Statistics (ML unavailable) ===")

	tcpCount := 0
	udpCount := 0
	icmpCount := 0
	totalBytes := 0

	for _, f := range features {
		if f.IsTCP {
			tcpCount++
		}
		if f.IsUDP {
			udpCount++
		}
		if f.IsICMP {
			icmpCount++
		}
		totalBytes += f.PacketLength
	}

	log.Printf("  TCP packets: %d", tcpCount)
	log.Printf("  UDP packets: %d", udpCount)
	log.Printf("  ICMP packets: %d", icmpCount)
	log.Printf("  Total bytes: %d (%.2f KB)", totalBytes, float64(totalBytes)/1024.0)
	log.Printf("  Avg packet size: %.2f bytes", float64(totalBytes)/float64(len(features)))

	log.Println("\n  Sample packets:")
	for i := 0; i < 3 && i < len(features); i++ {
		f := features[i]
		log.Printf("    [%d] %s:%d -> %s:%d | %s | %d bytes",
			i+1, f.SourceIP, f.SourcePort, f.DestinationIP, f.DestinationPort,
			f.Protocol, f.PacketLength)
	}
	log.Println("========================================")
}
