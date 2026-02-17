package response

import (
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"sync"
	"time"
)

// IPBlocker manages IP blocking
type IPBlocker struct {
	blockedIPs map[string]time.Time
	mu         sync.RWMutex
	autoBlock  bool
}

// NewIPBlocker creates a new IP blocker
func NewIPBlocker(autoBlock bool) *IPBlocker {
	return &IPBlocker{
		blockedIPs: make(map[string]time.Time),
		autoBlock:  autoBlock,
	}
}

// BlockIP blocks an IP address using firewall rules
func (b *IPBlocker) BlockIP(ip string, reason string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Check if already blocked
	if _, blocked := b.blockedIPs[ip]; blocked {
		log.Printf("⚠️  IP %s already blocked", ip)
		return nil
	}

	// Add to blocked list
	b.blockedIPs[ip] = time.Now()

	// Execute firewall command
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		// Windows Firewall command
		ruleName := fmt.Sprintf("IntelliShield_Block_%s", ip)
		cmd = exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			fmt.Sprintf("name=%s", ruleName),
			"dir=in",
			"action=block",
			fmt.Sprintf("remoteip=%s", ip))

	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	// Execute command
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to block IP %s: %v, output: %s", ip, err, string(output))
	}

	log.Printf("🚫 BLOCKED IP: %s (Reason: %s)", ip, reason)
	return nil
}

// UnblockIP removes IP from blocklist
func (b *IPBlocker) UnblockIP(ip string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Check if blocked
	if _, blocked := b.blockedIPs[ip]; !blocked {
		return fmt.Errorf("IP %s is not blocked", ip)
	}

	// Remove from map
	delete(b.blockedIPs, ip)

	// Execute firewall command (Windows only for now)
	ruleName := fmt.Sprintf("IntelliShield_Block_%s", ip)
	cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
		fmt.Sprintf("name=%s", ruleName))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to unblock IP %s: %v, output: %s", ip, err, string(output))
	}

	log.Printf("✅ UNBLOCKED IP: %s", ip)
	return nil
}

// GetBlockedIPs returns list of currently blocked IPs
func (b *IPBlocker) GetBlockedIPs() map[string]time.Time {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Create copy
	blocked := make(map[string]time.Time)
	for ip, t := range b.blockedIPs {
		blocked[ip] = t
	}

	return blocked
}
