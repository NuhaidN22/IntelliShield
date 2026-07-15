package main

import (
	"testing"
	"time"

	"intellishield/api"
)

// helper to build a simple FlowFeatures struct
func makeFeature(src string) *FlowFeatures {
	return &FlowFeatures{
		Timestamp:       time.Now(),
		SourceIP:        src,
		DestinationIP:   "1.1.1.1",
		SourcePort:      1234,
		DestinationPort: 80,
		Protocol:        "TCP",
		PacketLength:    100,
	}
}

// verify handleAttackDetection runs through without panicking
func TestHandleAttackDetection(t *testing.T) {
	// disable actual blocking and ES logging
	autoBlock = false
	esLogger = nil

	cases := []struct {
		name       string
		confidence float64
		expectIPS  int
	}{
		{"critical", 0.90, 0},
		{"high", 0.65, 0},
		{"medium", 0.55, 0},
		{"low", 0.40, 0},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			blockedIPs = make(map[string]time.Time) // reset state
			feats := []*FlowFeatures{makeFeature("10.0.0.1"), makeFeature("10.0.0.2")}
			pred := &api.PredictionResponse{
				IsAttack:      true,
				Confidence:    c.confidence,
				Predictions:   map[string]float64{"dummy": c.confidence},
				EnsembleScore: c.confidence,
			}

			// call function under test
			handleAttackDetection(pred, feats)

			if len(blockedIPs) != c.expectIPS {
				t.Errorf("unexpected blocked IPs count: got %d, want %d", len(blockedIPs), c.expectIPS)
			}
		})
	}
}
