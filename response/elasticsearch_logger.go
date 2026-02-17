package response

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
)

// ElasticsearchLogger logs traffic and alerts to Elasticsearch
type ElasticsearchLogger struct {
	client *elasticsearch.Client
	index  string
}

// TrafficLog represents a logged network event
type TrafficLog struct {
	Timestamp        time.Time          `json:"@timestamp"`
	SourceIP         string             `json:"source_ip"`
	DestIP           string             `json:"dest_ip"`
	SourcePort       int                `json:"source_port"`
	DestPort         int                `json:"dest_port"`
	Protocol         string             `json:"protocol"`
	PacketCount      int                `json:"packet_count"`
	TotalBytes       int                `json:"total_bytes"`
	IsAttack         bool               `json:"is_attack"`
	AttackConfidence float64            `json:"attack_confidence"`
	ModelPredictions map[string]float64 `json:"model_predictions"`
	Action           string             `json:"action"`
	Severity         string             `json:"severity"`
}

// NewElasticsearchLogger creates a new Elasticsearch logger
func NewElasticsearchLogger(addresses []string, index string) (*ElasticsearchLogger, error) {
	cfg := elasticsearch.Config{
		Addresses: addresses,
	}

	client, err := elasticsearch.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("error creating Elasticsearch client: %v", err)
	}

	// Test connection
	res, err := client.Info()
	if err != nil {
		return nil, fmt.Errorf("error getting Elasticsearch info: %v", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("Elasticsearch returned error: %s", res.String())
	}

	log.Printf("✅ Connected to Elasticsearch")

	return &ElasticsearchLogger{
		client: client,
		index:  index,
	}, nil
}

// LogTraffic logs network traffic to Elasticsearch
func (e *ElasticsearchLogger) LogTraffic(traffic TrafficLog) error {
	// Set timestamp if not provided
	if traffic.Timestamp.IsZero() {
		traffic.Timestamp = time.Now()
	}

	// Determine severity
	if traffic.IsAttack {
		if traffic.AttackConfidence > 0.8 {
			traffic.Severity = "critical"
		} else if traffic.AttackConfidence > 0.6 {
			traffic.Severity = "high"
		} else {
			traffic.Severity = "medium"
		}
	} else {
		traffic.Severity = "info"
	}

	// Marshal to JSON
	data, err := json.Marshal(traffic)
	if err != nil {
		return fmt.Errorf("error marshaling traffic log: %v", err)
	}

	// Index document
	req := esapi.IndexRequest{
		Index:   e.index,
		Body:    bytes.NewReader(data),
		Refresh: "true",
	}

	res, err := req.Do(context.Background(), e.client)
	if err != nil {
		return fmt.Errorf("error indexing document: %v", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("error response from Elasticsearch: %s", res.String())
	}

	return nil
}

// LogAttack logs a detected attack with full details
func (e *ElasticsearchLogger) LogAttack(
	sourceIP string,
	destIP string,
	sourcePort, destPort int,
	protocol string,
	packetCount, totalBytes int,
	confidence float64,
	predictions map[string]float64,
	action string,
) error {
	log := TrafficLog{
		Timestamp:        time.Now(),
		SourceIP:         sourceIP,
		DestIP:           destIP,
		SourcePort:       sourcePort,
		DestPort:         destPort,
		Protocol:         protocol,
		PacketCount:      packetCount,
		TotalBytes:       totalBytes,
		IsAttack:         true,
		AttackConfidence: confidence,
		ModelPredictions: predictions,
		Action:           action,
	}

	return e.LogTraffic(log)
}

// LogNormalTraffic logs normal (non-attack) traffic
func (e *ElasticsearchLogger) LogNormalTraffic(
	sourceIP string,
	packetCount, totalBytes int,
	confidence float64,
) error {
	log := TrafficLog{
		Timestamp:        time.Now(),
		SourceIP:         sourceIP,
		PacketCount:      packetCount,
		TotalBytes:       totalBytes,
		IsAttack:         false,
		AttackConfidence: confidence,
		Action:           "allow",
	}

	return e.LogTraffic(log)
}

// CreateIndexMapping creates the index with proper mapping
func (e *ElasticsearchLogger) CreateIndexMapping() error {
	mapping := `{
		"mappings": {
			"properties": {
				"@timestamp": { "type": "date" },
				"source_ip": { "type": "ip" },
				"dest_ip": { "type": "ip" },
				"source_port": { "type": "integer" },
				"dest_port": { "type": "integer" },
				"protocol": { "type": "keyword" },
				"packet_count": { "type": "integer" },
				"total_bytes": { "type": "long" },
				"is_attack": { "type": "boolean" },
				"attack_confidence": { "type": "float" },
				"action": { "type": "keyword" },
				"severity": { "type": "keyword" }
			}
		}
	}`

	req := esapi.IndicesCreateRequest{
		Index: e.index,
		Body:  bytes.NewReader([]byte(mapping)),
	}

	res, err := req.Do(context.Background(), e.client)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.IsError() && res.StatusCode != 400 { // 400 means index already exists
		return fmt.Errorf("error creating index: %s", res.String())
	}

	log.Printf("✅ Elasticsearch index '%s' ready", e.index)
	return nil
}
