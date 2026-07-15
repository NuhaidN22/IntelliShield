package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// MLAPIClient handles communication with Python ML API
type MLAPIClient struct {
	baseURL    string
	httpClient *http.Client
}

// PacketFeature represents a single packet's features
type PacketFeature struct {
	SourceIP         string  `json:"source_ip"`
	DestIP           string  `json:"dest_ip"`
	SourcePort       uint16  `json:"source_port"`
	DestPort         uint16  `json:"dest_port"`
	Protocol         string  `json:"protocol"`
	PacketLength     int     `json:"packet_length"`
	PayloadLength    int     `json:"payload_length"`
	InterArrivalTime float64 `json:"inter_arrival_time"`
	TCPFlags         string  `json:"tcp_flags"`
}

// PredictionRequest sent to ML API
type PredictionRequest struct {
	Features []map[string]interface{} `json:"features"`
}

// PredictionResponse from ML API
type PredictionResponse struct {
	IsAttack      bool               `json:"is_attack"`
	Confidence    float64            `json:"confidence"`
	Predictions   map[string]float64 `json:"predictions"`
	EnsembleScore float64            `json:"ensemble_score"`
}

// NewMLAPIClient creates a new ML API client
func NewMLAPIClient(baseURL string) *MLAPIClient {
	return &MLAPIClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Predict sends features to ML API and gets prediction
func (c *MLAPIClient) Predict(features []PacketFeature) (*PredictionResponse, error) {
	// Convert features to map format
	featureMaps := make([]map[string]interface{}, len(features))
	for i, f := range features {
		featureMaps[i] = map[string]interface{}{
			"source_ip":          f.SourceIP,
			"dest_ip":            f.DestIP,
			"source_port":        f.SourcePort,
			"dest_port":          f.DestPort,
			"protocol":           f.Protocol,
			"packet_length":      f.PacketLength,
			"payload_length":     f.PayloadLength,
			"inter_arrival_time": f.InterArrivalTime,
			"tcp_flags":          f.TCPFlags,
		}
	}

	// Create request
	request := PredictionRequest{
		Features: featureMaps,
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	// Send POST request
	url := fmt.Sprintf("%s/predict", c.baseURL)
	resp, err := c.httpClient.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Unmarshal response
	var prediction PredictionResponse
	if err := json.Unmarshal(body, &prediction); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return &prediction, nil
}

// HealthCheck checks if ML API is running
func (c *MLAPIClient) HealthCheck() error {
	url := fmt.Sprintf("%s/health", c.baseURL)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("health check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API unhealthy: status %d", resp.StatusCode)
	}

	return nil
}
