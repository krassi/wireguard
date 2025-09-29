package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the structure of result.yaml
type Config struct {
	GlobalSettings struct {
		DefaultFlags []string `yaml:"Default Flags"`
	} `yaml:"Global Settings"`
	Peers []Peer `yaml:"Peers"`
}

// Peer represents a WireGuard peer configuration
type Peer struct {
	NodeName             string   `yaml:"Node name"`
	PublicIP             string   `yaml:"Public IP"`
	PublicKey            string   `yaml:"Public key"`
	WireGuardInterfaceIP string   `yaml:"WireGuard Interface IP"`
	PrivateKey           string   `yaml:"Private key"`
	AllowedIPs           string   `yaml:"Allowed IPs"`
	OtherFlags           []string `yaml:"Other flags"`
	ClientConfig         *struct {
		PrimaryEndpoint     string `yaml:"Primary Endpoint"`
		AllowedNetworks     string `yaml:"Allowed Networks"`
		AlternateEndpoints  string `yaml:"Alternate Endpoints"`
	} `yaml:"Client Config,omitempty"`
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <yaml-file> <peer-name>\n", os.Args[0])
		os.Exit(1)
	}

	yamlFile := os.Args[1]
	peerName := os.Args[2]

	// Read and parse YAML file
	data, err := os.ReadFile(yamlFile)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		log.Fatalf("Error parsing YAML: %v", err)
	}

	// Find the requested peer
	var targetPeer *Peer
	var serverPeer *Peer // Server peer with private key for client configs

	for i := range config.Peers {
		peer := &config.Peers[i]
		if peer.NodeName == peerName {
			targetPeer = peer
		}
		// Find server peer (peer with both private key and public IP)
		if peer.PrivateKey != "" && peer.PublicIP != "" {
			serverPeer = peer
		}
	}

	if targetPeer == nil {
		log.Fatalf("Peer '%s' not found in configuration", peerName)
	}

	// Generate WireGuard configuration
	generateWireGuardConfig(targetPeer, serverPeer, &config)
}

func generateWireGuardConfig(peer *Peer, serverPeer *Peer, config *Config) {
	// Extract default values from global settings
	var listenPort string
	var persistentKeepalive string

	for _, flag := range config.GlobalSettings.DefaultFlags {
		if strings.HasPrefix(flag, "Listen Port:") {
			listenPort = strings.TrimSpace(strings.TrimPrefix(flag, "Listen Port:"))
		}
		if strings.HasPrefix(flag, "PersistentKeepalive") {
			parts := strings.Split(flag, "=")
			if len(parts) == 2 {
				persistentKeepalive = strings.TrimSpace(parts[1])
			}
		}
	}

	// Generate [Interface] section
	fmt.Println("[Interface]")

	// Address from WireGuard Interface IP
	if peer.WireGuardInterfaceIP != "" {
		fmt.Printf("Address = %s\n", peer.WireGuardInterfaceIP)
	}

	// Private key
	if peer.PrivateKey != "" {
		fmt.Printf("PrivateKey = %s\n", peer.PrivateKey)
	}

	// Listen port from global settings or peer-specific
	hasListenPort := false
	for _, flag := range peer.OtherFlags {
		if strings.Contains(flag, "ListenPort") {
			parts := strings.Split(flag, "=")
			if len(parts) == 2 {
				fmt.Printf("ListenPort = %s\n", strings.TrimSpace(parts[1]))
				hasListenPort = true
			}
		}
	}
	if !hasListenPort && listenPort != "" {
		fmt.Printf("ListenPort = %s\n", listenPort)
	}

	// SaveConfig from peer flags
	for _, flag := range peer.OtherFlags {
		if strings.Contains(flag, "SaveConfig") {
			fmt.Printf("SaveConfig = true\n")
			break
		}
	}

	fmt.Println()

	// Generate [Peer] section
	// If this is a client peer, connect to server
	// If this is the server, show first available peer as example

	var peerToConnect *Peer

	if peer.PrivateKey != "" && peer.PublicIP != "" {
		// This is a server, find first client peer to show as example
		for i := range config.Peers {
			p := &config.Peers[i]
			if p.NodeName != peer.NodeName && p.PublicKey != "" {
				peerToConnect = p
				break
			}
		}
	} else {
		// This is a client, connect to server
		peerToConnect = serverPeer
	}

	if peerToConnect != nil {
		fmt.Printf("# %s\n", peerToConnect.NodeName)
		fmt.Println("[Peer]")
		fmt.Printf("PublicKey = %s\n", peerToConnect.PublicKey)

		// AllowedIPs
		if peerToConnect.AllowedIPs != "" {
			fmt.Printf("AllowedIPs = %s\n", peerToConnect.AllowedIPs)
		} else if peerToConnect.WireGuardInterfaceIP != "" {
			fmt.Printf("AllowedIPs = %s\n", peerToConnect.WireGuardInterfaceIP)
		}

		// Endpoint (Public IP + Port)
		if peerToConnect.PublicIP != "" {
			fmt.Printf("Endpoint = %s:%s\n", peerToConnect.PublicIP, listenPort)
		}

		// PersistentKeepalive
		if persistentKeepalive != "" {
			keepalive, err := strconv.Atoi(persistentKeepalive)
			if err == nil && keepalive > 0 {
				fmt.Printf("PersistentKeepalive = %s\n", persistentKeepalive)
			}
		}
	}
}