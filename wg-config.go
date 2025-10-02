package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// WireGuard command path
const WG_CMD = "/usr/bin/wg"

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
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: \n")
		fmt.Fprintf(os.Stderr, "  %s export <yaml-file> <peer-name> [output-file]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s create <peer-name> [output-file]\n", os.Args[0])
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "export":
		if len(os.Args) < 4 || len(os.Args) > 5 {
			fmt.Fprintf(os.Stderr, "Usage: %s export <yaml-file> <peer-name> [output-file]\n", os.Args[0])
			os.Exit(1)
		}
		yamlFile := os.Args[2]
		peerName := os.Args[3]
		var outputFile string
		if len(os.Args) == 5 {
			outputFile = os.Args[4]
		}
		handleExport(yamlFile, peerName, outputFile)

	case "create":
		if len(os.Args) < 3 || len(os.Args) > 4 {
			fmt.Fprintf(os.Stderr, "Usage: %s create <peer-name> [output-file]\n", os.Args[0])
			os.Exit(1)
		}
		peerName := os.Args[2]
		var outputFile string
		if len(os.Args) == 4 {
			outputFile = os.Args[3]
		}
		handleCreate(peerName, outputFile)

	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown command '%s'. Use 'export' or 'create'\n", command)
		fmt.Fprintf(os.Stderr, "Usage: \n")
		fmt.Fprintf(os.Stderr, "  %s export <yaml-file> <peer-name> [output-file]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s create <peer-name> [output-file]\n", os.Args[0])
		os.Exit(1)
	}
}

func handleExport(yamlFile, peerName, outputFile string) {

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
	generateWireGuardConfig(targetPeer, serverPeer, &config, outputFile)
}

func handleCreate(peerName, outputFile string) {
	// Set up output writer
	var writer io.Writer
	var file *os.File
	var err error

	if outputFile != "" {
		// Open file in append mode
		file, err = os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Error opening output file: %v", err)
		}
		defer file.Close()
		writer = file
	} else {
		writer = os.Stdout
	}

	// Generate WireGuard key pair
	privateKey, publicKey, err := generateKeyPair()
	if err != nil {
		log.Fatalf("Error generating key pair: %v", err)
	}

	// Generate peer configuration template
	fmt.Fprintf(writer, "# %s\n", peerName)
	fmt.Fprintln(writer, "[Peer]")
	fmt.Fprintf(writer, "PublicKey = %s\n", publicKey)
	fmt.Fprintf(writer, "PrivateKey = %s\n", privateKey)
	fmt.Fprintln(writer, "AllowedIPs = ")
	fmt.Fprintln(writer)
}

func generateKeyPair() (privateKey, publicKey string, err error) {
	// Generate private key using wg genkey
	cmd := exec.Command(WG_CMD, "genkey")
	privateKeyBytes, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %v", err)
	}
	privateKey = strings.TrimSpace(string(privateKeyBytes))

	// Generate public key by piping private key to wg pubkey
	cmd = exec.Command(WG_CMD, "pubkey")
	cmd.Stdin = strings.NewReader(privateKey)
	publicKeyBytes, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate public key: %v", err)
	}
	publicKey = strings.TrimSpace(string(publicKeyBytes))

	return privateKey, publicKey, nil
}

func generateWireGuardConfig(peer *Peer, serverPeer *Peer, config *Config, outputFile string) {
	// Set up output writer
	var writer io.Writer
	var file *os.File
	var err error

	if outputFile != "" {
		file, err = os.Create(outputFile)
		if err != nil {
			log.Fatalf("Error creating output file: %v", err)
		}
		defer file.Close()
		writer = file
	} else {
		writer = os.Stdout
	}

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
	fmt.Fprintln(writer, "[Interface]")

	// Address from WireGuard Interface IP
	if peer.WireGuardInterfaceIP != "" {
		fmt.Fprintf(writer, "Address = %s\n", peer.WireGuardInterfaceIP)
	}

	// Private key
	if peer.PrivateKey != "" {
		fmt.Fprintf(writer, "PrivateKey = %s\n", peer.PrivateKey)
	}

	// Listen port from global settings or peer-specific
	hasListenPort := false
	for _, flag := range peer.OtherFlags {
		if strings.Contains(flag, "ListenPort") {
			parts := strings.Split(flag, "=")
			if len(parts) == 2 {
				fmt.Fprintf(writer, "ListenPort = %s\n", strings.TrimSpace(parts[1]))
				hasListenPort = true
			}
		}
	}
	if !hasListenPort && listenPort != "" {
		fmt.Fprintf(writer, "ListenPort = %s\n", listenPort)
	}

	// SaveConfig from peer flags
	for _, flag := range peer.OtherFlags {
		if strings.Contains(flag, "SaveConfig") {
			fmt.Fprintf(writer, "SaveConfig = true\n")
			break
		}
	}

	fmt.Fprintln(writer)

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
		fmt.Fprintf(writer, "# %s\n", peerToConnect.NodeName)
		fmt.Fprintln(writer, "[Peer]")
		fmt.Fprintf(writer, "PublicKey = %s\n", peerToConnect.PublicKey)

		// AllowedIPs
		if peerToConnect.AllowedIPs != "" {
			fmt.Fprintf(writer, "AllowedIPs = %s\n", peerToConnect.AllowedIPs)
		} else if peerToConnect.WireGuardInterfaceIP != "" {
			fmt.Fprintf(writer, "AllowedIPs = %s\n", peerToConnect.WireGuardInterfaceIP)
		}

		// Endpoint (Public IP + Port)
		if peerToConnect.PublicIP != "" {
			fmt.Fprintf(writer, "Endpoint = %s:%s\n", peerToConnect.PublicIP, listenPort)
		}

		// PersistentKeepalive
		if persistentKeepalive != "" {
			keepalive, err := strconv.Atoi(persistentKeepalive)
			if err == nil && keepalive > 0 {
				fmt.Fprintf(writer, "PersistentKeepalive = %s\n", persistentKeepalive)
			}
		}
	}
}