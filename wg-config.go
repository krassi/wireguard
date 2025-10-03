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
		fmt.Fprintf(os.Stderr, "  %s export <yaml-file> <peer-name> [output-file] [specific-peer-names...]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s create <peer-name> [output-file]\n", os.Args[0])
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "export":
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "Usage: %s export <yaml-file> <peer-name> [-o output-file] [specific-peer-names...]\n", os.Args[0])
			os.Exit(1)
		}
		yamlFile := os.Args[2]
		peerName := os.Args[3]
		var outputFile string
		var specificPeers []string

		// Parse arguments starting from index 4
		i := 4
		for i < len(os.Args) {
			if os.Args[i] == "-o" && i+1 < len(os.Args) {
				outputFile = os.Args[i+1]
				i += 2 // Skip both -o and the filename
			} else {
				// This is a specific peer name
				specificPeers = append(specificPeers, os.Args[i])
				i++
			}
		}
		handleExport(yamlFile, peerName, outputFile, specificPeers)

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
		fmt.Fprintf(os.Stderr, "  %s export <yaml-file> <peer-name> [output-file] [specific-peer-names...]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s create <peer-name> [output-file]\n", os.Args[0])
		os.Exit(1)
	}
}

func handleExport(yamlFile, peerName, outputFile string, specificPeers []string) {

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
	generateWireGuardConfig(targetPeer, serverPeer, &config, outputFile, specificPeers)
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

func generateWireGuardConfig(peer *Peer, serverPeer *Peer, config *Config, outputFile string, specificPeers []string) {
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

	// Generate [Peer] sections for selected peers
	for i := range config.Peers {
		p := &config.Peers[i]
		// Skip the current peer (don't include itself)
		if p.NodeName == peer.NodeName {
			continue
		}
		// Only include peers with public keys
		if p.PublicKey == "" {
			continue
		}

		// If specific peers are requested, only include those (loose match)
		if len(specificPeers) > 0 {
			found := false
			for _, specificPeer := range specificPeers {
				if strings.Contains(strings.ToLower(p.NodeName), strings.ToLower(specificPeer)) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		fmt.Fprintf(writer, "# %s\n", p.NodeName)
		fmt.Fprintln(writer, "[Peer]")
		fmt.Fprintf(writer, "PublicKey = %s\n", p.PublicKey)

		// AllowedIPs
		if p.AllowedIPs != "" {
			fmt.Fprintf(writer, "AllowedIPs = %s\n", p.AllowedIPs)
		} else if p.WireGuardInterfaceIP != "" {
			fmt.Fprintf(writer, "AllowedIPs = %s\n", p.WireGuardInterfaceIP)
		}

		// Endpoint (Public IP + Port) - only for peers with public IPs
		if p.PublicIP != "" {
			fmt.Fprintf(writer, "Endpoint = %s:%s\n", p.PublicIP, listenPort)
		}

		// PersistentKeepalive - apply to all peers from global settings
		if persistentKeepalive != "" {
			keepalive, err := strconv.Atoi(persistentKeepalive)
			if err == nil && keepalive > 0 {
				fmt.Fprintf(writer, "PersistentKeepalive = %s\n", persistentKeepalive)
			}
		}

		fmt.Fprintln(writer)
	}
}