package xray

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

type X25519KeyPair struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
}

type VlessEncryptionPair struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Decryption string `json:"decryption"`
	Encryption string `json:"encryption"`
}

func runKeyCommand(command string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// #nosec G204 -- command is selected only from fixed constants below.
	output, err := exec.CommandContext(ctx, GetBinaryPath(), command).CombinedOutput()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", fmt.Errorf("xray %s timed out", command)
		}
		return "", fmt.Errorf("xray %s failed: %w", command, err)
	}
	return string(output), nil
}

func parseX25519KeyPair(output string) (X25519KeyPair, error) {
	pair := X25519KeyPair{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "PrivateKey:"):
			pair.PrivateKey = strings.TrimSpace(strings.TrimPrefix(line, "PrivateKey:"))
		case strings.HasPrefix(line, "Password (PublicKey):"):
			pair.PublicKey = strings.TrimSpace(strings.TrimPrefix(line, "Password (PublicKey):"))
		case strings.HasPrefix(line, "PublicKey:"):
			pair.PublicKey = strings.TrimSpace(strings.TrimPrefix(line, "PublicKey:"))
		}
	}
	if pair.PrivateKey == "" || pair.PublicKey == "" {
		return X25519KeyPair{}, errors.New("unexpected xray x25519 output")
	}
	return pair, nil
}

var vlessEncryptionLine = regexp.MustCompile(`^\s*"(decryption|encryption)"\s*:\s*"([^"]+)"`)

func parseVlessEncryptionPairs(output string) ([]VlessEncryptionPair, error) {
	pairs := make([]VlessEncryptionPair, 0, 2)
	current := VlessEncryptionPair{}
	flush := func() {
		if current.Decryption != "" && current.Encryption != "" {
			if current.ID == "" {
				current.ID = fmt.Sprintf("auth-%d", len(pairs)+1)
			}
			pairs = append(pairs, current)
		}
		current = VlessEncryptionPair{}
	}

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Authentication:") {
			flush()
			current.Label = strings.TrimSpace(strings.TrimPrefix(line, "Authentication:"))
			if strings.Contains(strings.ToLower(current.Label), "ml-kem") {
				current.ID = "mlkem768"
			} else if strings.Contains(strings.ToLower(current.Label), "x25519") {
				current.ID = "x25519"
			}
			continue
		}
		match := vlessEncryptionLine.FindStringSubmatch(line)
		if len(match) != 3 {
			continue
		}
		if match[1] == "decryption" {
			current.Decryption = match[2]
		} else {
			current.Encryption = match[2]
		}
	}
	flush()
	if len(pairs) == 0 {
		return nil, errors.New("unexpected xray vlessenc output")
	}
	return pairs, nil
}

func GenerateX25519KeyPair() (X25519KeyPair, error) {
	output, err := runKeyCommand("x25519")
	if err != nil {
		return X25519KeyPair{}, err
	}
	return parseX25519KeyPair(output)
}

func GenerateVlessEncryptionPairs() ([]VlessEncryptionPair, error) {
	output, err := runKeyCommand("vlessenc")
	if err != nil {
		return nil, err
	}
	pairs, err := parseVlessEncryptionPairs(output)
	if err != nil {
		return nil, err
	}
	return append(pairs, deriveVlessEncryptionModes(pairs)...), nil
}

func deriveVlessEncryptionModes(pairs []VlessEncryptionPair) []VlessEncryptionPair {
	derived := make([]VlessEncryptionPair, 0, len(pairs)*2)
	for _, pair := range pairs {
		for _, mode := range []string{"xorpub", "random"} {
			decryption := strings.Replace(pair.Decryption, ".native.", "."+mode+".", 1)
			encryption := strings.Replace(pair.Encryption, ".native.", "."+mode+".", 1)
			if decryption == pair.Decryption && encryption == pair.Encryption {
				continue
			}
			derived = append(derived, VlessEncryptionPair{
				ID:         pair.ID + "_" + mode,
				Label:      pair.Label + " (" + mode + ")",
				Decryption: decryption,
				Encryption: encryption,
			})
		}
	}
	return derived
}
