package xray

import "testing"

func TestParseX25519KeyPair(t *testing.T) {
	pair, err := parseX25519KeyPair("PrivateKey: private\nPassword (PublicKey): public\nHash32: hash\n")
	if err != nil {
		t.Fatal(err)
	}
	if pair.PrivateKey != "private" || pair.PublicKey != "public" {
		t.Fatalf("unexpected pair: %#v", pair)
	}
}

func TestParseVlessEncryptionPairs(t *testing.T) {
	output := `Authentication: X25519, not Post-Quantum
"decryption": "server-x25519",
"encryption": "client-x25519"

Authentication: ML-KEM-768, Post-Quantum
"decryption": "server-mlkem",
"encryption": "client-mlkem"`
	pairs, err := parseVlessEncryptionPairs(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 2 {
		t.Fatalf("got %d pairs", len(pairs))
	}
	if pairs[0].ID != "x25519" || pairs[0].Decryption != "server-x25519" || pairs[0].Encryption != "client-x25519" {
		t.Fatalf("unexpected X25519 pair: %#v", pairs[0])
	}
	if pairs[1].ID != "mlkem768" || pairs[1].Decryption != "server-mlkem" || pairs[1].Encryption != "client-mlkem" {
		t.Fatalf("unexpected ML-KEM pair: %#v", pairs[1])
	}
}

func TestParseVlessEncryptionPairsRejectsIncompleteOutput(t *testing.T) {
	if _, err := parseVlessEncryptionPairs("Authentication: X25519\n\"decryption\": \"server\""); err == nil {
		t.Fatal("expected an error")
	}
}

func TestDeriveVlessEncryptionModes(t *testing.T) {
	pairs := []VlessEncryptionPair{{
		ID:         "x25519",
		Label:      "X25519",
		Decryption: "mlkem768x25519plus.native.600s.server",
		Encryption: "mlkem768x25519plus.native.0rtt.client",
	}}
	derived := deriveVlessEncryptionModes(pairs)
	if len(derived) != 2 {
		t.Fatalf("got %d derived pairs", len(derived))
	}
	if derived[0].ID != "x25519_xorpub" || derived[0].Decryption != "mlkem768x25519plus.xorpub.600s.server" {
		t.Fatalf("unexpected xorpub pair: %#v", derived[0])
	}
	if derived[1].ID != "x25519_random" || derived[1].Encryption != "mlkem768x25519plus.random.0rtt.client" {
		t.Fatalf("unexpected random pair: %#v", derived[1])
	}
}
