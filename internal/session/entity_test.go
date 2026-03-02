package session

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"testing"

	"github.com/ttpreport/ligolo-mp/v2/internal/protocol"
	"github.com/ttpreport/ligolo-mp/v2/pkg/memstore"
)

// mustParseMAC is a helper function to parse MAC addresses in tests
func mustParseMAC(s string) net.HardwareAddr {
	mac, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return mac
}

// TestHash_CertificateBased tests that when both CertOrganization and CertCommonName are set,
// the hash uses SHA-256 of "organization:commonName"
func TestHash_CertificateBased(t *testing.T) {
	sess := &Session{
		CertOrganization: "team01",
		CertCommonName:   "agent-alpha",
		Interfaces:       memstore.NewSyncslice[protocol.NetInterface](),
	}

	// Add a MAC address that would generate a different hash
	sess.Interfaces.Append(protocol.NetInterface{
		Name:         "eth0",
		HardwareAddr: mustParseMAC("aa:bb:cc:dd:ee:ff"),
		Addresses:    []string{"10.0.0.1"},
	})

	hash := sess.Hash()

	// Expected hash: SHA-256 of "team01:agent-alpha"
	hasher := sha256.New()
	hasher.Write([]byte("team01"))
	hasher.Write([]byte(":"))
	hasher.Write([]byte("agent-alpha"))
	expected := hex.EncodeToString(hasher.Sum(nil))

	if hash != expected {
		t.Errorf("Hash() with certificate = %v, want %v", hash, expected)
	}
}

// TestHash_MultipleCertsSameMac tests that two sessions with different certificates
// but identical MAC addresses produce different hashes
func TestHash_MultipleCertsSameMac(t *testing.T) {
	// Session 1: team01/agent-A
	sess1 := &Session{
		CertOrganization: "team01",
		CertCommonName:   "agent-A",
		Interfaces:       memstore.NewSyncslice[protocol.NetInterface](),
	}
	sess1.Interfaces.Append(protocol.NetInterface{
		Name:         "eth0",
		HardwareAddr: mustParseMAC("aa:bb:cc:dd:ee:ff"),
		Addresses:    []string{"10.0.0.1"},
	})

	// Session 2: team02/agent-B (same MAC!)
	sess2 := &Session{
		CertOrganization: "team02",
		CertCommonName:   "agent-B",
		Interfaces:       memstore.NewSyncslice[protocol.NetInterface](),
	}
	sess2.Interfaces.Append(protocol.NetInterface{
		Name:         "eth0",
		HardwareAddr: mustParseMAC("aa:bb:cc:dd:ee:ff"), // Same MAC as sess1
		Addresses:    []string{"10.0.0.2"},
	})

	hash1 := sess1.Hash()
	hash2 := sess2.Hash()

	if hash1 == hash2 {
		t.Errorf("Hash() should be different for different certificates, both got %v", hash1)
	}
}

// TestHash_SameCertDifferentMac tests that two sessions with the same certificate
// but different MAC addresses produce the SAME hash (certificate takes precedence)
func TestHash_SameCertDifferentMac(t *testing.T) {
	// Session 1: team01/agent-A on machine 1
	sess1 := &Session{
		CertOrganization: "team01",
		CertCommonName:   "agent-A",
		Interfaces:       memstore.NewSyncslice[protocol.NetInterface](),
	}
	sess1.Interfaces.Append(protocol.NetInterface{
		Name:         "eth0",
		HardwareAddr: mustParseMAC("aa:bb:cc:dd:ee:ff"),
		Addresses:    []string{"10.0.0.1"},
	})

	// Session 2: team01/agent-A on machine 2 (different MAC!)
	sess2 := &Session{
		CertOrganization: "team01",
		CertCommonName:   "agent-A",
		Interfaces:       memstore.NewSyncslice[protocol.NetInterface](),
	}
	sess2.Interfaces.Append(protocol.NetInterface{
		Name:         "eth0",
		HardwareAddr: mustParseMAC("11:22:33:44:55:66"), // Different MAC
		Addresses:    []string{"10.0.0.2"},
	})

	hash1 := sess1.Hash()
	hash2 := sess2.Hash()

	if hash1 != hash2 {
		t.Errorf("Hash() should be the same for same certificate, got %v and %v", hash1, hash2)
	}
}

// TestHash_MACFallback tests that when certificate fields are empty,
// the hash falls back to SHA-1 of sorted MAC addresses
func TestHash_MACFallback(t *testing.T) {
	sess := &Session{
		CertOrganization: "", // No certificate
		CertCommonName:   "",
		Interfaces:       memstore.NewSyncslice[protocol.NetInterface](),
	}

	sess.Interfaces.Append(protocol.NetInterface{
		Name:         "eth0",
		HardwareAddr: mustParseMAC("aa:bb:cc:dd:ee:ff"),
		Addresses:    []string{"10.0.0.1"},
	})

	hash := sess.Hash()

	// Expected hash: SHA-1 of MAC address (raw bytes, not string)
	hasher := sha1.New()
	hasher.Write(mustParseMAC("aa:bb:cc:dd:ee:ff"))
	expected := hex.EncodeToString(hasher.Sum(nil))

	if hash != expected {
		t.Errorf("Hash() with MAC fallback = %v, want %v", hash, expected)
	}
}

// TestHash_MACFallback_OnlyOrgSet tests that if only organization is set (not CN),
// it falls back to MAC-based hash
func TestHash_MACFallback_OnlyOrgSet(t *testing.T) {
	sess := &Session{
		CertOrganization: "team01", // Only org, no CN
		CertCommonName:   "",
		Interfaces:       memstore.NewSyncslice[protocol.NetInterface](),
	}

	sess.Interfaces.Append(protocol.NetInterface{
		Name:         "eth0",
		HardwareAddr: mustParseMAC("aa:bb:cc:dd:ee:ff"),
		Addresses:    []string{"10.0.0.1"},
	})

	hash := sess.Hash()

	// Expected hash: SHA-1 of MAC address (fallback, raw bytes)
	hasher := sha1.New()
	hasher.Write(mustParseMAC("aa:bb:cc:dd:ee:ff"))
	expected := hex.EncodeToString(hasher.Sum(nil))

	if hash != expected {
		t.Errorf("Hash() should fall back to MAC when CN is empty, got %v, want %v", hash, expected)
	}
}

// TestHash_MACFallback_OnlyCNSet tests that if only common name is set (not org),
// it falls back to MAC-based hash
func TestHash_MACFallback_OnlyCNSet(t *testing.T) {
	sess := &Session{
		CertOrganization: "", // No org, only CN
		CertCommonName:   "agent-A",
		Interfaces:       memstore.NewSyncslice[protocol.NetInterface](),
	}

	sess.Interfaces.Append(protocol.NetInterface{
		Name:         "eth0",
		HardwareAddr: mustParseMAC("aa:bb:cc:dd:ee:ff"),
		Addresses:    []string{"10.0.0.1"},
	})

	hash := sess.Hash()

	// Expected hash: SHA-1 of MAC address (fallback, raw bytes)
	hasher := sha1.New()
	hasher.Write(mustParseMAC("aa:bb:cc:dd:ee:ff"))
	expected := hex.EncodeToString(hasher.Sum(nil))

	if hash != expected {
		t.Errorf("Hash() should fall back to MAC when org is empty, got %v, want %v", hash, expected)
	}
}

// TestHash_MACFallback_MultipleInterfaces tests that MAC-based hash
// uses sorted MAC addresses when there are multiple interfaces
func TestHash_MACFallback_MultipleInterfaces(t *testing.T) {
	sess := &Session{
		CertOrganization: "",
		CertCommonName:   "",
		Interfaces:       memstore.NewSyncslice[protocol.NetInterface](),
	}

	// Add interfaces in unsorted order
	sess.Interfaces.Append(protocol.NetInterface{
		Name:         "eth1",
		HardwareAddr: mustParseMAC("bb:bb:bb:bb:bb:bb"),
		Addresses:    []string{"10.0.0.2"},
	})
	sess.Interfaces.Append(protocol.NetInterface{
		Name:         "eth0",
		HardwareAddr: mustParseMAC("aa:aa:aa:aa:aa:aa"),
		Addresses:    []string{"10.0.0.1"},
	})
	sess.Interfaces.Append(protocol.NetInterface{
		Name:         "eth2",
		HardwareAddr: mustParseMAC("cc:cc:cc:cc:cc:cc"),
		Addresses:    []string{"10.0.0.3"},
	})

	hash := sess.Hash()

	// Expected: SHA-1 of sorted (descending) MAC addresses (raw bytes)
	hasher := sha1.New()
	// Sorted descending: cc, bb, aa
	hasher.Write(mustParseMAC("cc:cc:cc:cc:cc:cc"))
	hasher.Write(mustParseMAC("bb:bb:bb:bb:bb:bb"))
	hasher.Write(mustParseMAC("aa:aa:aa:aa:aa:aa"))
	expected := hex.EncodeToString(hasher.Sum(nil))

	if hash != expected {
		t.Errorf("Hash() with multiple MACs = %v, want %v", hash, expected)
	}
}

// TestHash_CertificateHashLength tests that certificate-based hashes use SHA-256 (64 hex chars)
func TestHash_CertificateHashLength(t *testing.T) {
	sess := &Session{
		CertOrganization: "team01",
		CertCommonName:   "agent-A",
		Interfaces:       memstore.NewSyncslice[protocol.NetInterface](),
	}

	hash := sess.Hash()

	// SHA-256 produces 32 bytes = 64 hex characters
	if len(hash) != 64 {
		t.Errorf("Certificate-based hash length = %v, want 64 (SHA-256)", len(hash))
	}
}

// TestHash_MACHashLength tests that MAC-based hashes use SHA-1 (40 hex chars)
func TestHash_MACHashLength(t *testing.T) {
	sess := &Session{
		CertOrganization: "",
		CertCommonName:   "",
		Interfaces:       memstore.NewSyncslice[protocol.NetInterface](),
	}

	sess.Interfaces.Append(protocol.NetInterface{
		Name:         "eth0",
		HardwareAddr: mustParseMAC("aa:bb:cc:dd:ee:ff"),
		Addresses:    []string{"10.0.0.1"},
	})

	hash := sess.Hash()

	// SHA-1 produces 20 bytes = 40 hex characters
	if len(hash) != 40 {
		t.Errorf("MAC-based hash length = %v, want 40 (SHA-1)", len(hash))
	}
}

// TestHash_Stability tests that calling Hash() multiple times returns the same result
func TestHash_Stability(t *testing.T) {
	sess := &Session{
		CertOrganization: "team01",
		CertCommonName:   "agent-A",
		Interfaces:       memstore.NewSyncslice[protocol.NetInterface](),
	}

	hash1 := sess.Hash()
	hash2 := sess.Hash()
	hash3 := sess.Hash()

	if hash1 != hash2 || hash2 != hash3 {
		t.Errorf("Hash() should be stable, got %v, %v, %v", hash1, hash2, hash3)
	}
}

// TestHash_EmptyInterfaces tests that certificate-based hash works even with no interfaces
func TestHash_EmptyInterfaces(t *testing.T) {
	sess := &Session{
		CertOrganization: "team01",
		CertCommonName:   "agent-A",
		Interfaces:       memstore.NewSyncslice[protocol.NetInterface](),
	}

	hash := sess.Hash()

	// Should still produce a valid hash based on certificate
	hasher := sha256.New()
	hasher.Write([]byte("team01"))
	hasher.Write([]byte(":"))
	hasher.Write([]byte("agent-A"))
	expected := hex.EncodeToString(hasher.Sum(nil))

	if hash != expected {
		t.Errorf("Hash() with no interfaces = %v, want %v", hash, expected)
	}
}

// BenchmarkHash_MAC benchmarks the MAC-based hash performance
func BenchmarkHash_MAC(b *testing.B) {
	sess := &Session{
		CertOrganization: "",
		CertCommonName:   "",
		Interfaces:       memstore.NewSyncslice[protocol.NetInterface](),
	}

	sess.Interfaces.Append(protocol.NetInterface{
		Name:         "eth0",
		HardwareAddr: mustParseMAC("aa:bb:cc:dd:ee:ff"),
		Addresses:    []string{"10.0.0.1"},
	})
	sess.Interfaces.Append(protocol.NetInterface{
		Name:         "eth1",
		HardwareAddr: mustParseMAC("11:22:33:44:55:66"),
		Addresses:    []string{"10.0.0.2"},
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sess.Hash()
	}
}

// BenchmarkHash_Cert benchmarks the certificate-based hash performance
func BenchmarkHash_Cert(b *testing.B) {
	sess := &Session{
		CertOrganization: "team01",
		CertCommonName:   "agent-12345678",
		Interfaces:       memstore.NewSyncslice[protocol.NetInterface](),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sess.Hash()
	}
}

// BenchmarkHash_Cert_LongValues benchmarks certificate-based hash with longer org/CN values
func BenchmarkHash_Cert_LongValues(b *testing.B) {
	sess := &Session{
		CertOrganization: "very-long-organization-name-for-testing-performance",
		CertCommonName:   "very-long-common-name-with-uuid-12345678-90ab-cdef-1234-567890abcdef",
		Interfaces:       memstore.NewSyncslice[protocol.NetInterface](),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sess.Hash()
	}
}

// BenchmarkHash_MAC_MultipleInterfaces benchmarks MAC-based hash with many interfaces
func BenchmarkHash_MAC_MultipleInterfaces(b *testing.B) {
	sess := &Session{
		CertOrganization: "",
		CertCommonName:   "",
		Interfaces:       memstore.NewSyncslice[protocol.NetInterface](),
	}

	// Add 10 interfaces
	for i := 0; i < 10; i++ {
		sess.Interfaces.Append(protocol.NetInterface{
			Name:         "eth" + string(rune('0'+i)),
			HardwareAddr: mustParseMAC("aa:bb:cc:dd:ee:ff"),
			Addresses:    []string{"10.0.0.1"},
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sess.Hash()
	}
}
