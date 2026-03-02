package session

import (
	"fmt"
	"testing"

	"github.com/ttpreport/ligolo-mp/v2/internal/protocol"
	"github.com/ttpreport/ligolo-mp/v2/pkg/memstore"
)

// createTestSession creates a session for integration testing
func createTestSession(org, cn string) *Session {
	sess := &Session{
		CertOrganization: org,
		CertCommonName:   cn,
		Interfaces:       memstore.NewSyncslice[protocol.NetInterface](),
		Redirectors:      memstore.NewSyncmap[string, Redirector](),
	}

	// Add a test interface with a common MAC address
	sess.Interfaces.Append(protocol.NetInterface{
		Name:         "eth0",
		HardwareAddr: mustParseMAC("aa:bb:cc:dd:ee:ff"),
		Addresses:    []string{"10.0.0.1"},
	})

	sess.Hostname = "test-host"
	return sess
}

// TestIntegration_TC01_MultipleCertsSameMac tests TC-01 from the exec plan:
// Multiple agents with different certificates but same MAC address should create distinct sessions
func TestIntegration_TC01_MultipleCertsSameMac(t *testing.T) {
	// Scenario: Two VMs with certs team01/agent-A and team02/agent-B, identical MAC addresses
	sess1 := createTestSession("team01", "agent-A")
	sess2 := createTestSession("team02", "agent-B")

	id1 := sess1.Hash()
	id2 := sess2.Hash()

	// Both should have different session IDs despite same MAC
	if id1 == id2 {
		t.Errorf("TC-01 FAILED: Sessions with different certificates should have different IDs, both got %v", id1)
	}

	// Both should use certificate-based hash (SHA-256, 64 hex chars)
	if len(id1) != 64 || len(id2) != 64 {
		t.Errorf("TC-01 FAILED: Certificate-based hashes should be 64 chars, got %d and %d", len(id1), len(id2))
	}

	t.Logf("TC-01 PASSED: team01/agent-A -> %s", id1)
	t.Logf("TC-01 PASSED: team02/agent-B -> %s", id2)
}

// TestIntegration_TC02_SameCertDifferentMachines tests TC-02 from the exec plan:
// Two agents with identical certificate should be identified as duplicates
func TestIntegration_TC02_SameCertDifferentMachines(t *testing.T) {
	// Scenario: Two agents with identical cert team01/agent-A, different MACs
	sess1 := createTestSession("team01", "agent-A")

	sess2 := &Session{
		CertOrganization: "team01",
		CertCommonName:   "agent-A",
		Interfaces:       memstore.NewSyncslice[protocol.NetInterface](),
	}
	// Different MAC address
	sess2.Interfaces.Append(protocol.NetInterface{
		Name:         "eth0",
		HardwareAddr: mustParseMAC("11:22:33:44:55:66"),
		Addresses:    []string{"10.0.0.2"},
	})

	id1 := sess1.Hash()
	id2 := sess2.Hash()

	// Should have the same session ID (certificate takes precedence)
	if id1 != id2 {
		t.Errorf("TC-02 FAILED: Sessions with same certificate should have same ID, got %s and %s", id1, id2)
	}

	t.Logf("TC-02 PASSED: Both agents with team01/agent-A have same ID: %s", id1)
}

// TestIntegration_TC03_AgentReconnection tests TC-03 from the exec plan:
// Agent reconnection with certificate should maintain same session ID
func TestIntegration_TC03_AgentReconnection(t *testing.T) {
	// Scenario: Agent team01/agent-A connects, disconnects, reconnects
	sess1 := createTestSession("team01", "agent-A")
	id1 := sess1.Hash()

	// Simulate disconnection (session ID should not change)
	sess1.IsConnected = false

	// Simulate reconnection - create new session object with same certificate
	sess2 := createTestSession("team01", "agent-A")
	id2 := sess2.Hash()

	if id1 != id2 {
		t.Errorf("TC-03 FAILED: Session ID should remain same after reconnection, got %s and %s", id1, id2)
	}

	t.Logf("TC-03 PASSED: Session ID unchanged after reconnection: %s", id1)
}

// TestIntegration_TC04_NoCertificateBackwardsCompat tests TC-04 from the exec plan:
// Agent without certificate should fall back to MAC-based session ID
func TestIntegration_TC04_NoCertificateBackwardsCompat(t *testing.T) {
	// Scenario: Agent connects without certificate (empty org/CN)
	sess := createTestSession("", "")

	id := sess.Hash()

	// Should use MAC-based hash (SHA-1, 40 hex chars)
	if len(id) != 40 {
		t.Errorf("TC-04 FAILED: Non-certificate session should use SHA-1 (40 chars), got %d", len(id))
	}

	t.Logf("TC-04 PASSED: Non-certificate agent uses MAC-based ID (40 chars): %s", id)
}

// TestIntegration_TC05_PartialCertificate tests TC-05 from the exec plan:
// Certificate without org or CN should fall back to MAC-based session ID
func TestIntegration_TC05_PartialCertificate(t *testing.T) {
	// Scenario 1: Agent with cert but missing org field
	sess1 := createTestSession("", "agent-A")
	id1 := sess1.Hash()

	// Scenario 2: Agent with cert but missing CN field
	sess2 := createTestSession("team01", "")
	id2 := sess2.Hash()

	// Both should fall back to MAC-based hash (SHA-1, 40 chars)
	if len(id1) != 40 {
		t.Errorf("TC-05 FAILED: Session with only CN should use MAC-based hash (40 chars), got %d", len(id1))
	}
	if len(id2) != 40 {
		t.Errorf("TC-05 FAILED: Session with only org should use MAC-based hash (40 chars), got %d", len(id2))
	}

	t.Logf("TC-05 PASSED: Partial cert (only CN) falls back to MAC-based ID: %s", id1)
	t.Logf("TC-05 PASSED: Partial cert (only org) falls back to MAC-based ID: %s", id2)
}

// TestIntegration_TC06_MultiTeamScenario tests TC-06 from the exec plan:
// 15 teams, agents on VMs with duplicate MACs should all connect successfully
func TestIntegration_TC06_MultiTeamScenario(t *testing.T) {
	// Scenario: 15 teams (team01-team15), agents on VMs with duplicate MACs
	teamCount := 15
	sessionIDs := make(map[string]bool)

	for i := 1; i <= teamCount; i++ {
		teamName := "team" + fmt.Sprintf("%02d", i)
		sess := createTestSession(teamName, "agent-alpha")

		id := sess.Hash()

		// Check for duplicates
		if sessionIDs[id] {
			t.Errorf("TC-06 FAILED: Duplicate session ID found for %s: %s", teamName, id)
		}
		sessionIDs[id] = true

		t.Logf("TC-06: %s -> %s", teamName, id[:16]+"...")
	}

	// Verify all 15 sessions have unique IDs
	if len(sessionIDs) != teamCount {
		t.Errorf("TC-06 FAILED: Expected %d unique sessions, got %d", teamCount, len(sessionIDs))
	}

	t.Logf("TC-06 PASSED: All %d teams have unique session IDs", teamCount)
}

// TestIntegration_RealWorldSWCCDCScenario tests a comprehensive real-world scenario
// combining all test cases from the execution plan
func TestIntegration_RealWorldSWCCDCScenario(t *testing.T) {
	// Simulate SWCCDC environment:
	// - 15 teams (team01-team15)
	// - Each team has 2 agents (agent-A, agent-B)
	// - All VMs share the same MAC address pool (cloned VMs)

	sessionIDs := make(map[string]string) // id -> team/agent
	duplicates := 0

	for teamNum := 1; teamNum <= 15; teamNum++ {
		teamName := fmt.Sprintf("team%02d", teamNum)

		for _, agentName := range []string{"agent-A", "agent-B"} {
			sess := createTestSession(teamName, agentName)
			id := sess.Hash()

			identifier := teamName + "/" + agentName

			// Check if this ID already exists
			if existing, exists := sessionIDs[id]; exists {
				t.Errorf("DUPLICATE: %s has same ID as %s: %s", identifier, existing, id)
				duplicates++
			} else {
				sessionIDs[id] = identifier
			}
		}
	}

	expectedSessions := 15 * 2 // 15 teams * 2 agents each
	if len(sessionIDs) != expectedSessions {
		t.Errorf("Expected %d unique sessions, got %d", expectedSessions, len(sessionIDs))
	}

	if duplicates > 0 {
		t.Fatalf("Found %d duplicate session IDs in SWCCDC scenario", duplicates)
	}

	t.Logf("SWCCDC SCENARIO PASSED: All %d sessions have unique IDs", expectedSessions)
}

// TestIntegration_CertVsMACPerformance compares performance characteristics
func TestIntegration_CertVsMACPerformance(t *testing.T) {
	// Certificate-based session
	certSess := createTestSession("team01", "agent-A")
	certID := certSess.Hash()

	// MAC-based session
	macSess := createTestSession("", "")
	macID := macSess.Hash()

	// Verify hash lengths
	if len(certID) != 64 {
		t.Errorf("Certificate-based hash should be 64 chars (SHA-256), got %d", len(certID))
	}
	if len(macID) != 40 {
		t.Errorf("MAC-based hash should be 40 chars (SHA-1), got %d", len(macID))
	}

	t.Logf("Certificate-based ID (SHA-256, 64 chars): %s", certID)
	t.Logf("MAC-based ID (SHA-1, 40 chars): %s", macID)
}
