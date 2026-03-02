# Execution Plan: Certificate-Based Session Identity

**Status:** Ready for Implementation  
**Created:** 2026-03-02  
**Related PRD:** `PRD-CERTIFICATE-BASED-SESSION-ID.md`  
**Estimated Effort:** 2-4 hours

## Overview

This execution plan details the step-by-step implementation of certificate-based session identity for Ligolo-MP, as specified in the PRD. The change replaces MAC address-based session IDs with certificate-based IDs.

## Prerequisites

- [ ] Read and understand `PRD-CERTIFICATE-BASED-SESSION-ID.md`
- [ ] Development environment set up with Go toolchain
- [ ] Access to test certificates for multiple teams
- [ ] Test VMs or environments with identical MAC addresses (for validation)

## Implementation Steps

### Step 1: Update Imports in `entity.go`

**File:** `internal/session/entity.go`

**Current imports (lines 3-20):**
```go
import (
	"crypto/sha1"
	"encoding/hex"
	// ... other imports
)
```

**Action:** Add SHA-256 import
```go
import (
	"crypto/sha1"
	"crypto/sha256"  // ADD THIS
	"encoding/hex"
	// ... other imports
)
```

**Verification:** Run `go build` to ensure no import errors

---

### Step 2: Modify the `Hash()` Method

**File:** `internal/session/entity.go:445-457`

**Current implementation:**
```go
func (sess *Session) Hash() string {
	hasher := sha1.New()

	ifaces := sess.Interfaces.All()
	sort.SliceStable(ifaces, func(i, j int) bool {
		return ifaces[i].HardwareAddr.String() > ifaces[j].HardwareAddr.String()
	})
	for _, ifaceInfo := range ifaces {
		hasher.Write([]byte(ifaceInfo.HardwareAddr))
	}

	return hex.EncodeToString(hasher.Sum(nil))
}
```

**New implementation:**
```go
func (sess *Session) Hash() string {
	// Certificate-based identity takes precedence
	if sess.CertOrganization != "" && sess.CertCommonName != "" {
		hasher := sha256.New()
		hasher.Write([]byte(sess.CertOrganization))
		hasher.Write([]byte(":"))
		hasher.Write([]byte(sess.CertCommonName))
		return hex.EncodeToString(hasher.Sum(nil))
	}

	// Fallback to MAC-based identity for backwards compatibility
	hasher := sha1.New()
	ifaces := sess.Interfaces.All()
	sort.SliceStable(ifaces, func(i, j int) bool {
		return ifaces[i].HardwareAddr.String() > ifaces[j].HardwareAddr.String()
	})
	for _, ifaceInfo := range ifaces {
		hasher.Write([]byte(ifaceInfo.HardwareAddr))
	}

	return hex.EncodeToString(hasher.Sum(nil))
}
```

**Changes:**
1. Check if `CertOrganization` and `CertCommonName` are both non-empty
2. If yes: use SHA-256 hash of `organization:commonName`
3. If no: fall back to existing MAC-based SHA-1 hash
4. Use SHA-256 for certificate-based IDs (stronger than SHA-1)

**Verification:** Run `go build` to ensure no syntax errors

---

### Step 3: Add Logging for Debugging

**File:** `internal/session/entity.go`

**Optional but recommended:** Add debug logging to the `Hash()` method to track which identity method is used:

```go
func (sess *Session) Hash() string {
	// Certificate-based identity takes precedence
	if sess.CertOrganization != "" && sess.CertCommonName != "" {
		hasher := sha256.New()
		hasher.Write([]byte(sess.CertOrganization))
		hasher.Write([]byte(":"))
		hasher.Write([]byte(sess.CertCommonName))
		hash := hex.EncodeToString(hasher.Sum(nil))
		slog.Debug("using certificate-based session ID",
			slog.String("org", sess.CertOrganization),
			slog.String("cn", sess.CertCommonName),
			slog.String("id", hash))
		return hash
	}

	// Fallback to MAC-based identity for backwards compatibility
	slog.Debug("using MAC-based session ID (no certificate)")
	hasher := sha1.New()
	ifaces := sess.Interfaces.All()
	sort.SliceStable(ifaces, func(i, j int) bool {
		return ifaces[i].HardwareAddr.String() > ifaces[j].HardwareAddr.String()
	})
	for _, ifaceInfo := range ifaces {
		hasher.Write([]byte(ifaceInfo.HardwareAddr))
	}
	hash := hex.EncodeToString(hasher.Sum(nil))
	slog.Debug("MAC-based session ID", slog.String("id", hash))
	return hash
}
```

**Verification:** Run `go build` to ensure logging compiles

---

### Step 4: Verify Certificate Fields Are Set

**File:** `internal/session/service.go:32-40`

**Current code (already correct):**
```go
func (ss *SessionService) NewSessionWithCert(multiplex *yamux.Session, certOrg, certCN string) (*Session, error) {
	session, err := new()
	if err != nil {
		return nil, err
	}

	// Set certificate information if provided
	session.CertOrganization = certOrg
	session.CertCommonName = certCN
	// ...
}
```

**Action:** Verify this code is correctly setting certificate fields
- No changes needed, just verification that the fields are populated

**Verification:** 
- Check that callers of `NewSessionWithCert()` pass proper org and CN values
- Add logging if needed to confirm values are received

---

### Step 5: Test Build and Syntax

**Commands:**
```bash
cd /root/ligolo-mp
go build ./...
```

**Expected Result:** Clean build with no errors

**If errors occur:**
- Check import statements
- Verify syntax of `Hash()` method
- Ensure `slog` is imported if logging was added

---

### Step 6: Create Test Plan Document

**File:** `docs/TEST-PLAN-CERTIFICATE-SESSION-ID.md`

Create a comprehensive test plan covering all scenarios from the PRD:

**Test scenarios to document:**

1. **TC-01: Multiple agents, different certs, same MAC**
   - Setup: Two agents with certs `team01/agent-A` and `team02/agent-B`, identical MAC addresses
   - Expected: Both connect successfully with different session IDs
   - Verification: Check session repository has two distinct sessions

2. **TC-02: Two agents, same cert, different machines**
   - Setup: Two agents with identical cert `team01/agent-A`, different MACs
   - Expected: Second connection rejected as duplicate
   - Verification: Log shows "connection is a duplicate"

3. **TC-03: Agent reconnection with cert**
   - Setup: Agent `team01/agent-A` connects, disconnects, reconnects
   - Expected: Session restored with same ID
   - Verification: Session ID unchanged, `IsConnected` transitions false → true

4. **TC-04: Non-certificate agent (backwards compat)**
   - Setup: Agent connects without certificate (empty org/CN)
   - Expected: Falls back to MAC-based session ID
   - Verification: Session ID matches old SHA-1(MAC) format

5. **TC-05: Certificate without org or CN**
   - Setup: Agent with cert but missing org or CN field
   - Expected: Falls back to MAC-based session ID
   - Verification: Logs show "using MAC-based session ID"

6. **TC-06: SWCCDC multi-team scenario**
   - Setup: 15 teams (team01-team15), agents on VMs with duplicate MACs
   - Expected: All 15 agents connect simultaneously
   - Verification: Session repository has 15 distinct sessions

---

### Step 7: Manual Testing

**Setup:**
```bash
# Build the proxy
cd cmd/proxy
go build -o ligolo-proxy

# Build test agents with certificates
# (Assumes certificate generation is available via Conduit or manual creation)
```

**Test Case 1: Different certs, same MAC**

Terminal 1 (Proxy):
```bash
./ligolo-proxy -selfcert
```

Terminal 2 (Agent Team01):
```bash
# Agent with cert org=team01, cn=agent-alpha
./ligolo-agent -connect localhost:11601 -cert team01.crt -key team01.key
```

Terminal 3 (Agent Team02):
```bash
# Agent with cert org=team02, cn=agent-beta
# Simulate same MAC by running on same VM
./ligolo-agent -connect localhost:11601 -cert team02.crt -key team02.key
```

**Expected result:**
- Both agents connect
- Proxy shows two distinct session IDs
- Session list shows both `team01/agent-alpha` and `team02/agent-beta`

**Test Case 2: Same cert, duplicate connection**

Terminal 1 (Proxy):
```bash
./ligolo-proxy -selfcert
```

Terminal 2 (Agent 1):
```bash
./ligolo-agent -connect localhost:11601 -cert team01.crt -key team01.key
```

Terminal 3 (Agent 2):
```bash
# Same certificate as Agent 1
./ligolo-agent -connect localhost:11601 -cert team01.crt -key team01.key
```

**Expected result:**
- First agent connects successfully
- Second agent connection rejected with "connection is a duplicate"

**Test Case 3: Session restoration**

Terminal 1 (Proxy):
```bash
./ligolo-proxy -selfcert
```

Terminal 2 (Agent):
```bash
# Connect
./ligolo-agent -connect localhost:11601 -cert team01.crt -key team01.key

# Note the session ID, then disconnect (Ctrl+C)
# Reconnect
./ligolo-agent -connect localhost:11601 -cert team01.crt -key team01.key
```

**Expected result:**
- Session ID remains the same after reconnection
- Proxy logs show "connection is unique, restoring session"

---

### Step 8: Integration Testing with Conduit

**Prerequisites:**
- Conduit backend running
- Agent generator producing certificates with proper org/CN

**Test steps:**

1. Generate agents for multiple teams via Conduit:
   ```bash
   # Generate agents for team01, team02, team03
   curl -X POST http://conduit:8080/api/agents/generate \
     -d '{"team": "team01", "count": 1}'
   ```

2. Deploy agents to test machines

3. Verify in Conduit dashboard:
   - Each agent shows correct team association
   - Session IDs are unique per team
   - No "duplicate connection" errors

4. Test scenario: Cloned VMs with identical MACs
   - Deploy team01 agent to VM-A (MAC: aa:bb:cc:dd:ee:ff)
   - Deploy team02 agent to VM-B (MAC: aa:bb:cc:dd:ee:ff)
   - Both should connect successfully

**Expected result:**
- All agents visible in dashboard
- Correct team labels displayed
- Routes managed independently per agent

---

### Step 9: Performance Validation

**Test:** Measure performance impact of SHA-256 vs SHA-1

```go
// Add benchmark test to internal/session/entity_test.go
func BenchmarkHash_MAC(b *testing.B) {
	sess := &Session{
		Interfaces: /* ... populate with test MACs ... */
	}
	for i := 0; i < b.N; i++ {
		_ = sess.Hash()
	}
}

func BenchmarkHash_Cert(b *testing.B) {
	sess := &Session{
		CertOrganization: "team01",
		CertCommonName:   "agent-12345678",
		Interfaces:       /* ... empty or minimal ... */
	}
	for i := 0; i < b.N; i++ {
		_ = sess.Hash()
	}
}
```

**Run benchmark:**
```bash
go test -bench=. -benchmem ./internal/session/
```

**Expected result:**
- Certificate-based hashing should be faster (simpler input)
- Memory allocation should be negligible for both
- No significant performance degradation

---

### Step 10: Documentation Updates

**Files to update:**

1. **README.md** (if exists in project root)
   - Add note about certificate-based session identity
   - Mention backwards compatibility with non-cert agents

2. **CHANGELOG.md** (create if not exists)
   ```markdown
   ## [Unreleased]
   
   ### Changed
   - Session identity now based on mTLS certificate (org + CN) instead of MAC addresses
   - Enables multiple agents with different certificates on same physical machine
   - Backwards compatible: non-certificate agents fall back to MAC-based identity
   
   ### Fixed
   - Fixed "duplicate connection" errors in multi-team environments with cloned VMs
   - Fixed session state mixing between different teams' agents
   ```

3. **docs/ARCHITECTURE.md** (create if not exists)
   - Document new session identity mechanism
   - Explain fallback behavior

---

## Rollout Plan

### Development Environment
1. Implement changes in feature branch: `feature/cert-based-session-id`
2. Run all tests (Steps 7-9)
3. Code review
4. Merge to `main`

### Staging Environment
1. Deploy to staging Ligolo-MP instance
2. Test with Conduit integration
3. Verify multi-team scenarios
4. Monitor logs for errors

### Production Environment
1. Deploy during maintenance window
2. Monitor for "duplicate connection" errors (should decrease)
3. Verify session restoration works correctly
4. Have rollback plan ready (revert commit)

---

## Rollback Procedure

If critical issues occur in production:

**Step 1: Revert the commit**
```bash
git revert <commit-hash>
git push origin main
```

**Step 2: Rebuild and redeploy**
```bash
go build ./cmd/proxy
# Deploy reverted binary
```

**Step 3: Monitor**
- Existing sessions will disconnect (session IDs changed)
- Agents will reconnect with MAC-based IDs
- Session state may be lost for currently connected agents

**Step 4: Investigate**
- Review logs to identify root cause
- Fix issue in development
- Re-test before re-deployment

---

## Success Criteria

Implementation is considered successful when:

- [ ] Code builds without errors
- [ ] All 6 test cases (TC-01 through TC-06) pass
- [ ] No performance regression (< 5% overhead)
- [ ] Conduit integration works correctly
- [ ] Documentation updated
- [ ] Zero "duplicate connection" errors in multi-team SWCCDC scenario
- [ ] Backwards compatibility verified (non-cert agents still work)

---

## Risk Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Session state lost during upgrade | High | Medium | Expected behavior; document that active sessions will reconnect |
| Certificate fields not populated | Medium | High | Add validation/logging in `NewSessionWithCert()` |
| Hash collision (different certs, same hash) | Very Low | High | SHA-256 has negligible collision probability; monitor logs |
| Backwards compat broken | Low | High | Comprehensive testing with non-cert agents |
| Performance degradation | Very Low | Medium | Benchmark tests before deployment |

---

## Post-Implementation Tasks

After successful deployment:

1. **Monitor metrics:**
   - Session connection success rate
   - "Duplicate connection" error frequency
   - Session restoration success rate

2. **Gather feedback:**
   - SWCCDC operators experience
   - Conduit integration stability
   - Any edge cases encountered

3. **Future enhancements (from PRD):**
   - Hybrid identity (cert + MAC)
   - Configurable identity strategy via flag
   - Display cert metadata in operator UI
   - Support for multi-session per certificate

---

## Timeline

| Phase | Duration | Tasks |
|-------|----------|-------|
| **Day 1: Implementation** | 2-3 hours | Steps 1-5 (code changes) |
| **Day 1: Testing** | 1-2 hours | Steps 6-7 (build, manual tests) |
| **Day 2: Integration** | 2-3 hours | Step 8 (Conduit integration) |
| **Day 2: Validation** | 1 hour | Steps 9-10 (performance, docs) |
| **Day 3: Review & Deploy** | 2-4 hours | Code review, staging deployment |
| **Day 4: Production** | 1-2 hours | Production deployment, monitoring |

**Total estimated effort:** 9-15 hours across 4 days

---

## Contacts & Resources

- **PRD Author:** SWCCDC Team
- **Implementation Owner:** [TBD]
- **Code Repository:** https://github.com/ttpreport/ligolo-mp
- **Related Issue:** Duplicate connection errors (2026-03-02)
- **Test Environment:** SWCCDC Conduit deployment

---

## Appendix A: Code Diff Summary

**File:** `internal/session/entity.go`

```diff
import (
	"crypto/sha1"
+	"crypto/sha256"
	"encoding/hex"
	// ...
)

func (sess *Session) Hash() string {
+	// Certificate-based identity takes precedence
+	if sess.CertOrganization != "" && sess.CertCommonName != "" {
+		hasher := sha256.New()
+		hasher.Write([]byte(sess.CertOrganization))
+		hasher.Write([]byte(":"))
+		hasher.Write([]byte(sess.CertCommonName))
+		return hex.EncodeToString(hasher.Sum(nil))
+	}
+
+	// Fallback to MAC-based identity for backwards compatibility
	hasher := sha1.New()
	ifaces := sess.Interfaces.All()
	// ... (rest unchanged)
}
```

**Lines changed:** ~15 lines added, 0 lines removed  
**Files modified:** 1 (`internal/session/entity.go`)

---

## Appendix B: Session ID Examples

### Before (MAC-based)
```
Agent: team01/agent-A (MAC: aa:bb:cc:dd:ee:ff)
Session ID: 0d9bb9082e92e5755fe1a0149666f144207237d2  (SHA-1 of MAC)

Agent: team02/agent-B (MAC: aa:bb:cc:dd:ee:ff)  [same MAC!]
Session ID: 0d9bb9082e92e5755fe1a0149666f144207237d2  (DUPLICATE!)
```

### After (Certificate-based)
```
Agent: team01/agent-A (Cert: org=team01, cn=agent-A)
Session ID: 8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92  (SHA-256 of "team01:agent-A")

Agent: team02/agent-B (Cert: org=team02, cn=agent-B)
Session ID: 5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5  (SHA-256 of "team02:agent-B")
```

**Result:** Unique session IDs even with identical MACs!
