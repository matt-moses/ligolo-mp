# PRD: Certificate-Based Session Identity

**Status:** Draft  
**Created:** 2026-03-02  
**Author:** SWCCDC Team  
**Project:** Ligolo-MP Fork

## Problem Statement

Currently, Ligolo-MP identifies agent sessions using a SHA-1 hash of the agent's network interface MAC addresses. This creates several issues in multi-team competition environments like SWCCDC:

### Current Behavior
- Session ID is calculated from: `SHA1(sorted MAC addresses of all network interfaces)`
- Located in: `internal/session/entity.go:445-457`
- When an agent connects, Ligolo-MP checks if a session with that ID already exists
- If a session exists and `IsConnected == true`, the new connection is rejected as "duplicate"

### Issues

1. **Cannot run multiple agents on same physical/virtual machine**: Two VMs with identical MAC addresses (e.g., cloned VMs, VLAN-trunked environments) generate the same session ID, causing "duplicate connection" errors
   
2. **Session persistence confusion**: When Agent A disconnects and Agent B (different team, different certificate) connects from the same machine, Ligolo-MP restores Agent A's session state to Agent B
   
3. **Certificate ignored for identity**: The mTLS certificate (Organization + Common Name) is captured during connection but not used for session identification

4. **Multi-team scenario failure**: In SWCCDC, operators deploy agents for multiple teams (Team 01-15). If agents from different teams run on machines with identical MAC addresses (common in cloud/VM environments), only one can connect at a time

### Real-World Example

```
Timeline:
1. Agent Team01 connects from 10.101.100.2 (MAC: aa:bb:cc:dd:ee:ff)
   - Session ID: 0d9bb9082e92e5755fe1a0149666f144207237d2
   - Certificate: team01/team01-dc-df695028
   
2. Agent Team02 tries to connect from 10.101.100.3 (MAC: aa:bb:cc:dd:ee:ff) [same MAC]
   - Session ID: 0d9bb9082e92e5755fe1a0149666f144207237d2 [SAME!]
   - Certificate: team02/team02-agent-3f1d5185
   - Result: ERROR "connection is a duplicate"
   
3. Agent Team01 disconnects

4. Agent Team02 connects successfully
   - Ligolo-MP RESTORES Team01's session
   - Team02 agent now has Team01's session metadata in database
```

## Proposed Solution

Change session identity from MAC-based to **certificate-based** using the TLS certificate's Organization and Common Name fields.

### Design

#### New Session ID Calculation

```go
// Current (MAC-based)
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

// Proposed (Certificate-based)
func (sess *Session) Hash() string {
    hasher := sha256.New()
    
    // Use certificate organization and common name for identity
    if sess.CertOrganization != "" && sess.CertCommonName != "" {
        hasher.Write([]byte(sess.CertOrganization))
        hasher.Write([]byte(":"))
        hasher.Write([]byte(sess.CertCommonName))
        return hex.EncodeToString(hasher.Sum(nil))
    }
    
    // Fallback to MAC-based for backwards compatibility with non-cert agents
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

#### Session Lifecycle Changes

**Current Flow:**
```
1. Agent connects → Calculate session ID from MAC
2. Check if session ID exists in repository
3. If exists AND IsConnected → reject as duplicate
4. If exists AND NOT IsConnected → restore saved session state
5. Save session
```

**Proposed Flow:**
```
1. Agent connects → Extract certificate (org + CN)
2. Calculate session ID from certificate
3. Check if session ID exists in repository
4. If exists AND IsConnected → reject as duplicate (same cert = same agent)
5. If exists AND NOT IsConnected → restore saved session state
6. Save session
```

### Benefits

1. **Multiple agents per machine**: Agents with different certificates can coexist on the same physical/virtual machine
2. **Team isolation**: Each team's agents are identified by their unique certificates (e.g., `team01`, `team02`)
3. **Proper session restoration**: Only the same agent (same cert) can restore its previous session
4. **Backwards compatible**: Non-certificate connections fall back to MAC-based identity

### Edge Cases

| Scenario | Current Behavior | New Behavior |
|----------|------------------|--------------|
| Two agents, same cert, same machine | Second rejected (duplicate MAC) | Second rejected (duplicate cert) ✅ |
| Two agents, different certs, same machine | Second rejected (duplicate MAC) ❌ | Both connect ✅ |
| Agent reconnects after disconnect | Session restored (same MAC) | Session restored (same cert) ✅ |
| Non-certificate agent connects | Uses MAC hash | Uses MAC hash (fallback) ✅ |
| Certificate not available | N/A | Falls back to MAC hash ✅ |

## Implementation Plan

### Phase 1: Core Changes
**Files to modify:**
- `internal/session/entity.go`
  - Update `Hash()` method (lines 445-457)
  - Add certificate-based hashing
  - Keep MAC-based fallback

### Phase 2: Testing
**Test scenarios:**
1. Two agents with different certs, same MAC → both should connect
2. Two agents with same cert, different MACs → second should be rejected
3. Agent with cert disconnects and reconnects → session should restore
4. Non-cert agent connects → should use MAC-based ID

### Phase 3: Integration with Conduit
**Verify:**
- Conduit backend correctly tracks multiple agents per team
- Dashboard shows correct team associations
- Route management works per-agent

## Acceptance Criteria

- [ ] Agents with different certificates can connect from machines with identical MAC addresses
- [ ] Agents with the same certificate are correctly identified as duplicates
- [ ] Session restoration works based on certificate identity
- [ ] Backwards compatibility: non-certificate agents still work with MAC-based identity
- [ ] No breaking changes to gRPC API or protocol
- [ ] Conduit integration: agents show correct team and certificate info

## Security Considerations

- **Certificate validation**: Certificate-based identity assumes proper mTLS setup and certificate validation
- **Certificate uniqueness**: Operators must ensure each agent receives a unique certificate (handled by Conduit's agent generator)
- **Revocation**: No certificate revocation mechanism exists; disconnecting a compromised agent is manual

## Performance Impact

- **Minimal**: SHA-256 hash of two strings vs SHA-1 hash of MAC addresses
- **Session lookup**: Same repository lookup mechanism, just different hash input
- **Memory**: No additional memory overhead

## Rollback Plan

If issues arise:
1. Revert `Hash()` method to MAC-based implementation
2. All existing sessions will get new IDs (certificates weren't used before)
3. Sessions will reconnect with MAC-based IDs

## Future Enhancements

1. **Hybrid identity**: Include both certificate AND MAC in hash for maximum uniqueness
2. **Configurable identity strategy**: Allow operators to choose MAC-based vs cert-based via flag
3. **Certificate metadata in UI**: Display certificate org/CN in operator interface
4. **Multi-session per cert**: Allow same certificate to have multiple concurrent sessions (advanced use case)

## Related Code

### Current Implementation
```go
// internal/session/entity.go:445-457
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

### Certificate Extraction
```go
// internal/session/service.go:32-40
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

### Session ID Assignment
```go
// internal/session/entity.go:158-197
func (sess *Session) Connect(multiplex *yamux.Session) error {
    sess.Multiplex = multiplex
    info, err := sess.remoteGetInfo()
    // ...
    sess.Hostname = info.Hostname
    sess.ID = sess.Hash() // ← Session ID set here
    sess.IsConnected = true
    // ...
}
```

### Duplicate Detection
```go
// internal/session/service.go:46-53
savedSession := ss.repo.GetOne(session.ID)
if savedSession != nil {
    if savedSession.IsConnected {
        slog.Debug("connection is a duplicate, aborting")
        session.CleanUp()
        return nil, errors.New("connection is a duplicate")
    }
}
```

## References

- Issue discovered: 2026-03-02 during SWCCDC Conduit deployment
- Error message: `time=2026-03-02T01:21:20.970Z level=ERROR msg="could not initialize new session" error="connection is a duplicate"`
- Root cause: Two VMs (Team 01 and Team 02 agents) had identical MAC addresses due to VM cloning
