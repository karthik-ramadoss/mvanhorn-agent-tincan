// Package identity decides which agent sent a request. An agent is a name Matt
// chose, bound to one tailnet node by a one-time invite code. There are no
// keys: Tailscale authenticates the node, and the directory maps node to name.
// A node may carry several agents (claude-code and codex on one laptop); the
// client then names itself and the directory accepts the name only if it is
// bound to the calling node.
package identity

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// InviteTTL is how long an invite code stays valid.
const InviteTTL = 10 * time.Minute

// LocalAdmin is the remote address the relay passes for commands that arrive
// on its local admin socket. It always has admin rights.
const LocalAdmin = "local-admin"

var (
	ErrNotJoined          = errors.New("not a joined agent")
	ErrNotAdmin           = errors.New("admin commands must come from an admin device")
	ErrBadInvite          = errors.New("invite code is invalid, used, or expired")
	ErrUnknownAgent       = errors.New("no such agent")
	ErrEnrollmentConflict = errors.New("enrollment conflicts with existing binding")
	ErrPendingInvite      = errors.New("enrollment conflicts with pending invitation")
	// ErrAgentAmbiguous means several agents share the calling machine and the
	// request did not say which one it comes from.
	ErrAgentAmbiguous = errors.New("several agents share this machine; the client must name one (point TINCAN_CONFIG at that agent's config)")
	// ErrRebindCheckFailed means re-admitting a rebuilt machine could not
	// check whether the agent's old node is still online. It is a transient
	// failure, not a refusal.
	ErrRebindCheckFailed = errors.New("could not check the agent's old node; try again")
)

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

var serviceTagRE = regexp.MustCompile(`^tag:[a-z][a-z0-9-]*$`)

// ValidateServiceRoles validates explicit environment-level grants. A shared
// backend tag is not a dedicated authorization role. Configuration must come
// from the relay owner; neither a hostname nor a request header defines a role.
func ValidateServiceRoles(roles map[string]string) error {
	for tag, name := range roles {
		if !serviceTagRE.MatchString(tag) || tag == "tag:codex-forgejo" {
			return fmt.Errorf("service role %q must be a dedicated Tailscale tag (tag:codex-forgejo is shared)", tag)
		}
		if !ValidName(name) {
			return fmt.Errorf("service role %q has invalid agent name %q", tag, name)
		}
	}
	return nil
}

// ValidName reports whether name is an agent name the relay accepts: 1-32
// lowercase letters, digits or dashes, starting with a letter or digit.
func ValidName(name string) bool { return nameRE.MatchString(name) }

// Kinds share the name shape: lowercase words such as hermes or vm-webhook.
func checkKind(kind string) error {
	if kind != "" && !nameRE.MatchString(kind) {
		return fmt.Errorf("agent kind %q must be 1-32 lowercase letters, digits, or dashes", kind)
	}
	return nil
}

// maxGoodAtRunes caps an agent's good-at line so the roster stays scannable.
const maxGoodAtRunes = 120

// checkGoodAt trims line and reports the line to store ("" clears it). A line
// is one printable line: valid UTF-8, at most maxGoodAtRunes runes, and no
// control or format characters, newlines and tabs included.
func checkGoodAt(line string) (string, error) {
	line = strings.TrimSpace(line)
	if !utf8.ValidString(line) {
		return "", errors.New("the good-at line is not valid UTF-8")
	}
	if utf8.RuneCountInString(line) > maxGoodAtRunes {
		return "", fmt.Errorf("the good-at line is over %d characters", maxGoodAtRunes)
	}
	if strings.IndexFunc(line, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) >= 0 {
		return "", errors.New("the good-at line contains a line break or other control character")
	}
	return line, nil
}

// Agent is a joined agent.
type Agent struct {
	Name     string    `json:"name"`
	NodeID   string    `json:"node_id"`
	NodeName string    `json:"node_name"`
	JoinedAt time.Time `json:"joined_at"`
	// Kind is the agent runtime (hermes, codex, ...), empty when unknown.
	Kind string `json:"kind,omitempty"`
	// NodeUser is the Tailscale login that owned the node at join, empty for
	// agents joined before it was recorded.
	NodeUser string `json:"node_user,omitempty"`
	// GoodAt is the owner-written line saying what the agent is good at,
	// empty when unset. Only SetAgentGoodAt writes it; PutAgent keeps it.
	GoodAt string `json:"good_at,omitempty"`
}

// Invite is a pending one-time code.
//
// Code carries the raw code only at mint time, on the way to the admin that
// asked for it. Everything persisted (see PutInvite) holds only the digest
// produced by hashInviteCode, never the raw code.
type Invite struct {
	Code    string
	Name    string
	Kind    string // applied to the agent on join when set
	Expires time.Time
}

// Store persists agents and invites. The relay backs it with SQLite; tests
// use NewMemoryStore.
type Store interface {
	// CreateAgent inserts without replacement, rejecting an unexpired invite.
	CreateAgent(ctx context.Context, a Agent, now time.Time) (Agent, bool, error)
	// ReplaceAgentNode compares the expected binding and changes only node identity.
	// Persistent stores must commit the replacement and its audit together.
	ReplaceAgentNode(ctx context.Context, name, expectedOld string, target Node, now time.Time) (Agent, error)
	PutAgent(ctx context.Context, a Agent) error
	DeleteAgent(ctx context.Context, name string) (bool, error)
	Agents(ctx context.Context) ([]Agent, error)
	// AgentsByNode and AgentByName are lookups for the hot request path.
	// AgentsByNode returns every agent bound to the node, ordered by name.
	AgentsByNode(ctx context.Context, nodeID string) ([]Agent, error)
	AgentByName(ctx context.Context, name string) (Agent, bool, error)
	// SetAgentKind records an agent's runtime kind ("" clears it) and reports
	// whether the agent exists.
	SetAgentKind(ctx context.Context, name, kind string) (bool, error)
	// SetAgentGoodAt records an agent's owner-written good-at line ("" clears
	// it) and reports whether the agent exists. PutAgent keeps the line an
	// existing agent already has.
	SetAgentGoodAt(ctx context.Context, name, line string) (bool, error)
	// PutInvite stores inv and retires any earlier unredeemed code for the
	// same name, so re-inviting a name leaves only the newest code valid.
	// Callers pass inv.Code already digested (see hashInviteCode); the raw
	// code never reaches the store. Implementations persist the value
	// opaquely — they hold no pepper and perform no hashing.
	PutInvite(ctx context.Context, inv Invite) error
	// TakeInvite removes and returns the invite, so a code works once.
	// Callers pass the digest produced by hashInviteCode, not the raw code.
	TakeInvite(ctx context.Context, code string) (Invite, bool, error)
}

// Config tunes a Directory.
type Config struct {
	// Admins lists the machine names allowed to invite and remove agents.
	Admins []string
	// AdminLogins, when set, also requires an admin node's owning Tailscale
	// login to be listed. Every node on a single-user tailnet shares one login,
	// so this narrows admin rights but cannot replace the machine list.
	AdminLogins []string
	// NoAutoRebind turns off re-admitting rebuilt machines (see ResolveAgent).
	NoAutoRebind bool
	// ServiceRoles explicitly grants a verified WhoIs tag access to an already
	// enrolled logical agent. It does not prove which task started the node.
	// A service-role call never moves the agent's stored node binding. Nil or
	// empty preserves normal node-bound authorization.
	ServiceRoles map[string]string
	// InvitePepper is the relay-local secret used to digest invite codes
	// before they are persisted (see hashInviteCode). When empty, NewDirectory
	// generates an ephemeral one: fine for tests and single-process relays,
	// but a production relay must pass a pepper persisted in its state dir so
	// outstanding invites survive a restart.
	InvitePepper []byte
	// Now overrides the clock in tests.
	Now func() time.Time
}

// Directory maps tailnet nodes to agent names.
type Directory struct {
	store        Store
	who          Resolver
	cfg          Config
	invitePepper []byte
	mu           sync.Mutex // serializes join so a name moves atomically
}

// NewDirectory builds a Directory. Invalid ServiceRoles or an InvitePepper
// other than 32 bytes panics, so a misconfigured grant or key fails fast.
func NewDirectory(store Store, who Resolver, cfg Config) *Directory {
	if err := ValidateServiceRoles(cfg.ServiceRoles); err != nil {
		panic(fmt.Sprintf("identity: %v", err))
	}
	if cfg.ServiceRoles != nil {
		// Freeze the authorization policy so later caller map changes cannot
		// silently add grants or race request attribution.
		roles := make(map[string]string, len(cfg.ServiceRoles))
		maps.Copy(roles, cfg.ServiceRoles)
		cfg.ServiceRoles = roles
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	pepper := cfg.InvitePepper
	if len(pepper) == 0 {
		// Ephemeral pepper: outstanding invites are lost on restart, which is
		// acceptable for tests. Production relays pass a persisted pepper.
		pepper = make([]byte, 32)
		if _, err := rand.Read(pepper); err != nil {
			panic(fmt.Sprintf("identity: cannot generate invite pepper: %v", err))
		}
	} else {
		if len(pepper) != 32 {
			panic(fmt.Sprintf("identity: invite pepper has %d bytes, want 32", len(pepper)))
		}
		// Copy: the Directory must not retain the caller's buffer, which the
		// caller could mutate after minting and silently invalidate
		// outstanding invites.
		pepper = append([]byte(nil), pepper...)
	}
	return &Directory{store: store, who: who, cfg: cfg, invitePepper: pepper}
}

// hashInviteCode returns the hex HMAC-SHA256 of the normalized code under the
// relay's invite pepper. Only this digest is ever persisted; the raw code is
// shown once to the admin that minted it and never stored. The pepper makes
// the 40-bit code space unsearchable to anyone holding only the database.
func hashInviteCode(pepper []byte, code string) string {
	norm := strings.ToUpper(strings.TrimSpace(code))
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(norm))
	return hex.EncodeToString(mac.Sum(nil))
}

// Attribute returns the agent name for the node behind remoteAddr when the
// caller does not name itself. It fails with ErrAgentAmbiguous when the node
// carries several agents.
func (d *Directory) Attribute(ctx context.Context, remoteAddr string) (string, error) {
	return d.Resolve(ctx, remoteAddr, "")
}

// Resolve returns the agent behind remoteAddr. WhoIs authenticates the node;
// claimed, when set, picks one of the node's agents and is accepted only if
// that name is bound to the node. With no claim, a node with one agent
// resolves to it and a node with several fails with the choices. A rebuilt
// machine is re-admitted on the way (see ResolveAgent).
func (d *Directory) Resolve(ctx context.Context, remoteAddr, claimed string) (string, error) {
	res, err := d.ResolveAgent(ctx, remoteAddr, claimed)
	return res.Name, err
}

// ResolveAgent is Resolve that also reports a rebind. When the caller's node
// carries no agent, or not the claimed one, it tries to re-admit the node as
// a rebuilt machine before refusing.
func (d *Directory) ResolveAgent(ctx context.Context, remoteAddr, claimed string) (Resolved, error) {
	res, _, err := d.ResolveActor(ctx, remoteAddr, claimed)
	return res, err
}

// ResolveActor also returns the authenticated caller's actual StableID. A
// service-role grant changes only the logical name; the actor remains the node
// WhoIs verified, so distinct workers do not share an ownership or audit actor.
// ResolveAgent and Resolve retain their existing result shapes.
func (d *Directory) ResolveActor(ctx context.Context, remoteAddr, claimed string) (Resolved, string, error) {
	n, err := d.who.WhoIs(ctx, remoteAddr)
	if err != nil {
		return Resolved{}, "", err
	}
	res, err := d.resolveNode(ctx, n, claimed)
	if err != nil {
		return Resolved{}, "", err
	}
	return res, n.ID, nil
}

func (d *Directory) resolveNode(ctx context.Context, n Node, claimed string) (Resolved, error) {
	if res, matched, err := d.resolveServiceRole(ctx, n, claimed); matched || err != nil {
		return res, err
	}
	agents, err := d.store.AgentsByNode(ctx, n.ID)
	if err != nil {
		return Resolved{}, err
	}
	if claimed != "" {
		for _, a := range agents {
			if a.Name == claimed {
				return d.resolved(ctx, n, a)
			}
		}
		if res, ok, err := d.readmit(ctx, n, claimed); ok || err != nil {
			return res, err
		}
		return Resolved{}, fmt.Errorf("%s is not %q: %w", n.Name, claimed, ErrNotJoined)
	}
	switch len(agents) {
	case 0:
		if res, ok, err := d.readmit(ctx, n, ""); ok || err != nil {
			return res, err
		}
		return Resolved{}, fmt.Errorf("%s: %w", n.Name, ErrNotJoined)
	case 1:
		// Another agent from the same rebuilt machine may still be waiting to
		// be re-admitted, and this nameless call may be its first.
		waiting, err := d.awaitingReadmit(ctx, n)
		if err != nil {
			return Resolved{}, err
		}
		if len(waiting) > 0 {
			return Resolved{}, fmt.Errorf("%s runs %s, and %s from its old machine has not rejoined; each agent must name itself (tincan rejoin --name <agent>): %w",
				n.Name, agents[0].Name, strings.Join(agentNames(waiting), ", "), ErrAgentAmbiguous)
		}
		return d.resolved(ctx, n, agents[0])
	}
	return Resolved{}, fmt.Errorf("%s runs %s: %w", n.Name, strings.Join(agentNames(agents), ", "), ErrAgentAmbiguous)
}

// resolveServiceRole uses only tags returned by WhoIs, never the machine name
// or claimed header. A claim may narrow the grant to its configured name; it
// cannot select among conflicting grants or create a missing logical agent.
func (d *Directory) resolveServiceRole(ctx context.Context, n Node, claimed string) (Resolved, bool, error) {
	var name string
	for _, tag := range n.Tags {
		target, ok := d.cfg.ServiceRoles[tag]
		if !ok {
			continue
		}
		if name != "" && name != target {
			return Resolved{}, true, fmt.Errorf("%s has conflicting service roles: %w", n.Name, ErrAgentAmbiguous)
		}
		name = target
	}
	if name == "" {
		return Resolved{}, false, nil
	}
	if n.ID == "" || strings.HasPrefix(n.ID, VirtualPrefix) {
		return Resolved{}, true, fmt.Errorf("service role requires a tailnet StableID: %w", ErrNotJoined)
	}
	if claimed != "" && claimed != name {
		return Resolved{}, true, fmt.Errorf("service role is not %q: %w", claimed, ErrNotJoined)
	}
	_, found, err := d.store.AgentByName(ctx, name)
	if err != nil {
		return Resolved{}, true, err
	}
	if !found {
		return Resolved{}, true, fmt.Errorf("service role agent %q is not enrolled: %w", name, ErrNotJoined)
	}
	// Deliberately bypass resolved and readmit: there is no login recording,
	// enrollment, virtual binding, or persisted node replacement here.
	return Resolved{Name: name, ServiceRole: true}, true, nil
}

// resolved returns a, which is bound to n. An agent joined before logins
// were recorded gets n's login now, so that a later rebuild of its machine
// can be re-admitted with the login check (see readmit).
func (d *Directory) resolved(ctx context.Context, n Node, a Agent) (Resolved, error) {
	if a.NodeUser == "" && n.User != "" && len(n.Tags) == 0 {
		if err := d.recordLogin(ctx, n, a.Name); err != nil {
			return Resolved{}, err
		}
	}
	return Resolved{Name: a.Name}, nil
}

// recordLogin stores n's login on agent name, provided it is still bound to
// n with no login recorded.
func (d *Directory) recordLogin(ctx context.Context, n Node, name string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	a, found, err := d.store.AgentByName(ctx, name)
	if err != nil || !found || a.NodeID != n.ID || a.NodeUser != "" {
		return err
	}
	a.NodeUser = n.User
	return d.store.PutAgent(ctx, a)
}

// agentNames returns the names of agents, in order.
func agentNames(agents []Agent) []string {
	names := make([]string, len(agents))
	for i, a := range agents {
		names[i] = a.Name
	}
	return names
}

// Agent returns a joined agent by name.
func (d *Directory) Agent(ctx context.Context, name string) (Agent, bool, error) {
	return d.store.AgentByName(ctx, name)
}

// Has reports whether name is a joined agent.
func (d *Directory) Has(ctx context.Context, name string) (bool, error) {
	_, ok, err := d.store.AgentByName(ctx, name)
	return ok, err
}

// Invite creates a one-time code that joins the next machine to use it as
// name. Only admin devices may invite.
func (d *Directory) Invite(ctx context.Context, remoteAddr, name string) (string, error) {
	return d.InviteKind(ctx, remoteAddr, name, "")
}

// InviteKind is Invite that also records the agent's kind, applied when the
// code is used. An empty kind leaves the agent's kind as it was.
func (d *Directory) InviteKind(ctx context.Context, remoteAddr, name, kind string) (string, error) {
	if err := d.requireAdmin(ctx, remoteAddr); err != nil {
		return "", err
	}
	if !nameRE.MatchString(name) {
		return "", fmt.Errorf("agent name %q must be 1-32 lowercase letters, digits, or dashes", name)
	}
	if err := checkKind(kind); err != nil {
		return "", err
	}
	code, err := NewCode()
	if err != nil {
		return "", err
	}
	// Persist only the digest; the raw code is returned once to the admin and
	// never stored.
	inv := Invite{Code: hashInviteCode(d.invitePepper, code), Name: name, Kind: kind, Expires: d.cfg.Now().Add(InviteTTL)}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.store.PutInvite(ctx, inv); err != nil {
		return "", err
	}
	return code, nil
}

// EnrollNode is an owner-local enrollment with independently resolved identity.
// It never issues an invitation, changes an existing binding, or grants admin.
func (d *Directory) EnrollNode(ctx context.Context, remoteAddr, name, kind, stableID, ip, nodeName string) (Agent, bool, error) {
	if remoteAddr != LocalAdmin {
		return Agent{}, false, ErrNotAdmin
	}
	if kind == "" || checkKind(kind) != nil {
		return Agent{}, false, errors.New("invalid enrollment identity metadata")
	}
	n, err := d.enrollmentNode(ctx, name, stableID, ip, nodeName)
	if err != nil {
		return Agent{}, false, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.cfg.Now()
	return d.store.CreateAgent(ctx, Agent{Name: name, Kind: kind, NodeID: n.ID, NodeName: n.Name, NodeUser: n.User, JoinedAt: now}, now)
}

// RebindNode replaces one existing binding only when expectedOld still matches.
// It creates no invitation and leaves agent metadata and work intact.
func (d *Directory) RebindNode(ctx context.Context, remoteAddr, name, expectedOld, stableID, ip, nodeName string) (Agent, error) {
	if remoteAddr != LocalAdmin {
		return Agent{}, ErrNotAdmin
	}
	if !regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`).MatchString(expectedOld) || expectedOld == stableID {
		return Agent{}, errors.New("rebind requires a distinct expected old node")
	}
	n, err := d.enrollmentNode(ctx, name, stableID, ip, nodeName)
	if err != nil {
		return Agent{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.store.ReplaceAgentNode(ctx, name, expectedOld, n, d.cfg.Now())
}

func (d *Directory) enrollmentNode(ctx context.Context, name, stableID, ip, nodeName string) (Node, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Zone() != "" || addr.Is4In6() || (!netip.MustParsePrefix("100.64.0.0/10").Contains(addr) && !netip.MustParsePrefix("fd7a:115c:a1e0::/48").Contains(addr)) {
		return Node{}, errors.New("enrollment requires a literal Tailscale IP")
	}
	if !ValidName(name) || !regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`).MatchString(stableID) || !regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`).MatchString(nodeName) {
		return Node{}, errors.New("invalid enrollment identity metadata")
	}
	n, err := d.who.WhoIs(ctx, net.JoinHostPort(addr.String(), "1"))
	if err != nil {
		return Node{}, fmt.Errorf("enrollment whois: %w", err)
	}
	if n.ID != stableID || n.Name != nodeName {
		return Node{}, errors.New("enrollment identity mismatch")
	}
	status, ok := d.who.(NodeStatus)
	if !ok {
		return Node{}, errors.New("enrollment online metadata unavailable")
	}
	online, found, err := status.NodeOnline(ctx, n.ID)
	if err != nil {
		return Node{}, fmt.Errorf("enrollment status: %w", err)
	}
	if !found || !online {
		return Node{}, errors.New("enrollment node is missing or offline")
	}
	return n, nil
}

// Join binds the node behind remoteAddr to the invite's name. A node that
// already carries agents gains another name alongside them. Re-inviting an
// existing name moves it (and its kind, unless the invite names a new one) to
// the new machine; other agents on the old machine stay.
func (d *Directory) Join(ctx context.Context, remoteAddr, code string) (string, error) {
	n, err := d.who.WhoIs(ctx, remoteAddr)
	if err != nil {
		return "", err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	// Look up by digest: the store never sees the raw code.
	inv, ok, err := d.store.TakeInvite(ctx, hashInviteCode(d.invitePepper, code))
	if err != nil {
		return "", err
	}
	if !ok || d.cfg.Now().After(inv.Expires) {
		return "", ErrBadInvite
	}
	prev, _, err := d.Agent(ctx, inv.Name)
	if err != nil {
		return "", err
	}
	kind := prev.Kind
	if inv.Kind != "" {
		kind = inv.Kind
	}
	a := Agent{Name: inv.Name, NodeID: n.ID, NodeName: n.Name, NodeUser: n.User, JoinedAt: d.cfg.Now(), Kind: kind}
	if err := d.store.PutAgent(ctx, a); err != nil {
		return "", err
	}
	return a.Name, nil
}

// Remove unbinds an agent. The relay cancels its queued requests.
func (d *Directory) Remove(ctx context.Context, remoteAddr, name string) error {
	if err := d.requireAdmin(ctx, remoteAddr); err != nil {
		return err
	}
	ok, err := d.store.DeleteAgent(ctx, name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%s: %w", name, ErrUnknownAgent)
	}
	return nil
}

// SetKind records an agent's runtime kind ("" clears it). Only admin devices
// may set it.
func (d *Directory) SetKind(ctx context.Context, remoteAddr, name, kind string) error {
	if err := d.requireAdmin(ctx, remoteAddr); err != nil {
		return err
	}
	if err := checkKind(kind); err != nil {
		return err
	}
	// Join rewrites the whole agent row, so a kind set while it runs would
	// be lost.
	d.mu.Lock()
	defer d.mu.Unlock()
	ok, err := d.store.SetAgentKind(ctx, name, kind)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%s: %w", name, ErrUnknownAgent)
	}
	return nil
}

// SetGoodAt records the owner's line saying what an agent is good at (""
// clears it) and returns the line as stored. Only admin devices may set it.
func (d *Directory) SetGoodAt(ctx context.Context, remoteAddr, name, line string) (string, error) {
	if err := d.requireAdmin(ctx, remoteAddr); err != nil {
		return "", err
	}
	line, err := checkGoodAt(line)
	if err != nil {
		return "", err
	}
	// Serialize with Join, as SetKind does.
	d.mu.Lock()
	defer d.mu.Unlock()
	ok, err := d.store.SetAgentGoodAt(ctx, name, line)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("%s: %w", name, ErrUnknownAgent)
	}
	return line, nil
}

// Agents lists joined agents.
func (d *Directory) Agents(ctx context.Context) ([]Agent, error) {
	return d.store.Agents(ctx)
}

// IsAdmin reports whether remoteAddr may run admin commands.
func (d *Directory) IsAdmin(ctx context.Context, remoteAddr string) bool {
	return d.requireAdmin(ctx, remoteAddr) == nil
}

func (d *Directory) requireAdmin(ctx context.Context, remoteAddr string) error {
	if remoteAddr == LocalAdmin {
		return nil
	}
	n, err := d.who.WhoIs(ctx, remoteAddr)
	if err != nil {
		return err
	}
	// Admin = named in --admin, untagged (tagged nodes are services, never
	// people), and, when --admin-login is set, owned by a listed login.
	if !slices.Contains(d.cfg.Admins, n.Name) {
		return fmt.Errorf("%s: %w", n.Name, ErrNotAdmin)
	}
	if len(n.Tags) > 0 {
		return fmt.Errorf("%s is tagged %s: %w", n.Name, strings.Join(n.Tags, ","), ErrNotAdmin)
	}
	if len(d.cfg.AdminLogins) > 0 && !slices.Contains(d.cfg.AdminLogins, n.User) {
		return fmt.Errorf("%s is owned by %q: %w", n.Name, n.User, ErrNotAdmin)
	}
	return nil
}

// codeAlphabet drops 0, 1, I, and O so codes read cleanly aloud.
const codeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// NewCode returns a random one-time code shaped XXXX-XXXX.
func NewCode() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, 0, 9)
	for i, c := range b {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, codeAlphabet[int(c)%len(codeAlphabet)])
	}
	return string(out), nil
}
