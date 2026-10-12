// Package gateway lets ChatGPT, which runs in OpenAI's cloud and cannot reach
// the tailnet, join as an agent. It serves the Agent Tincan MCP tools over
// Streamable HTTP on a public Funnel hostname, behind the smallest OAuth 2.1
// authorization server ChatGPT's connectors accept: one owner, PKCE, and a
// login page that takes a one-time code Matt mints with `tincan connect`.
//
// Only the MCP endpoint and the OAuth endpoints are served. The relay's agent
// API is never reachable from the public side.
package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/mvanhorn/agent-tincan/internal/identity"
)

const oauthSchema = `
CREATE TABLE IF NOT EXISTS gw_clients (
  client_id     TEXT PRIMARY KEY,
  redirect_uris TEXT NOT NULL,
  created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS gw_codes (
  hash       TEXT PRIMARY KEY,
  kind       TEXT NOT NULL,          -- login | auth
  agent      TEXT NOT NULL,
  client_id  TEXT NOT NULL DEFAULT '',
  redirect   TEXT NOT NULL DEFAULT '',
  challenge  TEXT NOT NULL DEFAULT '',
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS gw_tokens (
  hash       TEXT PRIMARY KEY,
  kind       TEXT NOT NULL,          -- access | refresh
  agent      TEXT NOT NULL,
  client_id  TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS gw_grants (
  id         TEXT PRIMARY KEY,
  agent      TEXT NOT NULL,
  client_id  TEXT NOT NULL DEFAULT '',
  scope      TEXT NOT NULL,
  resource   TEXT NOT NULL DEFAULT '',
  revoked    INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL
);
`

// Lifetimes.
const (
	LoginCodeTTL = 10 * time.Minute
	authCodeTTL  = time.Minute
	accessTTL    = time.Hour
	refreshTTL   = 30 * 24 * time.Hour
)

var errInvalid = errors.New("invalid or expired")

// Registration is public and unauthenticated, so the client table is bounded:
// clients older than staleClientAge that never got a token are pruned, and
// registration is refused while maxClients remain.
const (
	maxClients     = 1000
	staleClientAge = 24 * time.Hour
)

// ErrTooManyClients means registration is full until stale clients age out.
var ErrTooManyClients = errors.New("too many registered clients")

// Row kinds in gw_codes and gw_tokens.
const (
	kindLogin   = "login"
	kindAuth    = "auth"
	kindAccess  = "access"
	kindRefresh = "refresh"
)

// codeRecord is what a consumed one-time code was bound to.
type codeRecord struct {
	Agent, ClientID, Redirect, Challenge, GrantID string
}

const (
	ScopeFull   = "full"
	ScopeEvents = "events"
)

// Principal identifies one OAuth connection. Its ID survives token rotation;
// the mailbox is independent of the mailbox's backend node binding.
type Principal struct {
	ID, Agent, ClientID, Scope, Resource string
}

// OAuth stores clients, one-time codes, and tokens. Only hashes of codes and
// tokens are stored.
type OAuth struct {
	db         *sql.DB
	now        func() time.Time
	mu         sync.RWMutex
	resource   string
	eventsOnly map[string]bool
}

// NewOAuth creates the OAuth tables in db.
func NewOAuth(db *sql.DB, now func() time.Time) (*OAuth, error) {
	if now == nil {
		now = time.Now
	}
	if _, err := db.Exec(oauthSchema); err != nil {
		return nil, err
	}
	// Older gateway databases have no grant reference. Such rows retain full
	// scope and are rejected for a mailbox after an events-only migration.
	for _, table := range []string{"gw_codes", "gw_tokens"} {
		rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
		if err != nil {
			return nil, err
		}
		found := false
		for rows.Next() {
			var n, notNull, pk int
			var name, typ string
			var def any
			if err := rows.Scan(&n, &name, &typ, &notNull, &def, &pk); err != nil {
				rows.Close()
				return nil, err
			}
			found = found || name == "grant_id"
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		if !found {
			if _, err := db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN grant_id TEXT NOT NULL DEFAULT ''`); err != nil {
				return nil, err
			}
		}
	}
	return &OAuth{db: db, now: now}, nil
}

// ConfigureEvents sets an explicit mailbox policy. It does not alter bindings
// or mint credentials. A configured mailbox cannot use an older full grant.
func (o *OAuth) ConfigureEvents(resource string, mailboxes []string) error {
	u, err := url.Parse(resource)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/mcp" {
		return fmt.Errorf("events resource must be the gateway HTTPS /mcp URL")
	}
	names := make(map[string]bool, len(mailboxes))
	for _, name := range mailboxes {
		if name == "" {
			return fmt.Errorf("events mailbox must not be empty")
		}
		names[name] = true
	}
	o.mu.Lock()
	o.resource, o.eventsOnly = resource, names
	o.mu.Unlock()
	return nil
}

func (o *OAuth) EventsOnly(agent string) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.eventsOnly[agent]
}

func (o *OAuth) allowed(p Principal, resource string) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.eventsOnly[p.Agent] && p.Scope != ScopeEvents {
		return false
	}
	if p.Scope == ScopeEvents {
		return o.eventsOnly[p.Agent] && p.ID != "" && o.resource != "" && p.Resource == o.resource && resource == o.resource
	}
	return p.Scope == ScopeFull
}

func (o *OAuth) checkPolicy(ctx context.Context, q queryRower, p Principal, resource string) error {
	if !o.allowed(p, resource) {
		return errInvalid
	}
	if p.Scope == ScopeEvents {
		// Removal must stop events even if a later token-revocation operation
		// fails. Connecting an event grant never creates this mailbox row.
		var n int
		if err := q.QueryRowContext(ctx, `SELECT count(*) FROM agents WHERE name = ? AND node_id <> ''`, p.Agent).Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			return errInvalid
		}
	}
	return nil
}

func secret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// MintLoginCode creates the one-time code Matt types on the login page.
func (o *OAuth) MintLoginCode(ctx context.Context, agent string) (string, error) {
	code := shortCode()
	p := Principal{ID: secret(), Agent: agent, Scope: ScopeFull}
	o.mu.RLock()
	if o.eventsOnly[agent] {
		p.Scope, p.Resource = ScopeEvents, o.resource
	}
	o.mu.RUnlock()
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO gw_grants(id, agent, scope, resource, expires_at) VALUES (?, ?, ?, ?, ?)`, p.ID, agent, p.Scope, p.Resource, o.now().Add(refreshTTL).UnixMilli()); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO gw_codes(hash, kind, agent, expires_at, grant_id) VALUES (?, ?, ?, ?, ?)`, hash(code), kindLogin, agent, o.now().Add(LoginCodeTTL).UnixMilli(), p.ID); err != nil {
		return "", err
	}
	return code, tx.Commit()
}

// RegisterClient implements dynamic client registration. It first sweeps
// expired codes and tokens and prunes stale token-less clients, then refuses
// with ErrTooManyClients if the table is still at the cap.
func (o *OAuth) RegisterClient(ctx context.Context, redirectURIs string) (string, error) {
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	now := o.now()
	for _, q := range []struct {
		sql string
		arg int64
	}{
		{`DELETE FROM gw_codes WHERE expires_at <= ?`, now.UnixMilli()},
		{`DELETE FROM gw_tokens WHERE expires_at <= ?`, now.UnixMilli()},
		{`DELETE FROM gw_grants WHERE expires_at <= ?`, now.UnixMilli()},
		{`DELETE FROM gw_clients WHERE created_at < ? AND client_id NOT IN (SELECT client_id FROM gw_tokens)`, now.Add(-staleClientAge).UnixMilli()},
	} {
		if _, err := tx.ExecContext(ctx, q.sql, q.arg); err != nil {
			return "", err
		}
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM gw_clients`).Scan(&n); err != nil {
		return "", err
	}
	if n >= maxClients {
		if err := tx.Commit(); err != nil {
			return "", err
		}
		return "", ErrTooManyClients
	}
	id := "tincan-" + secret()[:16]
	if _, err := tx.ExecContext(ctx, `INSERT INTO gw_clients(client_id, redirect_uris, created_at) VALUES (?, ?, ?)`, id, redirectURIs, now.UnixMilli()); err != nil {
		return "", err
	}
	return id, tx.Commit()
}

// ClientRedirects returns a registered client's redirect URIs (newline separated).
func (o *OAuth) ClientRedirects(ctx context.Context, clientID string) (string, error) {
	var uris string
	err := o.db.QueryRowContext(ctx, `SELECT redirect_uris FROM gw_clients WHERE client_id = ?`, clientID).Scan(&uris)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errInvalid
	}
	return uris, err
}

// takeCode consumes a one-time code of the given kind.
func (o *OAuth) takeCode(ctx context.Context, tx *sql.Tx, code, kind string) (codeRecord, error) {
	var r codeRecord
	var exp int64
	err := tx.QueryRowContext(ctx, `DELETE FROM gw_codes WHERE hash = ? AND kind = ? RETURNING agent, client_id, redirect, challenge, expires_at, grant_id`,
		hash(code), kind).Scan(&r.Agent, &r.ClientID, &r.Redirect, &r.Challenge, &exp, &r.GrantID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && o.now().UnixMilli() >= exp) {
		return codeRecord{}, errInvalid
	}
	return r, err
}

// ExchangeLogin trades a login code for an authorization code bound to the
// client, redirect URI, and PKCE challenge.
func (o *OAuth) ExchangeLogin(ctx context.Context, loginCode, clientID, redirect, challenge string) (string, error) {
	return o.ExchangeLoginResource(ctx, loginCode, clientID, redirect, challenge, "")
}

// ExchangeLoginResource binds an event connection to its exact MCP audience.
func (o *OAuth) ExchangeLoginResource(ctx context.Context, loginCode, clientID, redirect, challenge, resource string) (string, error) {
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	login, err := o.takeCode(ctx, tx, loginCode, kindLogin)
	if err != nil {
		return "", err
	}
	p, err := o.codePrincipal(ctx, tx, login)
	if err != nil {
		return "", err
	}
	if err := o.checkPolicy(ctx, tx, p, resource); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE gw_grants SET client_id = ? WHERE id = ?`, clientID, p.ID); err != nil {
		return "", err
	}
	code := secret()
	if _, err = tx.ExecContext(ctx, `INSERT INTO gw_codes(hash, kind, agent, client_id, redirect, challenge, expires_at, grant_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		hash(code), kindAuth, login.Agent, clientID, redirect, challenge, o.now().Add(authCodeTTL).UnixMilli(), p.ID); err != nil {
		return "", err
	}
	return code, tx.Commit()
}

func (o *OAuth) codePrincipal(ctx context.Context, tx *sql.Tx, code codeRecord) (Principal, error) {
	if code.GrantID != "" {
		return o.grant(ctx, tx, code.GrantID)
	}
	// Upgrade an old code to a full connection; policy can still reject it.
	p := Principal{ID: secret(), Agent: code.Agent, ClientID: code.ClientID, Scope: ScopeFull}
	_, err := tx.ExecContext(ctx, `INSERT INTO gw_grants(id, agent, client_id, scope, expires_at) VALUES (?, ?, ?, ?, ?)`, p.ID, p.Agent, p.ClientID, p.Scope, o.now().Add(refreshTTL).UnixMilli())
	return p, err
}

type queryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (o *OAuth) grant(ctx context.Context, q queryRower, id string) (Principal, error) {
	p := Principal{ID: id}
	var exp int64
	var revoked int
	err := q.QueryRowContext(ctx, `SELECT agent, client_id, scope, resource, revoked, expires_at FROM gw_grants WHERE id = ?`, id).Scan(&p.Agent, &p.ClientID, &p.Scope, &p.Resource, &revoked, &exp)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (revoked != 0 || o.now().UnixMilli() >= exp)) {
		return Principal{}, errInvalid
	}
	return p, err
}

// Tokens is a token response.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope,omitempty"`
}

// ExchangeAuthCode verifies PKCE and issues tokens.
func (o *OAuth) ExchangeAuthCode(ctx context.Context, code, clientID, redirect, verifier string) (Tokens, error) {
	return o.ExchangeAuthCodeResource(ctx, code, clientID, redirect, verifier, "")
}

func (o *OAuth) ExchangeAuthCodeResource(ctx context.Context, code, clientID, redirect, verifier, resource string) (Tokens, error) {
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return Tokens{}, err
	}
	defer tx.Rollback()
	auth, err := o.takeCode(ctx, tx, code, kindAuth)
	if err != nil {
		return Tokens{}, err
	}
	if auth.ClientID != clientID || auth.Redirect != redirect || pkce(verifier) != auth.Challenge {
		return Tokens{}, errInvalid
	}
	p, err := o.codePrincipal(ctx, tx, auth)
	if err != nil {
		return Tokens{}, err
	}
	if p.ClientID != clientID {
		return Tokens{}, errInvalid
	}
	if err := o.checkPolicy(ctx, tx, p, resource); err != nil {
		return Tokens{}, err
	}
	t, err := o.issue(ctx, tx, p)
	if err != nil {
		return Tokens{}, err
	}
	return t, tx.Commit()
}

// Refresh rotates a refresh token.
func (o *OAuth) Refresh(ctx context.Context, refresh, clientID string) (Tokens, error) {
	return o.RefreshResource(ctx, refresh, clientID, "")
}

func (o *OAuth) RefreshResource(ctx context.Context, refresh, clientID, resource string) (Tokens, error) {
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return Tokens{}, err
	}
	defer tx.Rollback()
	var agent, cid, grantID string
	var exp int64
	err = tx.QueryRowContext(ctx, `DELETE FROM gw_tokens WHERE hash = ? AND kind = ? RETURNING agent, client_id, expires_at, grant_id`, hash(refresh), kindRefresh).Scan(&agent, &cid, &exp, &grantID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (o.now().UnixMilli() >= exp || cid != clientID)) {
		return Tokens{}, errInvalid
	}
	if err != nil {
		return Tokens{}, err
	}
	p, err := o.codePrincipal(ctx, tx, codeRecord{Agent: agent, ClientID: cid, GrantID: grantID})
	if err != nil {
		return Tokens{}, err
	}
	if p.ClientID != clientID {
		return Tokens{}, errInvalid
	}
	if err := o.checkPolicy(ctx, tx, p, resource); err != nil {
		return Tokens{}, err
	}
	// Event rotation invalidates the old access token too. Full grants preserve
	// the old access lifetime. Both token inserts and consumption commit together.
	if p.Scope == ScopeEvents {
		if _, err := tx.ExecContext(ctx, `DELETE FROM gw_tokens WHERE grant_id = ?`, p.ID); err != nil {
			return Tokens{}, err
		}
	}
	t, err := o.issue(ctx, tx, p)
	if err != nil {
		return Tokens{}, err
	}
	return t, tx.Commit()
}

func (o *OAuth) issue(ctx context.Context, tx *sql.Tx, p Principal) (Tokens, error) {
	t := Tokens{AccessToken: secret(), TokenType: "Bearer", ExpiresIn: int(accessTTL.Seconds()), RefreshToken: secret()}
	now := o.now()
	if _, err := tx.ExecContext(ctx, `UPDATE gw_grants SET expires_at = ? WHERE id = ?`, now.Add(refreshTTL).UnixMilli(), p.ID); err != nil {
		return Tokens{}, err
	}
	if p.Scope == ScopeEvents {
		t.Scope = ScopeEvents
	}
	for _, row := range []struct {
		tok, kind string
		ttl       time.Duration
	}{{t.AccessToken, kindAccess, accessTTL}, {t.RefreshToken, kindRefresh, refreshTTL}} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO gw_tokens(hash, kind, agent, client_id, expires_at, grant_id) VALUES (?, ?, ?, ?, ?, ?)`,
			hash(row.tok), row.kind, p.Agent, p.ClientID, now.Add(row.ttl).UnixMilli(), p.ID); err != nil {
			return Tokens{}, err
		}
	}
	return t, nil
}

// Validate returns the agent an access token belongs to.
func (o *OAuth) Validate(ctx context.Context, access string) (string, error) {
	p, err := o.ValidatePrincipal(ctx, access, "")
	return p.Agent, err
}

// ValidatePrincipal checks both the connection and today's mailbox policy.
func (o *OAuth) ValidatePrincipal(ctx context.Context, access, resource string) (Principal, error) {
	var agent, grantID string
	var exp int64
	err := o.db.QueryRowContext(ctx, `SELECT agent, expires_at, grant_id FROM gw_tokens WHERE hash = ? AND kind = ?`, hash(access), kindAccess).Scan(&agent, &exp, &grantID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && o.now().UnixMilli() >= exp) {
		return Principal{}, errInvalid
	}
	if err != nil {
		return Principal{}, err
	}
	p := Principal{Agent: agent, Scope: ScopeFull}
	if grantID != "" {
		p, err = o.grant(ctx, o.db, grantID)
	}
	if err != nil {
		return Principal{}, err
	}
	if err := o.checkPolicy(ctx, o.db, p, resource); err != nil {
		return Principal{}, err
	}
	return p, nil
}

// PrincipalActive is used before every delivery, independently of access-token
// expiration. The plugin keeps the grant live through refresh-token rotation.
func (o *OAuth) PrincipalActive(ctx context.Context, id string) (bool, error) {
	p, err := o.grant(ctx, o.db, id)
	if errors.Is(err, errInvalid) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if p.Scope != ScopeEvents {
		return false, nil
	}
	err = o.checkPolicy(ctx, o.db, p, p.Resource)
	if errors.Is(err, errInvalid) {
		return false, nil
	}
	return err == nil, err
}

// RevokePrincipal revokes one connection without changing other connections
// or the agent's node binding. The persistent flag also gates delivery.
func (o *OAuth) RevokePrincipal(ctx context.Context, id string) error {
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{`UPDATE gw_grants SET revoked = 1 WHERE id = ?`, `DELETE FROM gw_tokens WHERE grant_id = ?`, `DELETE FROM gw_codes WHERE grant_id = ?`} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RevokeAgent deletes every token and pending code for an agent.
// RevokeToken implements public-client token revocation for one connection.
// Unknown tokens and a different registered client are intentionally no-ops.
// It never changes the mailbox or its backend node binding.
func (o *OAuth) RevokeToken(ctx context.Context, token, clientID string) error {
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var grantID, cid, agent string
	err = tx.QueryRowContext(ctx, `SELECT grant_id,client_id,agent FROM gw_tokens WHERE hash=?`, hash(token)).Scan(&grantID, &cid, &agent)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if cid != clientID || clientID == "" {
		return nil
	}
	if grantID != "" {
		for _, q := range []string{`UPDATE gw_grants SET revoked=1 WHERE id=?`, `DELETE FROM gw_tokens WHERE grant_id=?`, `DELETE FROM gw_codes WHERE grant_id=?`} {
			if _, err = tx.ExecContext(ctx, q, grantID); err != nil {
				return err
			}
		}
	} else {
		if _, err = tx.ExecContext(ctx, `DELETE FROM gw_tokens WHERE agent=? AND client_id=? AND grant_id=''`, agent, cid); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RevokeAgent deletes every token and pending code for an agent.
func (o *OAuth) RevokeAgent(ctx context.Context, agent string) error {
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{`UPDATE gw_grants SET revoked = 1 WHERE agent = ?`, `DELETE FROM gw_tokens WHERE agent = ?`, `DELETE FROM gw_codes WHERE agent = ?`} {
		if _, err := tx.ExecContext(ctx, q, agent); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func pkce(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func shortCode() string {
	code, err := identity.NewCode()
	if err != nil {
		panic(err)
	}
	return code
}
