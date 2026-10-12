package gateway

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	webhookMaxBody       = 256 << 10
	webhookTimeout       = 10 * time.Second
	verificationLimit    = 4 << 10
	callbackURLMaxSize   = 8192
	webhookMaxRetryAfter = time.Hour // same bound as Store.FinishEventDelivery
)

// WebhookSender verifies a callback and makes one signed delivery attempt.
// Durable retries, subscription authorization, expiry and the short lifetime
// of a previous signing secret belong to the subscription/outbox store.
type WebhookSender interface {
	Verify(ctx context.Context, subscriptionID, callbackURL, secret string) error
	Send(ctx context.Context, subscriptionID, callbackURL, secret, previousSecret, eventID string, body []byte) (status int, retryAfter time.Duration, err error)
}

// CallbackEndpointError provides the categorized reason used by MCP's
// CallbackEndpointError (-32015). Error text never includes a callback URL,
// challenge, signing secret or event body.
type CallbackEndpointError struct {
	Reason string
	err    error
}

func (e *CallbackEndpointError) Error() string { return "callback endpoint: " + e.Reason }
func (e *CallbackEndpointError) Unwrap() error { return e.err }

type webhookResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type webhookSender struct {
	resolver webhookResolver
	dial     func(context.Context, string, string) (net.Conn, error)
	now      func() time.Time
	random   io.Reader
	// Only package-local tests replace trust roots. Production never permits
	// skipped certificate verification or a caller-supplied HTTP transport.
	tlsConfig *tls.Config
}

// NewWebhookSender returns the HTTPS-only sender with no proxy or redirects.
// A new transport is used for every attempt so pooled connections cannot
// bypass destination validation after DNS rebinding.
func NewWebhookSender() WebhookSender {
	dialer := &net.Dialer{Timeout: webhookTimeout}
	return &webhookSender{
		resolver: net.DefaultResolver,
		dial:     dialer.DialContext,
		now:      time.Now,
		random:   rand.Reader,
	}
}

// ValidateWebhookSecret requires the MCP Events whsec_ base64 signing key.
func ValidateWebhookSecret(secret string) error {
	_, err := decodeWebhookSecret(secret)
	return err
}

func decodeWebhookSecret(secret string) ([]byte, error) {
	encoded, ok := strings.CutPrefix(secret, "whsec_")
	if !ok || len(encoded) > 88 || strings.IndexFunc(encoded, unicode.IsSpace) >= 0 {
		return nil, callbackError("invalid_secret", nil)
	}
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		key, err = base64.RawStdEncoding.Strict().DecodeString(encoded)
	}
	if err != nil || len(key) < 24 || len(key) > 64 {
		return nil, callbackError("invalid_secret", nil)
	}
	return key, nil
}

// ValidateCallbackURL validates syntax and IP literals. Hostnames are resolved
// and all answers checked at connection time, including verification requests.
func ValidateCallbackURL(raw string) error {
	_, err := parseCallbackURL(raw)
	return err
}

func parseCallbackURL(raw string) (*url.URL, error) {
	if len(raw) == 0 || len(raw) > callbackURLMaxSize || strings.ContainsAny(raw, "#\\") || strings.IndexFunc(raw, unicode.IsSpace) >= 0 {
		return nil, callbackError("invalid_url", nil)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" || u.User != nil || u.Fragment != "" {
		return nil, callbackError("invalid_url", nil)
	}
	host := u.Hostname()
	if host == "" || strings.Contains(host, "%") || strings.HasSuffix(u.Host, ":") {
		return nil, callbackError("invalid_url", nil)
	}
	if port := u.Port(); port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return nil, callbackError("invalid_url", nil)
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if !publicWebhookIP(ip) {
			return nil, callbackError("blocked_address", nil)
		}
	} else if strings.HasPrefix(u.Host, "[") || strings.ContainsAny(host, ":[]") {
		return nil, callbackError("invalid_url", nil)
	}
	return u, nil
}

// Conservatively reject special-purpose ranges, including documentation,
// benchmarking, shared address space and IPv6 transition mechanisms. Checking
// IsGlobalUnicast alone would allow many of these non-public destinations.
var webhookDeniedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

func publicWebhookIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, prefix := range webhookDeniedPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

func (s *webhookSender) dialValidated(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, callbackError("invalid_url", err)
	}
	var addresses []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{ip}
	} else {
		addresses, err = s.resolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(addresses) == 0 {
			return nil, callbackError("dns_failed", err)
		}
	}
	// Fail the whole resolution when any answer is non-public, rather than
	// choosing only a public answer from a malicious mixed DNS response.
	for _, ip := range addresses {
		if !publicWebhookIP(ip) {
			return nil, callbackError("blocked_address", nil)
		}
	}
	for _, ip := range addresses {
		conn, dialErr := s.dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		if dialErr == nil {
			return conn, nil
		}
		err = dialErr
		if ctx.Err() != nil {
			break
		}
	}
	return nil, callbackError("delivery_failed", err)
}

func (s *webhookSender) Verify(ctx context.Context, subscriptionID, callbackURL, secret string) error {
	// Each call creates an independent challenge; no challenge can activate
	// another call, and a response after this deadline cannot succeed.
	ctx, cancel := context.WithTimeout(ctx, webhookTimeout)
	defer cancel()
	random := make([]byte, 48)
	if _, err := io.ReadFull(s.random, random); err != nil {
		return callbackError("challenge_failed", err)
	}
	challenge := base64.RawURLEncoding.EncodeToString(random[:32])
	id := "msg_verification_" + base64.RawURLEncoding.EncodeToString(random[32:])
	body, err := json.Marshal(struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
	}{"verification", challenge})
	if err != nil {
		return callbackError("challenge_failed", err)
	}
	resp, err := s.post(ctx, subscriptionID, callbackURL, secret, "", id, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || resp.ContentLength > verificationLimit {
		return callbackError("challenge_failed", nil)
	}
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, verificationLimit+1))
	if err != nil {
		return callbackError("challenge_failed", err)
	}
	if len(responseBody) > verificationLimit {
		return callbackError("challenge_failed", nil)
	}
	var reply struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(responseBody, &reply); err != nil || subtle.ConstantTimeCompare([]byte(reply.Challenge), []byte(challenge)) != 1 {
		return callbackError("challenge_failed", nil)
	}
	if err := ctx.Err(); err != nil {
		return callbackError("timeout", err)
	}
	return nil
}

func (s *webhookSender) Send(ctx context.Context, subscriptionID, callbackURL, secret, previousSecret, eventID string, body []byte) (int, time.Duration, error) {
	if len(body) > webhookMaxBody {
		return 0, 0, callbackError("payload_too_large", nil)
	}
	var envelope struct {
		EventID string `json:"eventId"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil || envelope.EventID != eventID {
		return 0, 0, callbackError("invalid_payload", nil)
	}
	ctx, cancel := context.WithTimeout(ctx, webhookTimeout)
	defer cancel()
	resp, err := s.post(ctx, subscriptionID, callbackURL, secret, previousSecret, eventID, body)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	// No retries occur here. The durable outbox records the received status;
	// 410 and 413 must be final, while transient failures get bounded backoff.
	var retryAfter time.Duration
	if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode >= 500 && resp.StatusCode < 600) {
		if values := resp.Header.Values("Retry-After"); len(values) == 1 {
			retryAfter = webhookRetryAfter(values[0], s.now())
		}
	}
	return resp.StatusCode, retryAfter, nil
}

// Retry-After is either a non-negative integer number of seconds or an
// HTTP-date. Invalid/past values fall back to the store's exponential delay.
// Bound before converting seconds to Duration so a large value cannot wrap.
func webhookRetryAfter(value string, now time.Time) time.Duration {
	value = strings.Trim(value, " \t")
	if seconds, err := strconv.ParseUint(value, 10, 64); err == nil {
		return time.Duration(min(seconds, uint64(webhookMaxRetryAfter/time.Second))) * time.Second
	}
	if date, err := http.ParseTime(value); err == nil && date.After(now) {
		return min(date.Sub(now), webhookMaxRetryAfter)
	}
	return 0
}

func validWebhookHeader(value string) bool {
	if len(value) == 0 || len(value) > 512 {
		return false
	}
	for _, b := range []byte(value) {
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}

func (s *webhookSender) post(ctx context.Context, subscriptionID, callbackURL, secret, previousSecret, id string, body []byte) (*http.Response, error) {
	u, err := parseCallbackURL(callbackURL)
	if err != nil {
		return nil, err
	}
	if !validWebhookHeader(subscriptionID) || !validWebhookHeader(id) {
		return nil, callbackError("invalid_metadata", nil)
	}
	key, err := decodeWebhookSecret(secret)
	if err != nil {
		return nil, err
	}
	timestamp := strconv.FormatInt(s.now().Unix(), 10)
	signature := signWebhook(key, id, timestamp, body)
	if previousSecret != "" {
		previousKey, err := decodeWebhookSecret(previousSecret)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(key, previousKey) {
			signature += " " + signWebhook(previousKey, id, timestamp, body)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, callbackError("invalid_url", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("webhook-id", id)
	req.Header.Set("webhook-timestamp", timestamp)
	req.Header.Set("webhook-signature", signature)
	req.Header.Set("X-MCP-Subscription-Id", subscriptionID)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if s.tlsConfig != nil {
		tlsConfig = s.tlsConfig.Clone()
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           s.dialValidated,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   webhookTimeout,
		ResponseHeaderTimeout: webhookTimeout,
		DisableKeepAlives:     true,
		DisableCompression:    true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   webhookTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, callbackError("delivery_failed", err)
	}
	return resp, nil
}

func signWebhook(key []byte, id, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = fmt.Fprintf(mac, "%s.%s.", id, timestamp)
	_, _ = mac.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func callbackError(reason string, err error) *CallbackEndpointError {
	var endpointErr *CallbackEndpointError
	if errors.As(err, &endpointErr) {
		return endpointErr
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		reason = "timeout"
	}
	return &CallbackEndpointError{Reason: reason, err: err}
}
