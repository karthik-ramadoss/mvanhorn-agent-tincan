package gateway

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type webhookTestResolver func(context.Context, string, string) ([]netip.Addr, error)

func (f webhookTestResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

func webhookTestSecret(b byte, size int) string {
	return "whsec_" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, size))
}

func webhookReason(t *testing.T, err error, want string) {
	t.Helper()
	var endpointError *CallbackEndpointError
	if !errors.As(err, &endpointError) || endpointError.Reason != want {
		t.Fatalf("got error %v; want CallbackEndpointError reason %q", err, want)
	}
}

// A private local TLS test server is reached only through a test-only dial
// hook. The production validation still sees a public DNS answer, and normal
// TLS certificate/hostname verification remains enabled.
func webhookTestSender(t *testing.T, handler http.HandlerFunc) (*webhookSender, string) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	cert := server.Certificate()
	if len(cert.DNSNames) == 0 {
		t.Fatal("TLS test certificate has no DNS names")
	}
	host := cert.DNSNames[0]
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	sender := NewWebhookSender().(*webhookSender)
	sender.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	sender.resolver = webhookTestResolver(func(_ context.Context, network, queriedHost string) ([]netip.Addr, error) {
		if network != "ip" || queriedHost != host {
			t.Errorf("resolver got %q %q; want ip %q", network, queriedHost, host)
		}
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	})
	dialer := &net.Dialer{}
	sender.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != net.JoinHostPort("93.184.216.34", port) {
			t.Errorf("dial received unvalidated address %q", address)
		}
		return dialer.DialContext(ctx, network, server.Listener.Addr().String())
	}
	return sender, "https://" + net.JoinHostPort(host, port) + "/callback"
}

func webhookExpectedSignature(secret, id, timestamp string, body []byte) string {
	key, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	mac := hmac.New(sha256.New, key)
	mac.Write(append([]byte(id+"."+timestamp+"."), body...))
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func TestWebhookStandardSignatureVector(t *testing.T) {
	// Reference computed independently with .NET HMACSHA256 over the exact
	// Standard Webhooks id.timestamp.body byte sequence.
	key := []byte("0123456789abcdef0123456789abcdef")
	body := []byte(`{ "eventId" : "evt_123", "data":{"status":"queued"} }`)
	want := "v1,J7SHH8eXmaiBmD9MePoFpTZy9jq7okR7fj6d/Oh5MkQ="
	if got := signWebhook(key, "evt_123", "1700000000", body); got != want {
		t.Fatalf("signature %q, want %q", got, want)
	}
}

func TestWebhookSecretValidation(t *testing.T) {
	for _, size := range []int{24, 32, 64} {
		if err := ValidateWebhookSecret(webhookTestSecret(1, size)); err != nil {
			t.Fatalf("valid %d-byte key: %v", size, err)
		}
	}
	for _, secret := range []string{
		"", "secret", "whsec_%%%", webhookTestSecret(1, 23), webhookTestSecret(1, 65),
		webhookTestSecret(1, 32) + "\n", "whsec_" + strings.Repeat("A", 10000),
	} {
		webhookReason(t, ValidateWebhookSecret(secret), "invalid_secret")
	}
	// Base64 padding is optional; URL-safe substitutions and whitespace are not.
	if err := ValidateWebhookSecret(strings.TrimRight(webhookTestSecret(1, 32), "=")); err != nil {
		t.Fatal(err)
	}
}

func TestWebhookCallbackURLValidation(t *testing.T) {
	for _, raw := range []string{
		"https://callback.example/path?a=b", "https://8.8.8.8/path", "https://[2606:4700:4700::1111]:8443/path",
		"https://callback.example/path%23part",
	} {
		if err := ValidateCallbackURL(raw); err != nil {
			t.Errorf("valid URL %q: %v", raw, err)
		}
	}
	for _, raw := range []string{
		"", "http://callback.example", "file:///etc/passwd", "https:callback.example", "https:///callback",
		"https://user:password@callback.example", "https://callback.example/path#fragment", "https://callback.example/path#",
		"https://callback.example:0/", "https://callback.example:65536/", "https://callback.example:invalid/", "https://callback.example:/",
		"https://callback.example\\@127.0.0.1/", "https://callback.example/\n", "https://[fe80::1%25eth0]/",
		"https://[not-ip]/", "https://" + strings.Repeat("a", callbackURLMaxSize),
	} {
		webhookReason(t, ValidateCallbackURL(raw), "invalid_url")
	}
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "169.254.169.254", "192.168.1.1", "100.64.0.1", "[::1]", "[::ffff:127.0.0.1]", "[2002:7f00:1::]"} {
		webhookReason(t, ValidateCallbackURL("https://"+ip+"/"), "blocked_address")
	}
}

func TestWebhookPublicAddressPolicy(t *testing.T) {
	for _, raw := range []string{
		"0.0.0.0", "0.1.2.3", "10.0.0.1", "100.64.0.1", "127.0.0.2", "169.254.169.254", "172.16.0.1",
		"192.0.0.1", "192.0.2.1", "192.88.99.1", "192.168.0.1", "198.18.0.1", "198.51.100.1", "203.0.113.1",
		"224.0.0.1", "240.0.0.1", "255.255.255.255", "::", "::1", "::ffff:10.1.2.3", "fc00::1", "fe80::1",
		"ff00::1", "64:ff9b::7f00:1", "100::1", "2001::1", "2001:2::1", "2001:db8::1", "2001:20::1",
		"2002:0808:0808::1", "3fff::1", "4000::1", "fe80::1%eth0",
	} {
		if publicWebhookIP(netip.MustParseAddr(raw)) {
			t.Errorf("non-public address accepted: %s", raw)
		}
	}
	for _, raw := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "::ffff:8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888"} {
		if !publicWebhookIP(netip.MustParseAddr(raw)) {
			t.Errorf("public address rejected: %s", raw)
		}
	}
}

func TestWebhookRejectsMixedDNSBeforeDial(t *testing.T) {
	for _, blocked := range []string{"10.0.0.1", "::1", "2001:db8::1"} {
		t.Run(blocked, func(t *testing.T) {
			sender := NewWebhookSender().(*webhookSender)
			sender.resolver = webhookTestResolver(func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr(blocked)}, nil
			})
			sender.dial = func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("mixed DNS resolution reached dial")
				return nil, nil
			}
			_, _, err := sender.Send(context.Background(), "sub_1", "https://callback.example", webhookTestSecret(1, 32), "", "evt_1", []byte(`{"eventId":"evt_1"}`))
			webhookReason(t, err, "blocked_address")
		})
	}
}

func TestWebhookRevalidatesDNSOnEveryAttempt(t *testing.T) {
	var delivered atomic.Int32
	sender, callback := webhookTestSender(t, func(w http.ResponseWriter, r *http.Request) {
		delivered.Add(1)
		w.WriteHeader(http.StatusAccepted)
	})
	var resolved atomic.Int32
	sender.resolver = webhookTestResolver(func(context.Context, string, string) ([]netip.Addr, error) {
		if resolved.Add(1) == 1 {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})
	for attempt := range 2 {
		status, _, err := sender.Send(context.Background(), "sub_1", callback, webhookTestSecret(1, 32), "", "evt_1", []byte(`{"eventId":"evt_1"}`))
		if attempt == 0 && (status != http.StatusAccepted || err != nil) {
			t.Fatalf("first attempt: status %d, error %v", status, err)
		}
		if attempt == 1 {
			webhookReason(t, err, "blocked_address")
		}
	}
	if delivered.Load() != 1 || resolved.Load() != 2 {
		t.Fatalf("deliveries %d; resolutions %d", delivered.Load(), resolved.Load())
	}
}

func TestWebhookSigningExactBytesAndRotation(t *testing.T) {
	body := []byte(`{ "eventId" : "evt_123", "name":"tincan.request.queued", "data":{"status":"queued","value":"\u0026"} }`)
	secret, oldSecret := webhookTestSecret(1, 32), webhookTestSecret(2, 32)
	var attempts atomic.Int32
	sender, callback := webhookTestSender(t, func(w http.ResponseWriter, r *http.Request) {
		attempt := attempts.Add(1)
		got, _ := io.ReadAll(r.Body)
		if !bytes.Equal(got, body) {
			t.Errorf("body was reserialized: %q", got)
		}
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("X-MCP-Subscription-Id") != "sub_123" || r.Header.Get("webhook-id") != "evt_123" {
			t.Errorf("unexpected request headers: %v", r.Header)
		}
		timestamp := strconv.FormatInt(1700000000+int64(attempt), 10)
		if r.Header.Get("webhook-timestamp") != timestamp {
			t.Errorf("timestamp %q, want %q", r.Header.Get("webhook-timestamp"), timestamp)
		}
		want := webhookExpectedSignature(secret, "evt_123", timestamp, body) + " " + webhookExpectedSignature(oldSecret, "evt_123", timestamp, body)
		if r.Header.Get("webhook-signature") != want {
			t.Errorf("signature %q, want %q", r.Header.Get("webhook-signature"), want)
		}
		if r.TLS.ServerName == "" || !strings.HasPrefix(r.Host, r.TLS.ServerName+":") {
			t.Errorf("original hostname lost: Host %q; SNI %q", r.Host, r.TLS.ServerName)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	var timeCalls int64
	sender.now = func() time.Time {
		timeCalls++
		return time.Unix(1700000000+timeCalls, 0)
	}
	for i := range 2 {
		status, _, err := sender.Send(context.Background(), "sub_123", callback, secret, oldSecret, "evt_123", body)
		if err != nil || status != http.StatusServiceUnavailable {
			t.Fatalf("attempt %d: status %d error %v", i, status, err)
		}
	}
	if attempts.Load() != 2 {
		t.Fatalf("sender retried internally: %d requests", attempts.Load())
	}
}

func TestWebhookDoesNotDuplicateIdenticalRotationKey(t *testing.T) {
	secret := webhookTestSecret(1, 32)
	sender, callback := webhookTestSender(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("webhook-signature"), " ") {
			t.Error("same key was signed twice")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	if _, _, err := sender.Send(context.Background(), "sub_1", callback, secret, secret, "evt_1", []byte(`{"eventId":"evt_1"}`)); err != nil {
		t.Fatal(err)
	}
}

func TestWebhookVerificationFreshChallengeAndSignature(t *testing.T) {
	secret := webhookTestSecret(1, 32)
	var lastChallenge, lastID string
	var mu sync.Mutex
	sender, callback := webhookTestSender(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var verification struct {
			Type      string `json:"type"`
			Challenge string `json:"challenge"`
		}
		if err := json.Unmarshal(body, &verification); err != nil || verification.Type != "verification" || len(verification.Challenge) < 32 {
			t.Errorf("bad verification body: %s", body)
		}
		id := r.Header.Get("webhook-id")
		mu.Lock()
		if !strings.HasPrefix(id, "msg_verification_") || id == lastID || verification.Challenge == lastChallenge {
			t.Error("verification reused its ID or challenge")
		}
		lastID, lastChallenge = id, verification.Challenge
		mu.Unlock()
		want := webhookExpectedSignature(secret, id, r.Header.Get("webhook-timestamp"), body)
		if r.Header.Get("webhook-signature") != want || r.Header.Get("X-MCP-Subscription-Id") != "sub_1" {
			t.Error("verification was not signed for its subscription")
		}
		json.NewEncoder(w).Encode(map[string]string{"challenge": verification.Challenge})
	})
	for range 2 {
		if err := sender.Verify(context.Background(), "sub_1", callback, secret); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWebhookVerificationRejectsInvalidResponses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"wrong_challenge", 200, `{"challenge":"wrong"}`},
		{"missing_challenge", 200, `{}`},
		{"malformed_json", 200, `{"challenge"`},
		{"trailing_json", 200, `{} {}`},
		{"over_limit", 200, strings.Repeat("a", verificationLimit+1)},
		{"non_success", 401, `{}`},
		{"redirect", 302, `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender, callback := webhookTestSender(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			})
			webhookReason(t, sender.Verify(context.Background(), "sub_1", callback, webhookTestSecret(1, 32)), "challenge_failed")
		})
	}
}

func TestWebhookVerificationCannotReplayEarlierChallenge(t *testing.T) {
	var firstChallenge string
	var mu sync.Mutex
	sender, callback := webhookTestSender(t, func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Challenge string `json:"challenge"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		mu.Lock()
		if firstChallenge == "" {
			firstChallenge = in.Challenge
		}
		challenge := firstChallenge
		mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"challenge": challenge})
	})
	if err := sender.Verify(context.Background(), "sub_1", callback, webhookTestSecret(1, 32)); err != nil {
		t.Fatal(err)
	}
	webhookReason(t, sender.Verify(context.Background(), "sub_1", callback, webhookTestSecret(1, 32)), "challenge_failed")
}

func TestWebhookVerificationTimeout(t *testing.T) {
	sender := NewWebhookSender().(*webhookSender)
	sender.resolver = webhookTestResolver(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	webhookReason(t, sender.Verify(ctx, "sub_1", "https://callback.example", webhookTestSecret(1, 32)), "timeout")
}

func TestWebhookBlockedAddressAppliesToVerification(t *testing.T) {
	sender := NewWebhookSender().(*webhookSender)
	sender.resolver = webhookTestResolver(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
	})
	sender.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("verification reached private endpoint")
		return nil, nil
	}
	webhookReason(t, sender.Verify(context.Background(), "sub_1", "https://callback.example", webhookTestSecret(1, 32)), "blocked_address")
}

func TestWebhookRedirectsAndProxyAreDisabled(t *testing.T) {
	var proxyCalls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyCalls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(proxy.Close)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	var callbackCalls atomic.Int32
	sender, callback := webhookTestSender(t, func(w http.ResponseWriter, r *http.Request) {
		callbackCalls.Add(1)
		w.Header().Set("Location", "https://127.0.0.1/private")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	status, _, err := sender.Send(context.Background(), "sub_1", callback, webhookTestSecret(1, 32), "", "evt_1", []byte(`{"eventId":"evt_1"}`))
	if err != nil || status != http.StatusTemporaryRedirect || callbackCalls.Load() != 1 || proxyCalls.Load() != 0 {
		t.Fatalf("status %d error %v; callback requests %d; proxy requests %d", status, err, callbackCalls.Load(), proxyCalls.Load())
	}
}

func TestWebhookRetainsCertificateHostnameVerification(t *testing.T) {
	var delivered atomic.Int32
	sender, callback := webhookTestSender(t, func(w http.ResponseWriter, r *http.Request) {
		delivered.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	hostStart := strings.Index(callback, "://") + 3
	portStart := strings.Index(callback[hostStart:], ":") + hostStart
	callback = callback[:hostStart] + "wrong-host.invalid" + callback[portStart:]
	sender.resolver = webhookTestResolver(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	})
	_, _, err := sender.Send(context.Background(), "sub_1", callback, webhookTestSecret(1, 32), "", "evt_1", []byte(`{"eventId":"evt_1"}`))
	webhookReason(t, err, "delivery_failed")
	if delivered.Load() != 0 {
		t.Fatal("wrong certificate hostname received an event")
	}
}

func TestWebhookReceivedStatusesReturnWithoutRetry(t *testing.T) {
	for _, want := range []int{http.StatusAccepted, http.StatusGone, http.StatusRequestEntityTooLarge, http.StatusInternalServerError, http.StatusTooManyRequests} {
		t.Run(strconv.Itoa(want), func(t *testing.T) {
			var calls atomic.Int32
			sender, callback := webhookTestSender(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(want)
			})
			status, _, err := sender.Send(context.Background(), "sub_1", callback, webhookTestSecret(1, 32), "", "evt_1", []byte(`{"eventId":"evt_1"}`))
			if status != want || err != nil || calls.Load() != 1 {
				t.Fatalf("status %d error %v; attempts %d", status, err, calls.Load())
			}
		})
	}
}

func TestWebhookInvalidInputNeverConnects(t *testing.T) {
	for _, tc := range []struct {
		name, subID, id, secret, previous, body, reason string
	}{
		{"oversize", "sub_1", "evt_1", webhookTestSecret(1, 32), "", strings.Repeat("a", webhookMaxBody+1), "payload_too_large"},
		{"id_mismatch", "sub_1", "evt_2", webhookTestSecret(1, 32), "", `{"eventId":"evt_1"}`, "invalid_payload"},
		{"not_json", "sub_1", "evt_1", webhookTestSecret(1, 32), "", `not-json`, "invalid_payload"},
		{"secret", "sub_1", "evt_1", "wrong", "", `{"eventId":"evt_1"}`, "invalid_secret"},
		{"old_secret", "sub_1", "evt_1", webhookTestSecret(1, 32), "wrong", `{"eventId":"evt_1"}`, "invalid_secret"},
		{"header_injection", "sub_1\r\nAuthorization: secret", "evt_1", webhookTestSecret(1, 32), "", `{"eventId":"evt_1"}`, "invalid_metadata"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender := NewWebhookSender().(*webhookSender)
			sender.resolver = webhookTestResolver(func(context.Context, string, string) ([]netip.Addr, error) {
				t.Fatal("invalid input reached DNS")
				return nil, nil
			})
			_, _, err := sender.Send(context.Background(), tc.subID, "https://callback.example", tc.secret, tc.previous, tc.id, []byte(tc.body))
			webhookReason(t, err, tc.reason)
		})
	}
}

func TestWebhookPayloadLimitIsInclusive(t *testing.T) {
	body := []byte(`{"eventId":"evt_1","data":"` + strings.Repeat("a", webhookMaxBody-len(`{"eventId":"evt_1","data":""}`)) + `"}`)
	if len(body) != webhookMaxBody {
		t.Fatalf("test body size %d", len(body))
	}
	sender, callback := webhookTestSender(t, func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength != webhookMaxBody {
			t.Errorf("Content-Length %d", r.ContentLength)
		}
		got, _ := io.ReadAll(r.Body)
		if !bytes.Equal(got, body) {
			t.Error("boundary payload changed")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	status, _, err := sender.Send(context.Background(), "sub_1", callback, webhookTestSecret(1, 32), "", "evt_1", body)
	if status != http.StatusNoContent || err != nil {
		t.Fatalf("boundary delivery status %d error %v", status, err)
	}
}

func TestWebhookDNSFailuresAreCategorizedAndRedacted(t *testing.T) {
	sender := NewWebhookSender().(*webhookSender)
	sender.resolver = webhookTestResolver(func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, errors.New("DNS failed with sensitive details")
	})
	_, _, err := sender.Send(context.Background(), "sub_1", "https://callback.example?private=query", webhookTestSecret(1, 32), "", "evt_1", []byte(`{"eventId":"evt_1"}`))
	webhookReason(t, err, "dns_failed")
	if strings.Contains(err.Error(), "sensitive") || strings.Contains(err.Error(), "private=query") {
		t.Fatal("callback error exposed sensitive details")
	}
}
