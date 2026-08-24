package main

import (
	"encoding/gob"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

func TestErrorError(t *testing.T) {
	tests := []struct {
		err  Error
		want string
	}{
		{Error{Code: 404, Message: "nope"}, "404: nope"},
		// empty message falls back to the standard status text
		{Error{Code: 404}, "404: Not Found"},
		{Error{Code: 500}, "500: Internal Server Error"},
	}

	for _, f := range tests {
		if got := f.err.Error(); got != f.want {
			t.Errorf("Error.Error() = %q, want %q", got, f.want)
		}
	}
}

func TestLivenessHandler(t *testing.T) {
	tests := []struct {
		live     bool
		wantCode int
		wantBody string
	}{
		{true, 200, "ok"},
		{false, 500, "not ok"},
	}

	for _, f := range tests {
		httpLive = f.live
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/live", nil)

		if err := livenessHandler(rr, req); err != nil {
			t.Fatalf("livenessHandler() unexpected error: %v", err)
		}
		if rr.Code != f.wantCode {
			t.Errorf("livenessHandler() code = %d, want %d", rr.Code, f.wantCode)
		}
		if rr.Body.String() != f.wantBody {
			t.Errorf("livenessHandler() body = %q, want %q", rr.Body.String(), f.wantBody)
		}
	}
	httpLive = true
}

func TestReadinessHandler(t *testing.T) {
	tests := []struct {
		ready    bool
		wantCode int
		wantBody string
	}{
		{true, 200, "ok"},
		{false, 500, "not ok"},
	}

	for _, f := range tests {
		httpReady = f.ready
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/ready", nil)

		if err := readinessHandler(rr, req); err != nil {
			t.Fatalf("readinessHandler() unexpected error: %v", err)
		}
		if rr.Code != f.wantCode {
			t.Errorf("readinessHandler() code = %d, want %d", rr.Code, f.wantCode)
		}
		if rr.Body.String() != f.wantBody {
			t.Errorf("readinessHandler() body = %q, want %q", rr.Body.String(), f.wantBody)
		}
	}
	httpReady = false
}

func TestServeHTTP(t *testing.T) {
	// A handler returning an Error should be translated into an http.Error.
	errHandler := handle(func(w http.ResponseWriter, req *http.Request) error {
		return Error{Code: 403, Message: "forbidden"}
	})
	rr := httptest.NewRecorder()
	errHandler.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if rr.Code != 403 {
		t.Errorf("ServeHTTP() with Error: code = %d, want 403", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "forbidden") {
		t.Errorf("ServeHTTP() with Error: body = %q, want to contain %q", rr.Body.String(), "forbidden")
	}

	// A handler returning nil should leave the default 200 and empty body.
	okHandler := handle(func(w http.ResponseWriter, req *http.Request) error {
		return nil
	})
	rr = httptest.NewRecorder()
	okHandler.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if rr.Code != 200 {
		t.Errorf("ServeHTTP() with nil: code = %d, want 200", rr.Code)
	}

	// A panicking handler should be recovered, not crash the process.
	panicHandler := handle(func(w http.ResponseWriter, req *http.Request) error {
		panic("boom")
	})
	rr = httptest.NewRecorder()
	panicHandler.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil)) // must not panic
}

func TestSessionState(t *testing.T) {
	s := sessions.NewSession(sessions.NewCookieStore(), "session")
	s.ID = "abc123"

	got := SessionState(s)
	if got == "" {
		t.Fatal("SessionState() returned an empty string")
	}
	// deterministic for a given session ID
	if again := SessionState(s); again != got {
		t.Errorf("SessionState() not deterministic: %q vs %q", got, again)
	}
}

func TestIndexHandler(t *testing.T) {
	// Minimal wiring normally done by Authentication.init / initAzure.
	store = sessions.NewFilesystemStore(t.TempDir(), sessionStoreKeyPairs...)
	oauthConfig = &oauth2.Config{
		ClientID:    "test-client",
		RedirectURL: "http://localhost/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://login.example.com/authorize",
			TokenURL: "https://login.example.com/token",
		},
	}

	// No token in session -> the "whitelisting" branch with an auth redirect.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	if err := IndexHandler(rr, req); err != nil {
		t.Fatalf("IndexHandler() unexpected error: %v", err)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Whitelisting your IP") {
		t.Errorf("IndexHandler() body missing the whitelisting message:\n%s", body)
	}
	if !strings.Contains(body, "https://login.example.com/authorize") {
		t.Errorf("IndexHandler() body missing the auth redirect URL:\n%s", body)
	}

	// ?new=true clears the session and still renders the redirect branch.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/?new=true", nil)
	if err := IndexHandler(rr, req); err != nil {
		t.Fatalf("IndexHandler(new=true) unexpected error: %v", err)
	}
	if !strings.Contains(rr.Body.String(), "Whitelisting your IP") {
		t.Errorf("IndexHandler(new=true) body missing the whitelisting message")
	}
}

func TestIndexHandlerWithToken(t *testing.T) {
	// Minimal wiring normally done by Authentication.init / initAzure.
	gob.Register(&oauth2.Token{})
	store = sessions.NewFilesystemStore(t.TempDir(), sessionStoreKeyPairs...)
	oauthConfig = &oauth2.Config{
		ClientID:    "test-client",
		RedirectURL: "http://localhost/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://login.example.com/authorize",
			TokenURL: "https://login.example.com/token",
		},
	}

	// Populate a session with a token + ip, as callbackHandler would, and
	// capture the resulting session cookie.
	saveReq := httptest.NewRequest("GET", "/", nil)
	saveRR := httptest.NewRecorder()
	session, _ := store.Get(saveReq, "session")
	session.Values["token"] = &oauth2.Token{AccessToken: "test-access-token"}
	session.Values["ip_address"] = "203.0.113.7"
	if err := sessions.Save(saveReq, saveRR); err != nil {
		t.Fatalf("failed to save session: %v", err)
	}

	// Replay the cookie so IndexHandler takes the token-present branch.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	for _, cookie := range saveRR.Result().Cookies() {
		req.AddCookie(cookie)
	}
	if err := IndexHandler(rr, req); err != nil {
		t.Fatalf("IndexHandler() unexpected error: %v", err)
	}

	body := rr.Body.String()
	// the token branch renders the "Whitelist again" link and the whitelisted IP
	if !strings.Contains(body, "Whitelist again") {
		t.Errorf("IndexHandler() with token missing the 'Whitelist again' link:\n%s", body)
	}
	if !strings.Contains(body, "203.0.113.7") {
		t.Errorf("IndexHandler() with token missing the whitelisted IP:\n%s", body)
	}
	if strings.Contains(body, "Whitelisting your IP") {
		t.Errorf("IndexHandler() with token should not render the redirect branch:\n%s", body)
	}
}

func TestNoAuthIndexHandler(t *testing.T) {
	testRedisInstance := CreateTestRedis(t)
	var rc RedisConfiguration
	rc.Host = testRedisInstance.Host
	rc.Port = testRedisInstance.Port
	rc.Token = testRedisInstance.Token
	if !r.connect(rc) {
		t.Fatal("could not connect to test redis")
	}
	defer DeleteTestRedis(t, testRedisInstance)

	// config is never loaded in tests; give redis keys a real TTL and set the
	// trusted header the no-auth path reads.
	c.TTL = 24
	c.Auth.Header = "Cf-Access-Authenticated-User-Email"
	defer func() { c.Auth.Header = "" }()
	c.Auth.IPHeader = "Cf-Connecting-Ip"
	defer func() { c.Auth.IPHeader = "" }()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Cf-Access-Authenticated-User-Email", "alice@example.com")
	req.Header.Set("Cf-Connecting-Ip", "203.0.113.7")
	rr := httptest.NewRecorder()

	if err := noAuthIndexHandler(rr, req); err != nil {
		t.Fatalf("noAuthIndexHandler() unexpected error: %v", err)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "203.0.113.7") {
		t.Errorf("body missing whitelisted IP:\n%s", body)
	}
	if !strings.Contains(body, "alice@example.com") {
		t.Errorf("body missing identity:\n%s", body)
	}
	if !strings.Contains(body, "has been whitelisted") {
		t.Errorf("body missing confirmation text:\n%s", body)
	}
	if strings.Contains(body, "Whitelisting your IP") {
		t.Errorf("body unexpectedly rendered the OAuth redirect branch:\n%s", body)
	}

	if got := r.getWhitelist()["aliceexamplecom"]; got != "203.0.113.7/32" {
		t.Errorf("redis whitelist entry = %q, want %q", got, "203.0.113.7/32")
	}
}

func TestResolveHandler(t *testing.T) {
	testRedisInstance := CreateTestRedis(t)
	var rc RedisConfiguration
	rc.Host = testRedisInstance.Host
	rc.Port = testRedisInstance.Port
	rc.Token = testRedisInstance.Token
	if !r.connect(rc) {
		t.Fatal("could not connect to test redis")
	}
	defer DeleteTestRedis(t, testRedisInstance)

	c.TTL = 24
	c.IPWhiteList = nil
	c.Auth.Type = "none"
	c.Auth.Header = "Cf-Access-Authenticated-User-Email"
	c.Auth.IPHeader = "Cf-Connecting-Ip"
	c.IpResolution = IpResolution{
		IPv4: IpFamilyResolution{Header: "Cf-Connecting-Ip", Url: "https://ipv4.icanhazip.com"},
		IPv6: IpFamilyResolution{Header: "Cf-Connecting-Ip", Url: "https://ipv6.icanhazip.com"},
	}
	defer func() {
		c.Auth.Type = ""
		c.Auth.Header = ""
		c.Auth.IPHeader = ""
		c.IpResolution = IpResolution{}
	}()

	newReq := func(body string) *http.Request {
		req := httptest.NewRequest("POST", "/resolve", strings.NewReader(body))
		req.Header.Set("Cf-Access-Authenticated-User-Email", "bob@example.com")
		req.Header.Set("Cf-Connecting-Ip", "203.0.113.7")
		return req
	}

	// a valid ipv6 claim from a request that arrived over ipv4 is accepted
	rr := httptest.NewRecorder()
	if err := resolveHandler(rr, newReq(`{"family":"ipv6","ip":"2a00:11c7:1234:b801::1"}`)); err != nil {
		t.Fatalf("resolveHandler() unexpected error: %v", err)
	}
	if got := r.getWhitelist()["bobexamplecom"+redisKeySuffixV6]; got != "2a00:11c7:1234:b801::1/128" {
		t.Errorf("ipv6 entry = %q, want %q", got, "2a00:11c7:1234:b801::1/128")
	}

	// the claimed family must match the address actually supplied
	rr = httptest.NewRecorder()
	if err := resolveHandler(rr, newReq(`{"family":"ipv6","ip":"198.51.100.9"}`)); err == nil {
		t.Error("expected an error for a family mismatch")
	}

	// unparseable addresses are rejected. This must claim ipv6: the request
	// arrives over ipv4, so an ipv4 claim would be replaced by the observed
	// address before it was ever parsed.
	rr = httptest.NewRecorder()
	if err := resolveHandler(rr, newReq(`{"family":"ipv6","ip":"not-an-ip"}`)); err == nil {
		t.Error("expected an error for an unparseable ip")
	}

	// a claim for the family we observed is replaced by the observed address,
	// which is trustworthy where the claim is not
	rr = httptest.NewRecorder()
	if err := resolveHandler(rr, newReq(`{"family":"ipv4","ip":"8.8.8.8"}`)); err != nil {
		t.Fatalf("resolveHandler() unexpected error: %v", err)
	}
	if got := r.getWhitelist()["bobexamplecom"]; got != "203.0.113.7/32" {
		t.Errorf("ipv4 entry = %q, want the observed %q, not the claimed 8.8.8.8", got, "203.0.113.7/32")
	}

	// an unknown family is rejected
	rr = httptest.NewRecorder()
	if err := resolveHandler(rr, newReq(`{"family":"ipv5","ip":"198.51.100.9"}`)); err == nil {
		t.Error("expected an error for an unknown family")
	}

	// GET is not allowed
	rr = httptest.NewRecorder()
	getReq := httptest.NewRequest("GET", "/resolve", nil)
	if err := resolveHandler(rr, getReq); err == nil {
		t.Error("expected an error for a GET request")
	}
}

func TestResolveHandlerRejectsUnconfiguredFamily(t *testing.T) {
	testRedisInstance := CreateTestRedis(t)
	var rc RedisConfiguration
	rc.Host = testRedisInstance.Host
	rc.Port = testRedisInstance.Port
	rc.Token = testRedisInstance.Token
	if !r.connect(rc) {
		t.Fatal("could not connect to test redis")
	}
	defer DeleteTestRedis(t, testRedisInstance)

	c.TTL = 24
	c.Auth.Type = "none"
	c.Auth.Header = "Cf-Access-Authenticated-User-Email"
	// no url configured for ipv6 => the deployment never opted into
	// client-asserted resolution, so /resolve must not act as an open
	// whitelisting endpoint
	c.IpResolution = IpResolution{IPv4: IpFamilyResolution{Url: "https://ipv4.icanhazip.com"}}
	defer func() {
		c.Auth.Type = ""
		c.Auth.Header = ""
		c.IpResolution = IpResolution{}
	}()

	req := httptest.NewRequest("POST", "/resolve", strings.NewReader(`{"family":"ipv6","ip":"2a00:11c7:1234:b801::9"}`))
	req.Header.Set("Cf-Access-Authenticated-User-Email", "carol@example.com")
	rr := httptest.NewRecorder()

	if err := resolveHandler(rr, req); err == nil {
		t.Error("expected an error for a family with no url configured")
	}
	if got := r.getWhitelist()["carolexamplecom"+redisKeySuffixV6]; got != "" {
		t.Errorf("unconfigured family should not be stored, got %q", got)
	}
}

func TestResolveHandlerRejectsUnauthenticated(t *testing.T) {
	// azure mode with no session token: /resolve must not whitelist anything
	store = sessions.NewFilesystemStore(t.TempDir(), sessionStoreKeyPairs...)
	c.Auth.Type = "azure"
	c.IpResolution = IpResolution{IPv6: IpFamilyResolution{Url: "https://ipv6.icanhazip.com"}}
	defer func() {
		c.Auth.Type = ""
		c.IpResolution = IpResolution{}
	}()

	req := httptest.NewRequest("POST", "/resolve", strings.NewReader(`{"family":"ipv6","ip":"2a00:11c7:1234:b801::3"}`))
	rr := httptest.NewRecorder()

	err := resolveHandler(rr, req)
	if err == nil {
		t.Fatal("expected an error for an unauthenticated caller")
	}
	httpErr, ok := err.(Error)
	if !ok || httpErr.Code != http.StatusUnauthorized {
		t.Errorf("error = %v, want a 401", err)
	}
}
