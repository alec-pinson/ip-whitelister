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
