package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// fakeTransport routes graph.windows.net requests to canned responses keyed by
// URL path, so User.new() can be exercised without any live Azure call.
type fakeTransport struct {
	responses map[string]fakeResponse
}

type fakeResponse struct {
	status int
	body   string
}

func (f fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, ok := f.responses[req.URL.Path]
	if !ok {
		resp = fakeResponse{status: 404, body: "{}"}
	}
	return &http.Response{
		StatusCode: resp.status,
		Status:     http.StatusText(resp.status),
		Body:       io.NopCloser(strings.NewReader(resp.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func fakeGraphClient(me, memberOf fakeResponse) *http.Client {
	return &http.Client{
		Transport: fakeTransport{
			responses: map[string]fakeResponse{
				"/me":          me,
				"/me/memberOf": memberOf,
			},
		},
	}
}

func TestUserNew(t *testing.T) {
	c.Debug = false

	tests := []struct {
		name         string
		me           fakeResponse
		memberOf     fakeResponse
		clientIP     string // X-Azure-Clientip header
		remoteAddr   string
		wantName     string
		wantEmployee string
		wantKey      string
		wantIP       string
		wantCidr     string
		wantGroups   []string
	}{
		{
			name:         "ipv4 from X-Azure-Clientip header",
			me:           fakeResponse{200, `{"displayName":"Test User","employeeId":"12345"}`},
			memberOf:     fakeResponse{200, `{"value":[{"objectId":"group-a"},{"objectId":"group-b"}]}`},
			clientIP:     "1.2.3.4",
			remoteAddr:   "10.0.0.1:5555",
			wantName:     "Test User",
			wantEmployee: "12345",
			wantKey:      "testuser12345",
			wantIP:       "1.2.3.4",
			wantCidr:     "1.2.3.4/32",
			wantGroups:   []string{"group-a", "group-b"},
		},
		{
			name:         "falls back to RemoteAddr when header absent",
			me:           fakeResponse{200, `{"displayName":"Jane Doe","employeeId":"999"}`},
			memberOf:     fakeResponse{200, `{"value":[]}`},
			clientIP:     "",
			remoteAddr:   "8.8.8.8:1234",
			wantName:     "Jane Doe",
			wantEmployee: "999",
			wantKey:      "janedoe999",
			wantIP:       "8.8.8.8",
			wantCidr:     "8.8.8.8/32",
			wantGroups:   nil,
		},
		{
			name:         "loopback is rewritten to a public IP for local testing",
			me:           fakeResponse{200, `{"displayName":"Local Dev","employeeId":"1"}`},
			memberOf:     fakeResponse{200, `{"value":[]}`},
			clientIP:     "::1",
			remoteAddr:   "[::1]:8080",
			wantName:     "Local Dev",
			wantEmployee: "1",
			wantKey:      "localdev1",
			wantIP:       "80.18.81.18",
			wantCidr:     "80.18.81.18/32",
			wantGroups:   nil,
		},
	}

	for _, f := range tests {
		t.Run(f.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/callback", nil)
			req.RemoteAddr = f.remoteAddr
			if f.clientIP != "" {
				req.Header.Set("X-Azure-Clientip", f.clientIP)
			}

			var u User
			got := u.new(fakeGraphClient(f.me, f.memberOf), req)
			if got == nil {
				t.Fatalf("user.new() returned nil, want a populated user")
			}
			if u.name != f.wantName {
				t.Errorf("name: got %q, want %q", u.name, f.wantName)
			}
			if u.employeeId != f.wantEmployee {
				t.Errorf("employeeId: got %q, want %q", u.employeeId, f.wantEmployee)
			}
			if u.key != f.wantKey {
				t.Errorf("key: got %q, want %q", u.key, f.wantKey)
			}
			if u.ip != f.wantIP {
				t.Errorf("ip: got %q, want %q", u.ip, f.wantIP)
			}
			if u.cidr != f.wantCidr {
				t.Errorf("cidr: got %q, want %q", u.cidr, f.wantCidr)
			}
			if !reflect.DeepEqual(u.groups, f.wantGroups) {
				t.Errorf("groups: got %v, want %v", u.groups, f.wantGroups)
			}
		})
	}
}

func TestUserWhitelist(t *testing.T) {
	testRedisInstance := CreateTestRedis(t)
	var rc RedisConfiguration
	rc.Host = testRedisInstance.Host
	rc.Port = testRedisInstance.Port
	rc.Token = testRedisInstance.Token

	if !r.connect(rc) {
		t.Fatal("could not connect to test redis")
	}
	defer DeleteTestRedis(t, testRedisInstance)

	// config is never loaded in tests, so give the redis key a real TTL
	// (EXPIRE with 0 seconds would drop it immediately).
	c.TTL = 24

	var u User
	u.key = "whitelistuser1"
	u.name = "Whitelist User"
	u.employeeId = "424242"
	u.ip = "72.14.0.1"
	u.cidr = "72.14.0.1/32"

	// whitelist() delegates to w.add(); a fresh IP not covered by the static
	// whitelist should be stored and retrievable from redis.
	u.whitelist()

	if got := r.getWhitelist()[u.key]; got != u.cidr {
		t.Errorf("user.whitelist(): redis entry for %q = %q, want %q", u.key, got, u.cidr)
	}
}

func TestUserNewErrorStatus(t *testing.T) {
	c.Debug = false

	tests := []struct {
		name     string
		me       fakeResponse
		memberOf fakeResponse
	}{
		{"me endpoint 500s", fakeResponse{500, ``}, fakeResponse{200, `{"value":[]}`}},
		{"memberOf endpoint 500s", fakeResponse{200, `{"displayName":"x","employeeId":"1"}`}, fakeResponse{500, ``}},
		{"me returns invalid json", fakeResponse{200, `not-json`}, fakeResponse{200, `{"value":[]}`}},
	}

	for _, f := range tests {
		t.Run(f.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/callback", nil)
			req.Header.Set("X-Azure-Clientip", "1.2.3.4")

			var u User
			if got := u.new(fakeGraphClient(f.me, f.memberOf), req); got != nil {
				t.Errorf("user.new() = %v, want nil on error", got)
			}
		})
	}
}
