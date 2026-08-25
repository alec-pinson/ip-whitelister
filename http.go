package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	_ "golang.org/x/net/context"
	"golang.org/x/oauth2"
)

type handle func(w http.ResponseWriter, req *http.Request) error

var httpLive bool = true
var httpReady bool = false

type Error struct {
	Code    int
	Message string
}

var indexTempl = template.Must(template.New("").Parse(`<!DOCTYPE html>
<html>
  <head>
    <title>Dynamic IP Whitelist</title>

    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
  </head>
  <body class="container-fluid">
    <div class="row">
      <div class="col-xs-4 col-xs-offset-4">
        <h1>Dynamic IP Whitelist</h1>
{{with .Token}}
				<div id="displayName"></div>
				<i>Note: It can take a few minutes for your whitelisting to become active.</i>
				<br>
				<br>
				<a href="/?new=true">Whitelist again</a>
{{else}}
				Whitelisting your IP........
				<meta http-equiv="refresh" content="0; URL={{$.AuthURL}}" />
{{end}}
      </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.2.1.min.js" integrity="sha256-hwg4gsxgFZhOsEEamdOYGBf13FyQuiTwlAQgxVSNgt4=" crossorigin="anonymous"></script>
    <script>
{{with .Token}}
      var token = {{.}};

      $.ajax({
        url: 'https://graph.windows.net/me?api-version=1.6',
        dataType: 'json',
        success: function(data, status) {
        	$('#displayName').text('Welcome ' + data.displayName + ', your IP (' + {{$.IPAddress}} + ') has been whitelisted. Please note that IPv6 cannot be whitelisted on all resources.');
        },
        beforeSend: function(xhr, settings) {
          xhr.setRequestHeader('Authorization', 'Bearer ' + token.access_token);
        }
      });
{{end}}
    </script>
{{range .Probes}}
    <script>
      (function () {
        fetch({{.Url}}, {referrerPolicy: 'no-referrer', signal: AbortSignal.timeout({{.Timeout}})})
          .then(function (res) { return res.ok ? res.text() : Promise.reject(res.status); })
          .then(function (ip) {
            return fetch('/resolve', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({family: {{.Family}}, ip: ip.trim()})
            });
          })
          .catch(function (err) { console.log('ip probe failed', err); });
      })();
    </script>
{{end}}
  </body>
</html>
`))

var noAuthTempl = template.Must(template.New("").Parse(`<!DOCTYPE html>
<html>
  <head>
    <title>Dynamic IP Whitelist</title>

    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
  </head>
  <body class="container-fluid">
    <div class="row">
      <div class="col-xs-4 col-xs-offset-4">
        <h1>Dynamic IP Whitelist</h1>
        Welcome{{with .Name}} {{.}}{{end}}, your IP ({{.IPAddress}}) has been whitelisted.
        <br>
        <i>Note: It can take a few minutes for your whitelisting to become active. Please note that IPv6 cannot be whitelisted on all resources.</i>
      </div>
    </div>
{{range .Probes}}
    <script>
      (function () {
        fetch({{.Url}}, {referrerPolicy: 'no-referrer', signal: AbortSignal.timeout({{.Timeout}})})
          .then(function (res) { return res.ok ? res.text() : Promise.reject(res.status); })
          .then(function (ip) {
            return fetch('/resolve', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({family: {{.Family}}, ip: ip.trim()})
            });
          })
          .catch(function (err) { console.log('ip probe failed', err); });
      })();
    </script>
{{end}}
  </body>
</html>
`))

func (h handle) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			if c.Debug {
				log.Printf("Handler panic: %v", r)
			}
		}
	}()
	if err := h(w, req); err != nil {
		log.Printf("http.ServeHTTP(): %v", err)

		if httpErr, ok := err.(Error); ok {
			http.Error(w, httpErr.Message, httpErr.Code)
		}
	}
}

func (e Error) Error() string {
	if e.Message == "" {
		e.Message = http.StatusText(e.Code)
	}
	return fmt.Sprintf("%d: %s", e.Code, e.Message)
}

func SessionState(session *sessions.Session) string {
	return base64.StdEncoding.EncodeToString(sha256.New().Sum([]byte(session.ID)))
}

var (
	// Authentication + Encryption key pairs
	sessionStoreKeyPairs = [][]byte{
		[]byte("s0m2th1ng-v3ry-v3ry-s3cr3tive-l0v3-413c"),
		nil,
	}
	oauthConfig *oauth2.Config
	store       sessions.Store
	ctx         context.Context
)

type Authentication struct {
	Type         string `yaml:"type"`
	Header       string `yaml:"header"`
	IPHeader     string `yaml:"ip_header"`
	TenantId     string `yaml:"tenant_id"`
	ClientId     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
}

func (*Authentication) init(a Authentication) {
	// Create file system store with no size limit
	fsStore := sessions.NewFilesystemStore("/tmp", sessionStoreKeyPairs...)
	fsStore.MaxLength(0)
	store = fsStore

	gob.Register(&oauth2.Token{})

	switch strings.ToLower(a.Type) {
	case "azure":
		a.initAzure()
	case "none", "disabled":
		a.initNoAuth()
	default:
		log.Fatalln("http.init(): unsupported authentication type '" + a.Type + "'")
	}
}

func (a *Authentication) initAzure() {
	ctx = context.Background()

	var redirectURL = c.Url + "/callback"
	var authURL = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/authorize?resource=https://graph.windows.net", c.Auth.TenantId)
	var tokenURL = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/token", c.Auth.TenantId)

	oauthConfig = &oauth2.Config{
		ClientID:     a.ClientId,
		ClientSecret: a.ClientSecret,
		RedirectURL:  redirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},

		Scopes: []string{"profile"},
	}

	http.Handle("/live", handle(livenessHandler))
	http.Handle("/ready", handle(readinessHandler))
	http.Handle("/callback", handle(callbackHandler))
	http.Handle("/resolve", handle(resolveHandler))
	http.Handle("/", handle(IndexHandler))
	log.Fatal(http.ListenAndServe(":8090", nil))
}

func noAuthIndexHandler(w http.ResponseWriter, req *http.Request) error {
	var u User
	if u.newFromRequest(req) == nil {
		return Error{Code: http.StatusBadRequest, Message: "could not determine client IP"}
	}
	u.whitelist()

	var data = struct {
		Name      string
		IPAddress string
		Probes    []probe
	}{
		Name:      u.name,
		IPAddress: u.ip,
		Probes:    pendingProbes(u.ip),
	}
	return noAuthTempl.Execute(w, &data)
}

func (*Authentication) initNoAuth() {
	http.Handle("/live", handle(livenessHandler))
	http.Handle("/ready", handle(readinessHandler))
	http.Handle("/resolve", handle(resolveHandler))
	http.Handle("/", handle(noAuthIndexHandler))
	log.Fatal(http.ListenAndServe(":8090", nil))
}

func (a *Authentication) start() {
	httpReady = true
	log.Print("http.start(): ip whitelister started")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

/*
*
Method to handle OAuth callback, not library specific
*/
func callbackHandler(w http.ResponseWriter, req *http.Request) error {
	session, _ := store.Get(req, "session")
	queryParts, _ := url.ParseQuery(req.URL.RawQuery)

	// Use the authorization code that is pushed to the redirect
	// URL.
	code := queryParts["code"][0]

	// Exchange will do the handshake to retrieve the initial access token.
	token, err := oauthConfig.Exchange(ctx, code)
	if err != nil {
		log.Fatal("http.callbackHandler():", err)
	}
	// The HTTP Client returned by conf.Client will refresh the token as necessary.
	client := oauthConfig.Client(ctx, token)

	var u User
	u.new(client, req)
	u.whitelist()

	session.Values["token"] = &token
	session.Values["name"] = &u.name
	session.Values["ip_address"] = &u.ip
	// /resolve needs the whitelist key to rebuild the user
	session.Values["key"] = u.key
	if err := sessions.Save(req, w); err != nil {
		return fmt.Errorf("http.callbackHandler(): error saving session: %v", err)
	}

	http.Redirect(w, req, "/", http.StatusFound)
	return nil
}

func IndexHandler(w http.ResponseWriter, req *http.Request) error {
	session, _ := store.Get(req, "session")

	var token *oauth2.Token
	var ipAddress string

	if req.FormValue("new") != "" {
		session.Values["token"] = nil
		session.Values["ip_address"] = nil
		sessions.Save(req, w)
	} else {
		if v, ok := session.Values["token"]; ok {
			token = v.(*oauth2.Token)
		}
		if v, ok := session.Values["ip_address"]; ok {
			ipAddress = v.(string)
		}
	}

	var probes []probe
	if token != nil {
		// before authentication the page only renders a redirect, so there is
		// nothing to probe for yet
		probes = pendingProbes(ipAddress)
	}

	var data = struct {
		Token     *oauth2.Token
		AuthURL   string
		IPAddress string
		Probes    []probe
	}{
		Token:     token,
		AuthURL:   oauthConfig.AuthCodeURL(SessionState(session), oauth2.AccessTypeOnline),
		IPAddress: ipAddress,
		Probes:    probes,
	}

	return indexTempl.Execute(w, &data)
}

// probe is one family's browser-side lookup, rendered into the page.
type probe struct {
	Family  string
	Url     string
	Timeout int // milliseconds, for AbortSignal.timeout()
}

// pendingProbes returns the lookups the page should run: one per enabled family
// that has a url configured and was not already satisfied by the connection.
// The family we observed needs no probe, which also avoids a third-party
// request for an address we already know.
func pendingProbes(observed string) []probe {
	observedType, err := ipVersion(observed)
	if err != nil {
		observedType = Undefined
	}

	var out []probe
	families := []struct {
		name string
		t    IpType
		fr   IpFamilyResolution
	}{
		{ipVersionV4, IpV4, c.IpResolution.IPv4},
		{ipVersionV6, IpV6, c.IpResolution.IPv6},
	}
	for _, f := range families {
		if !f.fr.isEnabled() || f.fr.Url == "" || f.t == observedType {
			continue
		}
		out = append(out, probe{
			Family:  f.name,
			Url:     f.fr.Url,
			Timeout: int(f.fr.timeout() / time.Millisecond),
		})
	}
	return out
}

// resolveRequest is a client-asserted address for one family, POSTed by the
// probe JS after it fetches the configured echo url.
type resolveRequest struct {
	Family string `json:"family"`
	Ip     string `json:"ip"`
}

// resolveUser rebuilds the authenticated user for a /resolve request without
// setting an address — the caller supplies that from the claim or the
// connection. Groups are read back from the cache rather than left nil: w.add()
// writes u.groups to the cache, so a nil slice here would silently drop the
// user out of every group-scoped resource.
func resolveUser(req *http.Request) (*User, error) {
	switch strings.ToLower(c.Auth.Type) {
	case "none", "disabled":
		var u User
		if u.newFromRequest(req) == nil {
			return nil, Error{Code: http.StatusUnauthorized, Message: "could not determine client identity"}
		}
		return &u, nil
	default:
		session, _ := store.Get(req, "session")
		if session.Values["token"] == nil {
			return nil, Error{Code: http.StatusUnauthorized}
		}
		key, _ := session.Values["key"].(string)
		if key == "" {
			return nil, Error{Code: http.StatusUnauthorized}
		}
		name, _ := session.Values["name"].(string)
		return &User{key: key, name: name, groups: r.getGroups(key)}, nil
	}
}

// resolveHandler accepts a client-asserted address for one family and
// whitelists it. The address is a claim the app cannot verify, so it is only
// accepted for a family that has a url configured — otherwise a deployment that
// never opted into client-asserted resolution would expose an open whitelisting
// endpoint.
func resolveHandler(wr http.ResponseWriter, req *http.Request) error {
	if req.Method != http.MethodPost {
		return Error{Code: http.StatusMethodNotAllowed}
	}

	var body resolveRequest
	if err := json.NewDecoder(io.LimitReader(req.Body, 1024)).Decode(&body); err != nil {
		return Error{Code: http.StatusBadRequest, Message: "invalid json"}
	}

	fr, claimed, ok := c.IpResolution.family(body.Family)
	if !ok {
		return Error{Code: http.StatusBadRequest, Message: "unknown address family"}
	}
	if !fr.isEnabled() {
		return Error{Code: http.StatusBadRequest, Message: "address family is disabled"}
	}
	if fr.Url == "" {
		return Error{Code: http.StatusBadRequest, Message: "client-asserted resolution is not configured for this family"}
	}

	u, err := resolveUser(req)
	if err != nil {
		return err
	}

	ip := body.Ip
	// if this request itself arrived over the claimed family, the address we
	// observed is strictly better than the one being claimed
	if observed := observedIp(req); observed != "" {
		if t, err := ipVersion(observed); err == nil && t == claimed {
			ip = observed
		}
	}

	t, err := ipVersion(ip)
	if err != nil {
		return Error{Code: http.StatusBadRequest, Message: "unparseable ip"}
	}
	if t != claimed {
		return Error{Code: http.StatusBadRequest, Message: "ip does not match the claimed address family"}
	}

	cidr, err := addNetmask(ip)
	if err != nil {
		return Error{Code: http.StatusBadRequest, Message: "unparseable ip"}
	}
	u.ip = ip
	u.cidr = cidr
	u.whitelist()

	wr.WriteHeader(http.StatusNoContent)
	return nil
}

func livenessHandler(w http.ResponseWriter, req *http.Request) error {
	var err error
	if httpLive {
		w.WriteHeader(200)
		_, err = w.Write([]byte("ok"))
	} else {
		w.WriteHeader(500)
		_, err = w.Write([]byte("not ok"))
	}
	return err
}

func readinessHandler(w http.ResponseWriter, req *http.Request) error {
	var err error
	if httpReady {
		w.WriteHeader(200)
		_, err = w.Write([]byte("ok"))
	} else {
		w.WriteHeader(500)
		_, err = w.Write([]byte("not ok"))
	}
	return err
}
