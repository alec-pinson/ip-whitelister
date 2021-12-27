package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/sessions"
	_ "golang.org/x/net/context"
	"golang.org/x/oauth2"
)

type handle func(w http.ResponseWriter, req *http.Request) error

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
        	$('#displayName').text('Welcome ' + data.displayName + ', your IP (' + {{$.IPAddress}} + ') has been whitelisted.');
        },
        beforeSend: function(xhr, settings) {
          xhr.setRequestHeader('Authorization', 'Bearer ' + token.access_token);
        }
      });
{{end}}
    </script>
  </body>
</html>
`))

func (h handle) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			// if c.Debug {
			// 	log.Printf("Handler panic: %v", r)
			// }
		}
	}()
	if err := h(w, req); err != nil {
		log.Printf("Handler error: %v", err)

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
	default:
		log.Fatalln("unsupported authentication type '" + a.Type + "'")
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

	http.Handle("/callback", handle(callbackHandler))
	// http.HandleFunc("/ip", IPHandler)
	http.Handle("/", handle(IndexHandler))
	log.Fatal(http.ListenAndServe(":8080", nil))
}

/**
Method to handle OAuth callback, not library specific
*/
func callbackHandler(w http.ResponseWriter, req *http.Request) error {
	session, _ := store.Get(req, "session")
	queryParts, _ := url.ParseQuery(req.URL.RawQuery)

	// Use the authorization code that is pushed to the redirect
	// URL.
	code := queryParts["code"][0]
	// log.Printf("code: %s\n", code)

	// Exchange will do the handshake to retrieve the initial access token.
	token, err := oauthConfig.Exchange(ctx, code)
	if err != nil {
		log.Fatal(err)
	}
	// log.Printf("Token: %s", token)
	// The HTTP Client returned by conf.Client will refresh the token as necessary.
	client := oauthConfig.Client(ctx, token)

	var u User
	u.new(client, req)
	u.whitelist()

	session.Values["token"] = &token
	session.Values["name"] = &u.name
	session.Values["ip_address"] = &u.ip
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

	var data = struct {
		Token     *oauth2.Token
		AuthURL   string
		IPAddress string
	}{
		Token:     token,
		AuthURL:   oauthConfig.AuthCodeURL(SessionState(session), oauth2.AccessTypeOnline),
		IPAddress: ipAddress,
	}

	return indexTempl.Execute(w, &data)
}
