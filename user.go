package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type User struct {
	key        string
	name       string
	employeeId string
	ip         string
	cidr       string   // microsoft saying without /<netmask> can cause issues... dont believe them but w/e ticket id - 2106010050001687
	groups     []string // list of object ids
}

type AzGetGroup struct {
	Value []AzGroup `json:"value"`
}

type AzGroup struct {
	ObjectId string `json:"objectId"`
}

func (u *User) new(client *http.Client, req *http.Request) *User {
	// get display name + employee id
	resp, err := client.Get("https://graph.windows.net/me?api-version=1.6")
	if err != nil {
		log.Printf("user.new(): error creating token  %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("user.new(): token response was %s", resp.Status)
		return nil
	}

	var ud map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&ud); err != nil {
		log.Printf("user.new(): error decoding JSON response: %v", err)
		return nil
	}

	if c.Debug {
		log.Printf("user.new(): %v", ud)
	}

	u.employeeId = fmt.Sprintf("%v", ud["employeeId"])
	u.name = fmt.Sprintf("%v", ud["displayName"])

	// get users groups
	resp, err = client.Get("https://graph.windows.net/me/memberOf?api-version=1.6")
	if err != nil {
		log.Printf("user.new(): error creating token  %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("user.new(): token response was %s", resp.Status)
		return nil
	}

	var ug AzGetGroup
	if err := json.NewDecoder(resp.Body).Decode(&ug); err != nil {
		log.Printf("user.new(): error decoding JSON response: %v", err)
		return nil
	}

	if c.Debug {
		log.Printf("user.new(): %v", ug)
	}

	for _, g := range ug.Value {
		u.groups = append(u.groups, g.ObjectId)
	}

	if c.Debug {
		log.Printf("user.new(): %v groups: %v", u.name, u.groups)
	}

	// derive key, client IP, and cidr (shared with the no-auth path)
	if err := u.finishUser(u.name+u.employeeId, req); err != nil {
		log.Fatal("user.new(): ", err)
	}

	log.Println("user.new(): authentication successful - " + u.name + " (" + u.employeeId + ") - " + u.ip)

	return u
}

// finishUser fills in the request-derived fields shared by both the OAuth and
// no-auth constructors: the client IP (with a loopback override for local
// testing), its cidr, and the whitelist key derived from identity. When
// identity is empty the key falls back to the client IP.
func (u *User) finishUser(identity string, req *http.Request) error {
	// get ip from the configured trusted header. Azure Front Door sets
	// X-Azure-Clientip (the default when ip_header is unset); no-auth mode uses
	// ip_header (e.g. Cf-Connecting-Ip). Fall back to RemoteAddr when absent.
	ipHeader := c.Auth.IPHeader
	if ipHeader == "" {
		ipHeader = "X-Azure-Clientip"
	}
	u.ip = req.Header.Get(ipHeader)
	if u.ip == "" {
		var err error
		u.ip, _, err = net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			log.Printf("user.finishUser(): %q is not IP:port\n", req.RemoteAddr)
		}
	}

	// annoying when testing locally, make up an ip :)
	if u.ip == "::1" {
		u.ip = "80.18.81.18"
	}

	cidr, err := addNetmask(u.ip)
	if err != nil {
		return err
	}
	u.cidr = cidr

	// Create our 'key' by removing spaces, lower-casing and stripping special
	// characters. Fall back to the IP when there is no identity (no-auth mode);
	// the OAuth path always supplies a non-empty identity.
	if identity == "" {
		identity = u.ip
	}
	reg, err := regexp.Compile("[^a-zA-Z0-9]+")
	if err != nil {
		return err
	}
	u.key = strings.ToLower(reg.ReplaceAllString(identity, ""))

	return nil
}

// newFromRequest builds a User without OAuth, for auth.type: none. Identity
// comes from the configured trusted header (set by an upstream SSO proxy such
// as Cloudflare Access). Groups are unavailable, so u.groups stays nil and the
// existing hasGroup logic skips group-scoped resources.
func (u *User) newFromRequest(req *http.Request) *User {
	var identity string
	if c.Auth.Header != "" {
		identity = req.Header.Get(c.Auth.Header)
	}
	if identity != "" {
		u.name = identity
	}

	if err := u.finishUser(identity, req); err != nil {
		log.Printf("user.newFromRequest(): %v", err)
		return nil
	}

	log.Println("user.newFromRequest(): request accepted - " + u.name + " - " + u.ip)
	return u
}

func (u *User) whitelist() {
	s := w.add(u)
	if s {
		log.Println("user.whitelist(): Whitelisting for '" + u.ip + "' (" + u.name + ") will expire on " + time.Now().Add(time.Duration(c.TTL)*time.Hour).Format("02-01-2006 at 15:04"))
	}
}

// TODO: currently unused
// func (u *User) unwhitelist() {
// 	s := w.delete(u)
// 	if s {
// 		log.Println("user.unwhitelist(): Whitelisting for '" + u.ip + "' (" + u.name + ") has been removed")
// 	}
// }
