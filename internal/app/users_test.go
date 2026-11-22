package app

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestRolesAuditAndUsers(t *testing.T) {
	a, h, adminTok := newTestApp(t)
	call(t, h, adminTok, "POST", "/api/groups", []byte(`{"name":"Діти","members":["192.168.11.45"]}`))
	// create a viewer and an operator
	for _, u := range []string{`{"name":"mama","role":"operator","password":"operator-pass"}`, `{"name":"guest","role":"viewer","password":"viewer-pass1"}`} {
		if w := call(t, h, adminTok, "PUT", "/api/users", []byte(u)); w.Code != 200 {
			t.Fatalf("create user: %d %s", w.Code, w.Body)
		}
	}
	if _, ok := a.checkLogin("mama", "operator-pass"); !ok {
		t.Fatal("operator login")
	}
	op := a.sessions.create("mama", RoleOperator, "10.0.0.2")
	vw := a.sessions.create("guest", RoleViewer, "10.0.0.3")
	gid := a.state.get().Groups[0].ID

	if w := call(t, h, vw, "GET", "/api/status", nil); w.Code != 200 {
		t.Fatalf("viewer status: %d", w.Code)
	}
	if w := call(t, h, vw, "POST", "/api/groups/internet", []byte(`{"id":"`+gid+`","off":true}`)); w.Code != 403 {
		t.Fatalf("viewer must not switch internet: %d", w.Code)
	}
	if w := call(t, h, op, "POST", "/api/groups/internet", []byte(`{"id":"`+gid+`","off":true}`)); w.Code != 200 {
		t.Fatalf("operator internet: %d %s", w.Code, w.Body)
	}
	if w := call(t, h, op, "PUT", "/api/lists", []byte(`{}`)); w.Code != 403 {
		t.Fatalf("operator must not edit lists: %d", w.Code)
	}
	if w := call(t, h, op, "GET", "/api/telegram", nil); w.Code != 403 {
		t.Fatalf("operator must not read telegram settings: %d", w.Code)
	}
	// last admin cannot be removed or demoted
	if w := call(t, h, adminTok, "PUT", "/api/users", []byte(`{"name":"admin","role":"viewer"}`)); w.Code != 400 {
		t.Fatalf("demoting the last admin must fail: %d", w.Code)
	}
	if w := call(t, h, adminTok, "DELETE", "/api/users", []byte(`{"name":"admin"}`)); w.Code != 400 {
		t.Fatalf("self-delete must fail: %d", w.Code)
	}
	// role change ends the user's sessions
	call(t, h, adminTok, "PUT", "/api/users", []byte(`{"name":"mama","role":"viewer"}`))
	if w := call(t, h, op, "GET", "/api/status", nil); w.Code != 401 {
		t.Fatalf("old operator session must end: %d", w.Code)
	}
	// audit
	w := call(t, h, adminTok, "GET", "/api/audit", nil)
	var au []AuditEntry
	json.Unmarshal(w.Body.Bytes(), &au)
	found := false
	for _, e := range au {
		if e.User == "mama" && e.Action == "POST /api/groups/internet" && e.Status == 200 {
			found = true
		}
	}
	if !found {
		t.Fatalf("audit lacks the operator action: %+v", au)
	}
	// legacy fields keep pointing at an admin (rollback to 0.2.x)
	st := a.state.get()
	if st.AdminUser != "admin" || st.PasswordHash == "" {
		t.Fatal("legacy admin fields")
	}
	// backup without secrets has no hashes; restore keeps logins working
	w = call(t, h, adminTok, "GET", "/api/backup", nil)
	if strings.Contains(w.Body.String(), st.Users[0].Hash) {
		t.Fatal("user hash in backup without secrets")
	}
	if r := call(t, h, adminTok, "POST", "/api/restore", w.Body.Bytes()); r.Code != 200 {
		t.Fatalf("restore: %d %s", r.Code, r.Body)
	}
	if _, ok := a.checkLogin("guest", "viewer-pass1"); !ok {
		t.Fatal("viewer password lost after restore")
	}
}

func TestPanelHTTPS(t *testing.T) {
	a, h, tok := newTestApp(t)
	if w := call(t, h, tok, "PUT", "/api/tls", []byte(`{"mode":"custom","cert_pem":"junk","key_pem":"junk"}`)); w.Code != 400 {
		t.Fatalf("bad custom cert must be rejected: %d", w.Code)
	}
	w := call(t, h, tok, "PUT", "/api/tls", []byte(`{"mode":"auto","redirect":true}`))
	if w.Code != 200 {
		t.Fatalf("tls auto: %d %s", w.Code, w.Body)
	}
	defer a.stopTLS()
	var v tlsView
	json.Unmarshal(w.Body.Bytes(), &v)
	if !v.Running || v.Fingerprint == "" {
		t.Fatalf("tls view: %+v", v)
	}
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := cl.Get("https://" + a.tls.addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("https status %d", resp.StatusCode)
	}
	// plain HTTP is redirected
	if w := call(t, h, tok, "GET", "/api/status", nil); w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("redirect expected, got %d", w.Code)
	}
}
