package app

import (
	"bufio"
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Roles, from least to most privileged.
const (
	RoleViewer   = "viewer"   // dashboard, logs, read-only
	RoleOperator = "operator" // viewer + group controls (internet on/off, group rules)
	RoleAdmin    = "admin"    // everything
)

func roleRank(r string) int {
	switch r {
	case RoleViewer:
		return 1
	case RoleOperator:
		return 2
	case RoleAdmin:
		return 3
	}
	return 0
}

// User is a panel account. Hash is "salt$pbkdf2-sha256".
type User struct {
	Name string `json:"name"`
	Hash string `json:"hash"`
	Role string `json:"role"`
}

var userNameRE = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,32}$`)

const pbkdf2Iter = 120000

func hashPassword(pw string, salt []byte) (string, error) {
	k, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, 32)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(salt) + "$" + hex.EncodeToString(k), nil
}

func newHash(pw string) (string, error) {
	if len(pw) < 8 {
		return "", errors.New("password must be at least 8 characters")
	}
	if len(pw) > 256 {
		return "", errors.New("password is too long")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return hashPassword(pw, salt)
}

func verifyHash(stored, pw string) bool {
	parts := strings.SplitN(stored, "$", 2)
	if len(parts) != 2 {
		return false
	}
	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return false
	}
	h, err := hashPassword(pw, salt)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(h), []byte(stored)) == 1
}

// dummyHash keeps the login time equal for unknown user names.
var dummyHash, _ = hashPassword("x", make([]byte, 16))

// migrateUsers turns the single admin of 0.2.x into the first user.
func (a *App) migrateUsers() error {
	s := a.state.get()
	if len(s.Users) > 0 || s.PasswordHash == "" {
		return nil
	}
	return a.state.update(func(st *State) {
		st.Users = []User{{Name: st.AdminUser, Hash: st.PasswordHash, Role: RoleAdmin}}
	})
}

// syncLegacy keeps admin_user/password_hash pointing at an admin so an
// older version can still log in after a rollback.
func syncLegacy(st *State) {
	for _, u := range st.Users {
		if u.Name == st.AdminUser && u.Role == RoleAdmin {
			st.PasswordHash = u.Hash
			return
		}
	}
	for _, u := range st.Users {
		if u.Role == RoleAdmin {
			st.AdminUser, st.PasswordHash = u.Name, u.Hash
			return
		}
	}
}

// SetUserPassword creates the user (with role) or changes its password.
func (a *App) SetUserPassword(name, pw, role string) error {
	h, err := newHash(pw)
	if err != nil {
		return err
	}
	return a.state.update(func(st *State) {
		for i := range st.Users {
			if st.Users[i].Name == name {
				st.Users[i].Hash = h
				if role != "" {
					st.Users[i].Role = role
				}
				syncLegacy(st)
				return
			}
		}
		if role == "" {
			role = RoleViewer
		}
		st.Users = append(st.Users, User{Name: name, Hash: h, Role: role})
		syncLegacy(st)
	})
}

// checkLogin returns the user on a correct password.
func (a *App) checkLogin(name, pw string) (User, bool) {
	for _, u := range a.state.get().Users {
		if subtle.ConstantTimeCompare([]byte(u.Name), []byte(name)) == 1 {
			return u, verifyHash(u.Hash, pw)
		}
	}
	verifyHash(dummyHash, pw)
	return User{}, false
}

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]byte, n)
	for i, v := range b {
		out[i] = alphabet[int(v)%len(alphabet)]
	}
	return string(out)
}

// ---- sessions -----------------------------------------------------------------------

type session struct {
	User string
	Role string
	Exp  time.Time
	IP   string
}

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]session
	fails    map[string][]time.Time // login failures per client IP and per user
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: map[string]session{}, fails: map[string][]time.Time{}}
}

const sessionTTL = 12 * time.Hour

func (s *sessionStore) create(user, role, ip string) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	s.mu.Lock()
	s.sessions[tok] = session{User: user, Role: role, Exp: time.Now().Add(sessionTTL), IP: ip}
	s.mu.Unlock()
	return tok
}

func (s *sessionStore) get(tok string) (session, bool) {
	if tok == "" {
		return session{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ss, ok := s.sessions[tok]
	if !ok || time.Now().After(ss.Exp) {
		delete(s.sessions, tok)
		return session{}, false
	}
	return ss, true
}

func (s *sessionStore) drop(tok string) {
	s.mu.Lock()
	delete(s.sessions, tok)
	s.mu.Unlock()
}

// dropUser ends every session of a user (after a password/role change).
func (s *sessionStore) dropUser(user string) {
	s.mu.Lock()
	for k, v := range s.sessions {
		if v.User == user {
			delete(s.sessions, k)
		}
	}
	s.mu.Unlock()
}

func (s *sessionStore) dropAll() {
	s.mu.Lock()
	s.sessions = map[string]session{}
	s.mu.Unlock()
}

// count returns active sessions per user.
func (s *sessionStore) count() map[string]int {
	out := map[string]int{}
	now := time.Now()
	s.mu.Lock()
	for _, v := range s.sessions {
		if now.Before(v.Exp) {
			out[v.User]++
		}
	}
	s.mu.Unlock()
	return out
}

// lockedOut reports whether key had 5+ failed logins in the last 10 minutes.
func (s *sessionStore) lockedOut(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := time.Now().Add(-10 * time.Minute)
	keep := s.fails[key][:0]
	for _, t := range s.fails[key] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	s.fails[key] = keep
	return len(keep) >= 5
}

func (s *sessionStore) fail(keys ...string) {
	s.mu.Lock()
	for _, k := range keys {
		if len(s.fails) < 10000 || s.fails[k] != nil {
			s.fails[k] = append(s.fails[k], time.Now())
		}
	}
	s.mu.Unlock()
}

func (s *sessionStore) gcLoop(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.mu.Lock()
			for k, v := range s.sessions {
				if now.After(v.Exp) {
					delete(s.sessions, k)
				}
			}
			for k, v := range s.fails {
				if len(v) == 0 || now.Sub(v[len(v)-1]) > 10*time.Minute {
					delete(s.fails, k)
				}
			}
			s.mu.Unlock()
		}
	}
}

// ---- request context ----------------------------------------------------------------------

type ctxKey struct{}

func withSession(r *http.Request, s session) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxKey{}, s))
}

func sessionOf(r *http.Request) session {
	s, _ := r.Context().Value(ctxKey{}).(session)
	return s
}

// ---- audit log -------------------------------------------------------------------------------

// AuditEntry records a change made in the panel or a login.
type AuditEntry struct {
	Time   time.Time `json:"time"`
	User   string    `json:"user"`
	IP     string    `json:"ip"`
	Action string    `json:"action"` // e.g. "POST /api/groups/internet" or "login"
	Detail string    `json:"detail,omitempty"`
	Status int       `json:"status"`
}

type auditLog struct {
	mu   sync.Mutex
	path string
}

const auditMax = 2 << 20 // rotate at 2 MB, keep one old file

func newAuditLog(dir string) *auditLog { return &auditLog{path: filepath.Join(dir, "audit.log")} }

func (l *auditLog) add(e AuditEntry) {
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if fi, err := os.Stat(l.path); err == nil && fi.Size() > auditMax {
		os.Rename(l.path, l.path+".1")
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return
	}
	f.Write(append(b, '\n'))
	f.Close()
}

// last returns up to n newest entries, newest first.
func (l *auditLog) last(n int) []AuditEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	var all []AuditEntry
	for _, p := range []string{l.path + ".1", l.path} {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var e AuditEntry
			if json.Unmarshal(sc.Bytes(), &e) == nil {
				all = append(all, e)
			}
		}
		f.Close()
	}
	out := make([]AuditEntry, 0, n)
	for i := len(all) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, all[i])
	}
	return out
}

// ---- users API (admin) -----------------------------------------------------------------------

type userView struct {
	Name     string `json:"name"`
	Role     string `json:"role"`
	Sessions int    `json:"sessions"`
}

func (a *App) hUsersGet(w http.ResponseWriter, r *http.Request) {
	cnt := a.sessions.count()
	var out []userView
	for _, u := range a.state.get().Users {
		out = append(out, userView{Name: u.Name, Role: u.Role, Sessions: cnt[u.Name]})
	}
	writeJSON(w, out)
}

func adminCount(us []User) int {
	n := 0
	for _, u := range us {
		if u.Role == RoleAdmin {
			n++
		}
	}
	return n
}

// hUsersSave creates a user or changes its role and/or password.
func (a *App) hUsersSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Role     string `json:"role"`
		Password string `json:"password"` // "" = keep (existing users only)
	}
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if !userNameRE.MatchString(req.Name) {
		jsonErr(w, http.StatusBadRequest, "user name: 1-32 letters, digits, . _ @ -")
		return
	}
	if roleRank(req.Role) == 0 {
		jsonErr(w, http.StatusBadRequest, "role must be admin, operator or viewer")
		return
	}
	var hash string
	if req.Password != "" {
		var err error
		if hash, err = newHash(req.Password); err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	var bad string
	err := a.state.update(func(st *State) {
		for i := range st.Users {
			if st.Users[i].Name != req.Name {
				continue
			}
			old := st.Users[i]
			st.Users[i].Role = req.Role
			if hash != "" {
				st.Users[i].Hash = hash
			}
			if adminCount(st.Users) == 0 {
				st.Users[i] = old
				bad = "at least one admin must remain"
				return
			}
			syncLegacy(st)
			return
		}
		if hash == "" {
			bad = "a password is required for a new user"
			return
		}
		if len(st.Users) >= 50 {
			bad = "too many users"
			return
		}
		st.Users = append(st.Users, User{Name: req.Name, Hash: hash, Role: req.Role})
		syncLegacy(st)
	})
	if bad != "" {
		jsonErr(w, http.StatusBadRequest, bad)
		return
	}
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.sessions.dropUser(req.Name) // new role/password applies at the next login
	a.hUsersGet(w, r)
}

func (a *App) hUsersDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if req.Name == sessionOf(r).User {
		jsonErr(w, http.StatusBadRequest, "you cannot delete yourself")
		return
	}
	var bad string
	err := a.state.update(func(st *State) {
		out := st.Users[:0:0]
		for _, u := range st.Users {
			if u.Name != req.Name {
				out = append(out, u)
			}
		}
		if adminCount(out) == 0 {
			bad = "at least one admin must remain"
			return
		}
		st.Users = out
		syncLegacy(st)
	})
	if bad != "" {
		jsonErr(w, http.StatusBadRequest, bad)
		return
	}
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.sessions.dropUser(req.Name)
	a.hUsersGet(w, r)
}

func (a *App) hAudit(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.audit.last(300)) }

func (a *App) hMe(w http.ResponseWriter, r *http.Request) {
	s := sessionOf(r)
	writeJSON(w, map[string]string{"user": s.User, "role": s.Role})
}

// auditAdd writes to the audit log and forwards to syslog when enabled.
func (a *App) auditAdd(e AuditEntry) {
	a.audit.add(e)
	a.Syslog.Audit(e)
}
