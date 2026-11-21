package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/takobas/vartadns/internal/filter"
	"github.com/takobas/vartadns/internal/policy"
)

// catState is one loaded category list.
type catState struct {
	eng     *filter.Engine
	Rules   int       `json:"rules"`
	Updated time.Time `json:"updated"`
	Error   string    `json:"error,omitempty"`
}

func (a *App) categoryURL(c policy.Category) string {
	if a.cfg.Profile == "light" && c.LightURL != "" {
		return c.LightURL
	}
	return c.URL
}

// loadCategories (re)loads every category used by at least one group and
// drops the others, so unused categories cost no memory.
func (a *App) loadCategories(ctx context.Context, network bool) {
	a.catMu.Lock()
	defer a.catMu.Unlock()
	used := map[string]bool{}
	if st := a.Resolver.PolicyState(); st != nil {
		for _, c := range st.UsedCategories() {
			used[c] = true
		}
	}
	old := a.categories.Load()
	next := map[string]*catState{}
	for _, c := range policy.Categories {
		if !used[c.ID] {
			continue
		}
		if !network && old != nil && (*old)[c.ID] != nil && (*old)[c.ID].eng != nil {
			next[c.ID] = (*old)[c.ID] // already loaded, keep it
			continue
		}
		cs := &catState{}
		spec := ListSpec{Name: "category " + c.ID, URL: a.categoryURL(c), Enabled: true}
		rc, err := a.openList(ctx, spec, network || !fileExists(a.listCachePath(spec)))
		if err != nil {
			cs.Error = err.Error()
			if old != nil && (*old)[c.ID] != nil {
				cs = (*old)[c.ID] // keep the previous copy on failure
			}
			next[c.ID] = cs
			continue
		}
		b := filter.NewBuilder(0)
		_, perr := b.Add(c.Name, rc, false)
		rc.Close()
		eng := filter.New()
		b.Apply(eng)
		cs.eng = eng
		cs.Rules, _ = b.Counts()
		if perr != nil {
			cs.Error = perr.Error()
		}
		if fi, err := os.Stat(a.listCachePath(spec)); err == nil {
			cs.Updated = fi.ModTime()
		}
		next[c.ID] = cs
		log.Printf("category %s loaded: %d rules", c.ID, cs.Rules)
	}
	a.categories.Store(&next)
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// categoryChecker reads the current category engines (lock-free).
func (a *App) categoryChecker(category, name string) (string, bool) {
	m := a.categories.Load()
	if m == nil {
		return "", false
	}
	cs := (*m)[category]
	if cs == nil || cs.eng == nil {
		return "", false
	}
	if r := cs.eng.Check(name); r.Verdict == filter.Blocked {
		return r.Rule, true
	}
	return "", false
}

// applyPolicy compiles the saved groups into the resolver and loads the
// categories they need (in the background when downloads are required).
func (a *App) applyPolicy(ctx context.Context, background bool) error {
	p, err := policy.Compile(a.state.get().Groups)
	if err != nil {
		a.Resolver.SetPolicy(nil, nil)
		return err
	}
	a.Resolver.SetPolicy(p, a.categoryChecker)
	if background {
		go func() {
			// Never load categories in parallel with a list rebuild: on small
			// routers two builders at once would double the memory peak.
			a.listMu.Lock()
			defer a.listMu.Unlock()
			a.loadCategories(context.Background(), false)
			runtime.GC()
		}()
	} else {
		a.loadCategories(ctx, false)
	}
	return nil
}

func newGroupID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---- HTTP handlers ------------------------------------------------------------------------

type groupView struct {
	policy.Group
	OffActive         bool `json:"off_active"`
	RestrictionActive bool `json:"restrictions_active"`
}

func (a *App) hGroupsGet(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	groups := a.state.get().Groups
	views := make([]groupView, 0, len(groups))
	var compiled *policy.Policy
	if p, err := policy.Compile(groups); err == nil {
		compiled = p
	}
	for i, g := range groups {
		v := groupView{Group: g}
		if compiled != nil {
			gp := compiled.Groups()[i]
			v.OffActive, _ = gp.InternetOff(now)
			v.RestrictionActive = gp.RestrictionsActive(now)
		}
		for _, sl := range []*[]string{&v.Members, &v.Services, &v.Categories} {
			if *sl == nil {
				*sl = []string{}
			}
		}
		if v.Schedule.Windows == nil {
			v.Schedule.Windows = []policy.Window{}
		}
		if v.Block == nil {
			v.Block = []string{}
		}
		if v.Allow == nil {
			v.Allow = []string{}
		}
		views = append(views, v)
	}
	type svc struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Domains int    `json:"domains"`
		Note    string `json:"note,omitempty"`
	}
	svcs := make([]svc, 0, len(policy.Services))
	for _, s := range policy.Services {
		svcs = append(svcs, svc{s.ID, s.Name, len(s.Domains), s.Note})
	}
	type cat struct {
		ID   string    `json:"id"`
		Name string    `json:"name"`
		URL  string    `json:"url"`
		Load *catState `json:"load,omitempty"`
	}
	cats := make([]cat, 0, len(policy.Categories))
	loaded := a.categories.Load()
	for _, c := range policy.Categories {
		v := cat{ID: c.ID, Name: c.Name, URL: a.categoryURL(c)}
		if loaded != nil {
			v.Load = (*loaded)[c.ID]
		}
		cats = append(cats, v)
	}
	writeJSON(w, map[string]any{"groups": views, "services": svcs, "categories": cats,
		"profile": a.cfg.Profile, "now": now})
}

// saveGroups validates the full new group list, persists and applies it.
func (a *App) saveGroups(w http.ResponseWriter, r *http.Request, mutate func([]policy.Group) ([]policy.Group, error)) {
	var resultErr error
	err := a.state.update(func(s *State) {
		groups, err := mutate(append([]policy.Group(nil), s.Groups...))
		if err == nil {
			for i := range groups {
				if err = policy.Normalize(&groups[i]); err != nil {
					break
				}
			}
		}
		if err == nil {
			_, err = policy.Compile(groups)
		}
		if err != nil {
			resultErr = err
			return
		}
		s.Groups = groups
	})
	if resultErr != nil {
		jsonErr(w, http.StatusBadRequest, resultErr.Error())
		return
	}
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := a.applyPolicy(r.Context(), true); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a.hGroupsGet(w, r)
}

var errGroupNotFound = errors.New("group not found")

func findGroup(groups []policy.Group, id string) int {
	for i := range groups {
		if groups[i].ID == id {
			return i
		}
	}
	return -1
}

func (a *App) hGroupsCreate(w http.ResponseWriter, r *http.Request) {
	var g policy.Group
	if err := readJSON(r, &g); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	// A new group never blocks anything until the admin enables it.
	g = policy.Group{ID: newGroupID(), Name: g.Name, Members: g.Members}
	a.saveGroups(w, r, func(gs []policy.Group) ([]policy.Group, error) {
		return append(gs, g), nil
	})
}

func (a *App) hGroupsUpdate(w http.ResponseWriter, r *http.Request) {
	var g policy.Group
	if err := readJSON(r, &g); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	a.saveGroups(w, r, func(gs []policy.Group) ([]policy.Group, error) {
		i := findGroup(gs, g.ID)
		if i < 0 {
			return nil, errGroupNotFound
		}
		// The kill switch has its own endpoint; keep its state.
		g.InternetOff, g.OffUntil = gs[i].InternetOff, gs[i].OffUntil
		gs[i] = g
		return gs, nil
	})
}

func (a *App) hGroupsDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	a.saveGroups(w, r, func(gs []policy.Group) ([]policy.Group, error) {
		i := findGroup(gs, req.ID)
		if i < 0 {
			return nil, errGroupNotFound
		}
		return append(gs[:i], gs[i+1:]...), nil
	})
}

func (a *App) hGroupsMove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID  string `json:"id"`
		Dir int    `json:"dir"` // -1 up, +1 down
	}
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	a.saveGroups(w, r, func(gs []policy.Group) ([]policy.Group, error) {
		i := findGroup(gs, req.ID)
		if i < 0 {
			return nil, errGroupNotFound
		}
		j := i + req.Dir
		if req.Dir != -1 && req.Dir != 1 || j < 0 || j >= len(gs) {
			return gs, nil
		}
		gs[i], gs[j] = gs[j], gs[i]
		return gs, nil
	})
}

func (a *App) hGroupsInternet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID      string `json:"id"`
		Off     bool   `json:"off"`
		Minutes int    `json:"minutes"` // 0 = until switched on
	}
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	a.saveGroups(w, r, func(gs []policy.Group) ([]policy.Group, error) {
		i := findGroup(gs, req.ID)
		if i < 0 {
			return nil, errGroupNotFound
		}
		gs[i].InternetOff = req.Off
		gs[i].OffUntil = time.Time{}
		if req.Off && req.Minutes > 0 {
			gs[i].OffUntil = time.Now().Add(time.Duration(req.Minutes) * time.Minute)
		}
		return gs, nil
	})
}

// hGroupsRule adds a block/allow domain to a group (used from the query log).
func (a *App) hGroupsRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     string `json:"id"`
		Kind   string `json:"kind"`
		Domain string `json:"domain"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	d := filter.Normalize(req.Domain)
	if d == "" || (req.Kind != "block" && req.Kind != "allow") {
		jsonErr(w, http.StatusBadRequest, "invalid domain or kind")
		return
	}
	a.saveGroups(w, r, func(gs []policy.Group) ([]policy.Group, error) {
		i := findGroup(gs, req.ID)
		if i < 0 {
			return nil, errGroupNotFound
		}
		if req.Kind == "block" {
			gs[i].Block = append(append([]string(nil), gs[i].Block...), d)
			gs[i].Allow = editList(gs[i].Allow, d, false)
		} else {
			gs[i].Allow = append(append([]string(nil), gs[i].Allow...), d)
			gs[i].Block = editList(gs[i].Block, d, false)
		}
		return gs, nil
	})
}
