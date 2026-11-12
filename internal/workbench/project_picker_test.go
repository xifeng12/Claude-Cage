package workbench

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestProjectPickerConsumerAddsOnceAndReusesAuthorizedDirectory(t *testing.T) {
	s := testServer(t)
	s.ready, s.networkPaused = true, true
	a, _ := filepath.EvalSymlinks(t.TempDir())
	b, _ := filepath.EvalSymlinks(t.TempDir())
	s.preferences.Workspace = a
	if err := s.rememberSharedProject(a); err != nil {
		t.Fatal(err)
	}
	share := &projectShare{done: make(chan struct{})}
	s.projectShares = map[string]*projectShare{a: {done: make(chan struct{})}, b: share}
	terminal := &terminalSession{id: "existing", workspace: a}
	s.terminals.sessions = map[string]*terminalSession{terminal.id: terminal}
	config, _ := os.ReadFile(s.configPath)
	call := func(path string, add bool) string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"workspace": path, "add": add})
		w := request(s, "POST", "/api/projects/open", s.origin, string(body), true)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var result struct {
			Workspace string `json:"workspace"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result.Workspace
	}
	body, _ := json.Marshal(map[string]any{"workspace": b})
	if w := request(s, "POST", "/api/projects/open", s.origin, string(body), true); w.Code != 400 {
		t.Fatal("consumer granted an unregistered directory", w.Code, w.Body.String())
	}
	if call(b, true) != b || call(b, false) != b || call(b, true) != b {
		t.Fatal("project path changed")
	}
	alias := filepath.Join(t.TempDir(), "project-link")
	if err := os.Symlink(b, alias); err == nil {
		if call(alias, false) != b {
			t.Fatal("authorized alias did not use canonical project")
		}
	}
	projects, err := s.projectPaths()
	if err != nil || !slices.Equal(projects, []string{a, b}) {
		t.Fatal("list diverged or repeated grants", projects, err)
	}
	reloaded := testServer(t)
	reloaded.profile = s.profile
	reloaded.preferences = s.preferences
	if saved, err := reloaded.projectPaths(); err != nil || !slices.Equal(projects, saved) {
		t.Fatal("project list did not persist", saved, err)
	}
	if s.workspace() != a || s.projectShares[b] != share || terminal.closed || !s.ready || !s.networkPaused {
		t.Fatal("consumer selection changed existing context")
	}
	after, _ := os.ReadFile(s.configPath)
	if !bytes.Equal(config, after) {
		t.Fatal("project selection rewrote network configuration")
	}
}

func TestProjectPickerWorkbenchActivationPreservesOtherPreferences(t *testing.T) {
	s := testServer(t)
	s.ready = true
	root, _ := filepath.EvalSymlinks(t.TempDir())
	s.projectShares = map[string]*projectShare{root: {done: make(chan struct{})}}
	s.preferences = Preferences{Workspace: s.environmentDir(), Keyboard: "mac", AutoTimezone: true}
	original := s.preferences
	body, _ := json.Marshal(map[string]any{"workspace": root, "add": true, "activate": true})
	w := request(s, "POST", "/api/projects/open", s.origin, string(body), true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var saved Preferences
	data, err := os.ReadFile(filepath.Join(s.profile, "workbench.json"))
	if err != nil || json.Unmarshal(data, &saved) != nil {
		t.Fatal("activation was not persisted", err)
	}
	original.Workspace = root
	if s.preferences != original || saved != original {
		t.Fatal("activation changed unrelated preferences", saved, s.preferences)
	}
}

func TestProjectPickerRejectsLifecycleRacesAndUntrustedRequests(t *testing.T) {
	s := testServer(t)
	s.ready = true
	root, _ := filepath.EvalSymlinks(t.TempDir())
	body, _ := json.Marshal(map[string]any{"workspace": root, "add": true})
	for _, c := range []struct {
		origin string
		auth   bool
		code   int
	}{{s.origin, false, 401}, {"https://example.com", true, 403}} {
		if w := request(s, "POST", "/api/projects/open", c.origin, string(body), c.auth); w.Code != c.code {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	s.op.Lock()
	for _, c := range []struct{ endpoint, body string }{
		{"/api/projects/open", string(body)},
		{"/api/input/files/directory", `{"target":"desktop","id":"` + testBrowserFileID + `","workspace":"` + filepath.ToSlash(root) + `"}`},
	} {
		w := request(s, "POST", c.endpoint, s.origin, c.body, true)
		if w.Code != 409 {
			s.op.Unlock()
			t.Fatal("project access raced lifecycle operation", w.Code, w.Body.String())
		}
	}
	s.op.Unlock()
	if _, err := os.Stat(filepath.Join(s.profile, "projects.json")); !os.IsNotExist(err) {
		t.Fatal("busy request granted project access")
	}
	s.ready = false
	if w := request(s, "POST", "/api/projects/open", s.origin, string(body), true); w.Code != 409 {
		t.Fatal(w.Code, w.Body.String())
	}
	s.account.lock()
	if w := request(s, "POST", "/api/projects/open", s.origin, string(body), true); w.Code != 423 {
		t.Fatal("locked account could authorize project", w.Code)
	}
}

// A short monitor operation should not cause an authorized project open to
// fail immediately with HTTP 409.
func TestProjectPickerWaitsForTransientOperationLock(t *testing.T) {
	s := testServer(t)
	s.ready = true
	root, _ := filepath.EvalSymlinks(t.TempDir())
	s.projectShares = map[string]*projectShare{root: {done: make(chan struct{})}}
	body, _ := json.Marshal(map[string]any{"workspace": root, "add": true})

	s.op.Lock()
	released := make(chan struct{})
	go func() {
		time.Sleep(90 * time.Millisecond)
		s.op.Unlock()
		close(released)
	}()
	w := request(s, "POST", "/api/projects/open", s.origin, string(body), true)
	<-released
	if w.Code != 200 {
		t.Fatalf("brief monitor lock rejected project access: %d %s", w.Code, w.Body.String())
	}
}
