package gostapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gost-panel/internal/store"
)

func TestSavedConfigKeepsAPIEndpoint(t *testing.T) {
	for _, endpoint := range []string{"127.0.0.1:18080", "127.0.0.1:19081", "[::1]:18080"} {
		client := New("http://"+endpoint, "test-user", "test-only", "")
		config := client.buildFullConfig(nil)
		api := config["api"].(map[string]any)
		if api["addr"] != endpoint {
			t.Fatalf("API listen address=%v; want %s", api["addr"], endpoint)
		}
	}
}

func TestListNamesAcceptsEmptyLists(t *testing.T) {
	for _, response := range []string{
		`{"data":{"list":null}}`,
		`{"data":{"list":[]}}`,
		`[]`,
	} {
		names, err := listNames([]byte(response))
		if err != nil {
			t.Fatalf("listNames(%s): %v", response, err)
		}
		if len(names) != 0 {
			t.Fatalf("listNames(%s)=%v; want an empty set", response, names)
		}
	}
}

func TestListNamesRejectsMalformedResponses(t *testing.T) {
	for _, response := range []string{
		`not-json`,
		`{"unexpected":true}`,
		`{"data":{"list":"not-a-list"}}`,
	} {
		if _, err := listNames([]byte(response)); err == nil {
			t.Fatalf("listNames(%s) unexpectedly succeeded", response)
		}
	}
}

func TestAllocateRuleNamesDisambiguatesConflicts(t *testing.T) {
	rules := []store.Rule{
		{ID: 35, Name: "new", Type: "forward", Enabled: 1},
		{ID: 17, Name: "imported", Type: "forward", GostName: "svc-35", Enabled: 1},
		{ID: 99, Name: "disabled", Type: "forward", GostName: "svc-35", Enabled: 0},
	}

	names := allocateRuleNames(rules)
	if got := names[17].service; got != "svc-35" {
		t.Fatalf("explicit service name=%q; want svc-35", got)
	}
	if got := names[35].service; got != "svc-35-35" {
		t.Fatalf("generated service name=%q; want svc-35-35", got)
	}
	if got := names[17].chain; got != "chn-35" {
		t.Fatalf("explicit chain name=%q; want chn-35", got)
	}
	if got := names[35].chain; got != "chn-35-35" {
		t.Fatalf("generated chain name=%q; want chn-35-35", got)
	}
	if got := names[17].node; got != "n-35" {
		t.Fatalf("explicit node name=%q; want n-35", got)
	}
	if got := names[35].node; got != "n-35-35" {
		t.Fatalf("generated node name=%q; want n-35-35", got)
	}
	if _, ok := names[99]; ok {
		t.Fatal("disabled rule unexpectedly received a runtime name")
	}
}

func TestApplyDoesNotOverwriteRulesWithConflictingNames(t *testing.T) {
	var serviceNames []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeNameList(w, nil)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/config/services" {
			var body struct {
				Name string `json:"name"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode service request: %v", err)
			}
			serviceNames = append(serviceNames, body.Name)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	baseDir := t.TempDir()
	st, err := store.Open(filepath.Join(baseDir, "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.CreateRule(store.Rule{
		Name: "imported", Type: "forward", Proto: "tcp", ListenPort: 23456,
		TargetHost: "127.0.0.1", TargetPort: 80, GostName: "svc-2", Enabled: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateRule(store.Rule{
		Name: "generated", Type: "forward", Proto: "tcp", ListenPort: 23457,
		TargetHost: "127.0.0.1", TargetPort: 81, Enabled: 1,
	}); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(baseDir, "gost.json")
	code, msg := New(server.URL, "test-user", "test-password", configPath).Apply(st)
	if code != http.StatusOK {
		t.Fatalf("Apply status=%d, message=%q; want %d", code, msg, http.StatusOK)
	}
	if len(serviceNames) != 2 {
		t.Fatalf("service POST count=%d; want 2", len(serviceNames))
	}
	got := map[string]bool{}
	for _, name := range serviceNames {
		got[name] = true
	}
	for _, name := range []string{"svc-2", "svc-2-2"} {
		if !got[name] {
			t.Fatalf("service names=%v; missing %q", serviceNames, name)
		}
	}

	config, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(config), `"name": "svc-2"`) || !strings.Contains(string(config), `"name": "svc-2-2"`) {
		t.Fatalf("persisted config lost a conflicting rule: %s", config)
	}
}

func TestApplyStopsAndPreservesConfigOnUpstreamFailure(t *testing.T) {
	tests := []struct {
		name              string
		ruleType          string
		services          []string
		chains            []string
		failMethod        string
		failPath          string
		wantMutationCount int
	}{
		{name: "list services", failMethod: http.MethodGet, failPath: "/config/services"},
		{name: "list chains", services: []string{"stale-svc"}, failMethod: http.MethodGet, failPath: "/config/chains"},
		{name: "delete service", services: []string{"orphan-svc"}, failMethod: http.MethodDelete, failPath: "/config/services/orphan-svc", wantMutationCount: 1},
		{name: "delete chain", chains: []string{"orphan-chain"}, failMethod: http.MethodDelete, failPath: "/config/chains/orphan-chain", wantMutationCount: 1},
		{name: "create chain", ruleType: "tunnel", failMethod: http.MethodPost, failPath: "/config/chains", wantMutationCount: 1},
		{name: "update chain", ruleType: "tunnel", services: []string{"svc-1"}, chains: []string{"chn-1"}, failMethod: http.MethodPut, failPath: "/config/chains/chn-1", wantMutationCount: 1},
		{name: "create service", ruleType: "forward", failMethod: http.MethodPost, failPath: "/config/services", wantMutationCount: 1},
		{name: "update service", ruleType: "forward", services: []string{"svc-1"}, failMethod: http.MethodPut, failPath: "/config/services/svc-1", wantMutationCount: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			failedRequestSeen := false
			mutationCount := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					mutationCount++
				}
				if r.Method == tt.failMethod && r.URL.Path == tt.failPath {
					failedRequestSeen = true
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if r.Method == http.MethodGet {
					switch r.URL.Path {
					case "/config/services":
						writeNameList(w, tt.services)
						return
					case "/config/chains":
						writeNameList(w, tt.chains)
						return
					}
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			baseDir := t.TempDir()
			st, err := store.Open(filepath.Join(baseDir, "panel.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			if tt.ruleType != "" {
				_, err := st.CreateRule(store.Rule{
					Name: "test", Type: tt.ruleType, Proto: "tcp", ListenPort: 23456,
					TargetHost: "127.0.0.1", TargetPort: 80, TunnelProto: "ws", Enabled: 1,
				})
				if err != nil {
					t.Fatal(err)
				}
			}

			configPath := filepath.Join(baseDir, "gost.json")
			const previousConfig = "previous config must be preserved"
			if err := os.WriteFile(configPath, []byte(previousConfig), 0o600); err != nil {
				t.Fatal(err)
			}
			client := New(server.URL, "test-user", "test-password", configPath)
			code, msg := client.Apply(st)
			if code != http.StatusBadGateway {
				t.Fatalf("Apply status=%d, message=%q; want %d", code, msg, http.StatusBadGateway)
			}
			if !failedRequestSeen {
				t.Fatalf("expected failing request %s %s", tt.failMethod, tt.failPath)
			}
			if mutationCount != tt.wantMutationCount {
				t.Fatalf("mutation request count=%d; want %d", mutationCount, tt.wantMutationCount)
			}
			if !strings.Contains(msg, tt.failPath) {
				t.Fatalf("failure message %q does not identify %s", msg, tt.failPath)
			}
			config, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(config) != previousConfig {
				t.Fatalf("failed sync changed saved config to %q", config)
			}
		})
	}
}

func TestApplyAcceptsSuccessfulMutationStatuses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeNameList(w, nil)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	baseDir := t.TempDir()
	st, err := store.Open(filepath.Join(baseDir, "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.CreateRule(store.Rule{
		Name: "forward", Type: "forward", Proto: "tcp", ListenPort: 23456,
		TargetHost: "127.0.0.1", TargetPort: 80, Enabled: 1,
	}); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(baseDir, "gost.json")
	code, msg := New(server.URL, "test-user", "test-password", configPath).Apply(st)
	if code != http.StatusOK {
		t.Fatalf("Apply status=%d, message=%q; want %d", code, msg, http.StatusOK)
	}
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("successful sync did not persist config: %v", err)
	}
}

func TestApplyReportsConfigPersistenceFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeNameList(w, nil)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	baseDir := t.TempDir()
	st, err := store.Open(filepath.Join(baseDir, "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	configPath := filepath.Join(baseDir, "missing", "gost.json")
	code, msg := New(server.URL, "test-user", "test-password", configPath).Apply(st)
	if code != http.StatusInternalServerError {
		t.Fatalf("Apply status=%d, message=%q; want %d", code, msg, http.StatusInternalServerError)
	}
	if !strings.Contains(msg, "写入 gost 配置失败") {
		t.Fatalf("unexpected persistence failure message: %q", msg)
	}
}

func writeNameList(w http.ResponseWriter, names []string) {
	_, _ = fmt.Fprint(w, `{"data":{"list":[`)
	for i, name := range names {
		if i > 0 {
			_, _ = fmt.Fprint(w, ", ")
		}
		_, _ = fmt.Fprintf(w, `{"name":%q}`, name)
	}
	_, _ = fmt.Fprint(w, "]}}")
}
