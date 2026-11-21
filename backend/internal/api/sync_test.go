package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"gost-panel/internal/auth"
	"gost-panel/internal/config"
	"gost-panel/internal/gostapi"
	"gost-panel/internal/store"
)

func TestRuleMutationsReportGostSyncFailure(t *testing.T) {
	tests := []struct {
		name              string
		method            string
		path              string
		body              any
		initialRule       *store.Rule
		services          []string
		failMethod        string
		failPath          string
		wantRuleCount     int
		wantUpdatedRemark string
	}{
		{
			name:   "create",
			method: http.MethodPost,
			path:   "/api/rules",
			body: map[string]any{
				"name": "created", "type": "forward", "proto": "tcp", "listen_port": 0,
				"target_host": "127.0.0.1", "target_port": 80,
			},
			failMethod: http.MethodPost, failPath: "/config/services", wantRuleCount: 1,
		},
		{
			name:   "update",
			method: http.MethodPut,
			path:   "/api/rules/1",
			body:   map[string]any{"remark": "saved despite sync failure"},
			initialRule: &store.Rule{
				Name: "existing", Type: "forward", Proto: "tcp", ListenPort: 23456,
				TargetHost: "127.0.0.1", TargetPort: 80, Enabled: 1,
			},
			services:   []string{"svc-1"},
			failMethod: http.MethodPut, failPath: "/config/services/svc-1",
			wantRuleCount: 1, wantUpdatedRemark: "saved despite sync failure",
		},
		{
			name:   "delete",
			method: http.MethodDelete,
			path:   "/api/rules/1",
			initialRule: &store.Rule{
				Name: "existing", Type: "forward", Proto: "tcp", ListenPort: 23456,
				TargetHost: "127.0.0.1", TargetPort: 80, Enabled: 1,
			},
			services:   []string{"svc-1"},
			failMethod: http.MethodDelete, failPath: "/config/services/svc-1",
			wantRuleCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			failedRequestSeen := false
			gostServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == tt.failMethod && r.URL.Path == tt.failPath {
					failedRequestSeen = true
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if r.Method == http.MethodGet {
					switch r.URL.Path {
					case "/config/services":
						writeAPITestNameList(w, tt.services)
						return
					case "/config/chains":
						writeAPITestNameList(w, nil)
						return
					}
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer gostServer.Close()

			baseDir := t.TempDir()
			st, err := store.Open(filepath.Join(baseDir, "panel.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			if tt.initialRule != nil {
				if _, err := st.CreateRule(*tt.initialRule); err != nil {
					t.Fatal(err)
				}
			}

			manager := &auth.Manager{Secret: "sync-tests-only", ExpireHours: 1}
			token, err := manager.CreateToken("test-user")
			if err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{BaseDir: baseDir, PanelUser: "test-user", PanelPass: "test-password"}
			gost := gostapi.New(gostServer.URL, "test-user", "test-password", filepath.Join(baseDir, "gost.json"))
			s := NewServer(cfg, st, gost, manager)

			bodyValue := tt.body
			if tt.name == "create" {
				bodyValue = map[string]any{
					"name": "created", "type": "forward", "proto": "tcp", "listen_port": availableTestPort(t),
					"target_host": "127.0.0.1", "target_port": 80,
				}
			}
			bodyText := ""
			if tt.body != nil {
				data, err := json.Marshal(bodyValue)
				if err != nil {
					t.Fatal(err)
				}
				bodyText = string(data)
			}
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(bodyText))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			s.router.ServeHTTP(w, req)

			var response struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode response %q: %v", w.Body.String(), err)
			}
			if w.Code != http.StatusBadGateway || response.Code != 50200 {
				t.Fatalf("response status=%d body=%s; want HTTP 502", w.Code, w.Body)
			}
			if !strings.Contains(response.Message, "面板规则数据已更新") || !strings.Contains(response.Message, "同步到 GOST 失败") {
				t.Fatalf("unexpected failure message: %q", response.Message)
			}
			if !failedRequestSeen {
				t.Fatalf("expected failing request %s %s", tt.failMethod, tt.failPath)
			}

			rules, err := st.ListRules()
			if err != nil {
				t.Fatal(err)
			}
			if len(rules) != tt.wantRuleCount {
				t.Fatalf("stored rule count=%d; want %d", len(rules), tt.wantRuleCount)
			}
			if tt.wantUpdatedRemark != "" && rules[0].Remark != tt.wantUpdatedRemark {
				t.Fatalf("stored remark=%q; want %q", rules[0].Remark, tt.wantUpdatedRemark)
			}
		})
	}
}

func writeAPITestNameList(w http.ResponseWriter, names []string) {
	_, _ = fmt.Fprint(w, `{"data":{"list":[`)
	for i, name := range names {
		if i > 0 {
			_, _ = fmt.Fprint(w, ", ")
		}
		_, _ = fmt.Fprintf(w, `{"name":%q}`, name)
	}
	_, _ = fmt.Fprint(w, "]}}")
}

func availableTestPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}
