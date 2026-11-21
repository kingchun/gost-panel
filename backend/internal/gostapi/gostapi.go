// Package gostapi 封装 gost v3 Web API 调用与配置编译（热更新 + 持久化）。
package gostapi

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"gost-panel/internal/store"
)

// Client 是 gost Web API 客户端。
type Client struct {
	BaseURL    string
	User, Pass string
	ConfigPath string // 持久化写回的 gost 配置文件路径
	HTTPClient *http.Client
}

// New 创建客户端。
func New(baseURL, user, pass, configPath string) *Client {
	return &Client{
		BaseURL:    baseURL,
		User:       user,
		Pass:       pass,
		ConfigPath: configPath,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// Request 调用 gost Web API，返回 (httpCode, body)。
func (c *Client) Request(method, path string, body any) (int, json.RawMessage) {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, c.BaseURL+path, rdr)
	if err != nil {
		return 0, nil
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(
		[]byte(c.User+":"+c.Pass)))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if len(raw) == 0 {
		return resp.StatusCode, nil
	}
	return resp.StatusCode, json.RawMessage(raw)
}

// listNames 从 /config/services、/config/chains 提取名字集合，
// 兼容 {"data":{"list":[...]}} 与裸数组两种返回格式。
func listNames(raw json.RawMessage) (map[string]bool, error) {
	type obj struct {
		Name string `json:"name"`
	}
	var wrapped struct {
		Data *struct {
			List json.RawMessage `json:"list"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &wrapped); err == nil && wrapped.Data != nil && wrapped.Data.List != nil {
		var list []obj
		if err := json.Unmarshal(wrapped.Data.List, &list); err != nil {
			return nil, fmt.Errorf("列表字段格式无效")
		}
		names := make(map[string]bool, len(list))
		for _, o := range list {
			names[o.Name] = true
		}
		return names, nil
	}
	var list []obj
	if err := json.Unmarshal(raw, &list); err == nil && list != nil {
		names := make(map[string]bool, len(list))
		for _, o := range list {
			names[o.Name] = true
		}
		return names, nil
	}
	return nil, fmt.Errorf("响应格式无效")
}

func handlerTypeOf(r store.Rule) string {
	if r.Proto == "udp" {
		return "udp"
	}
	return "tcp"
}

type ruleNames struct {
	service string
	chain   string
	node    string
}

// serviceBaseName 返回规则的首选 gost 服务名。
func serviceBaseName(r store.Rule) string {
	if r.GostName != "" {
		return r.GostName
	}
	return fmt.Sprintf("svc-%d", r.ID)
}

// chainBaseName 返回规则的首选 gost 链名。
func chainBaseName(r store.Rule) string {
	if r.GostName != "" {
		// svc-N -> chn-N
		return strings.Replace(r.GostName, "svc-", "chn-", 1)
	}
	return fmt.Sprintf("chn-%d", r.ID)
}

// nodeBaseName 返回规则的首选 gost 节点名。
func nodeBaseName(r store.Rule) string {
	if r.GostName != "" {
		return strings.Replace(r.GostName, "svc-", "n-", 1)
	}
	return fmt.Sprintf("n-%d", r.ID)
}

// allocateRuleNames 为启用规则分配稳定且不重复的 service、chain、node 名称。
// 显式保存的 GostName 优先保留；同名时按规则 ID 决定保留者，后续规则追加 ID 后缀。
func allocateRuleNames(rules []store.Rule) map[int]ruleNames {
	ordered := append([]store.Rule(nil), rules...)
	sort.SliceStable(ordered, func(i, j int) bool {
		iExplicit := ordered[i].GostName != ""
		jExplicit := ordered[j].GostName != ""
		if iExplicit != jExplicit {
			return iExplicit
		}
		if ordered[i].ID != ordered[j].ID {
			return ordered[i].ID < ordered[j].ID
		}
		if ordered[i].GostName != ordered[j].GostName {
			return ordered[i].GostName < ordered[j].GostName
		}
		return ordered[i].Name < ordered[j].Name
	})

	usedServices := map[string]bool{}
	usedChains := map[string]bool{}
	usedNodes := map[string]bool{}
	allocated := make(map[int]ruleNames, len(ordered))
	for _, r := range ordered {
		if r.Enabled == 0 {
			continue
		}
		allocated[r.ID] = ruleNames{
			service: uniqueName(serviceBaseName(r), r.ID, usedServices),
			chain:   uniqueName(chainBaseName(r), r.ID, usedChains),
			node:    uniqueName(nodeBaseName(r), r.ID, usedNodes),
		}
	}
	return allocated
}

func uniqueName(base string, id int, used map[string]bool) string {
	if !used[base] {
		used[base] = true
		return base
	}

	candidate := fmt.Sprintf("%s-%d", base, id)
	for suffix := 2; used[candidate]; suffix++ {
		candidate = fmt.Sprintf("%s-%d-%d", base, id, suffix)
	}
	used[candidate] = true
	return candidate
}

// svcName 返回单条规则的首选服务名，保留给客户端命令等单规则调用。
func svcName(r store.Rule) string { return serviceBaseName(r) }

// chainName 返回单条规则的首选链名。
func chainName(r store.Rule) string { return chainBaseName(r) }

// nodeName 返回单条规则的首选节点名。
func nodeName(r store.Rule) string { return nodeBaseName(r) }

// buildTunnel 构造隧道规则对应的 chain + service。
func buildTunnel(r store.Rule) (chain, svc map[string]any) {
	return buildTunnelNamed(r, ruleNames{
		service: svcName(r),
		chain:   chainName(r),
		node:    nodeName(r),
	})
}

func buildTunnelNamed(r store.Rule, names ruleNames) (chain, svc map[string]any) {
	sname := names.service
	cname := names.chain
	nname := names.node
	node := map[string]any{
		"name":      nname,
		"addr":      fmt.Sprintf("%s:%d", r.TargetHost, r.TargetPort),
		"connector": map[string]any{"type": "tcp"},
		"dialer":    map[string]any{"type": "tcp"},
	}
	chain = map[string]any{
		"name": cname,
		"hops": []any{map[string]any{
			"name":  "hop-" + nname,
			"nodes": []any{node},
		}},
	}
	listener := map[string]any{"type": r.TunnelProto}
	if r.TunnelProto == "ws" && r.TunnelPath != "" {
		listener = map[string]any{"type": "ws", "metadata": map[string]any{"path": r.TunnelPath}}
	}
	handler := map[string]any{"type": "auto", "chain": cname}
	if r.TunnelUser != "" {
		handler["auth"] = map[string]any{"username": r.TunnelUser, "password": r.TunnelPass}
	}
	svc = map[string]any{
		"name":     sname,
		"addr":     fmt.Sprintf(":%d", r.ListenPort),
		"handler":  handler,
		"listener": listener,
	}
	return chain, svc
}

// buildForward 构造普通端口转发 service。
func buildForward(r store.Rule) map[string]any {
	return buildForwardNamed(r, ruleNames{
		service: svcName(r),
		node:    nodeName(r),
	})
}

func buildForwardNamed(r store.Rule, names ruleNames) map[string]any {
	ht := handlerTypeOf(r)
	return map[string]any{
		"name":     names.service,
		"addr":     fmt.Sprintf(":%d", r.ListenPort),
		"handler":  map[string]any{"type": ht},
		"listener": map[string]any{"type": ht},
		"forwarder": map[string]any{
			"nodes": []any{map[string]any{
				"name": names.node,
				"addr": fmt.Sprintf("%s:%d", r.TargetHost, r.TargetPort),
			}},
		},
	}
}

// buildFullConfig 生成完整 gost 配置（services + chains + api），用于持久化。
func (c *Client) buildFullConfig(rules []store.Rule) map[string]any {
	// 与面板实际连接的 API 地址一致，避免保存规则后把本机 API 改成公网监听。
	apiAddr := "127.0.0.1:18080"
	if endpoint, err := url.Parse(c.BaseURL); err == nil && endpoint.Host != "" {
		apiAddr = endpoint.Host
	}
	services := []any{}
	chains := []any{}
	names := allocateRuleNames(rules)
	for _, r := range rules {
		if r.Enabled == 0 {
			continue
		}
		ruleName, ok := names[r.ID]
		if !ok {
			continue
		}
		if r.Type == "tunnel" {
			ch, svc := buildTunnelNamed(r, ruleName)
			chains = append(chains, ch)
			services = append(services, svc)
		} else {
			services = append(services, buildForwardNamed(r, ruleName))
		}
	}
	return map[string]any{
		"api": map[string]any{
			"addr": apiAddr,
			"auth": map[string]any{"username": c.User, "password": c.Pass},
		},
		"services": services,
		"chains":   chains,
	}
}

// Apply 把数据库规则同步到 gost（对象级热更新，不断流），并持久化配置文件。
func (c *Client) Apply(st *store.Store) (int, string) {
	rules, err := st.ListRules()
	if err != nil {
		return http.StatusInternalServerError, "读取规则失败: " + err.Error()
	}

	code, raw := c.Request("GET", "/config/services", nil)
	if code != http.StatusOK {
		return http.StatusBadGateway, fmt.Sprintf("gost API 查询服务列表 /config/services 失败 (%d)", code)
	}
	existingSvc, err := listNames(raw)
	if err != nil {
		return http.StatusBadGateway, "gost API 服务列表响应无效: " + err.Error()
	}
	code, raw = c.Request("GET", "/config/chains", nil)
	if code != http.StatusOK {
		return http.StatusBadGateway, fmt.Sprintf("gost API 查询转发链列表 /config/chains 失败 (%d)", code)
	}
	existingChain, err := listNames(raw)
	if err != nil {
		return http.StatusBadGateway, "gost API 转发链列表响应无效: " + err.Error()
	}

	wantedSvc := map[string]map[string]any{}
	wantedChain := map[string]map[string]any{}
	names := allocateRuleNames(rules)
	for _, r := range rules {
		if r.Enabled == 0 {
			continue
		}
		ruleName, ok := names[r.ID]
		if !ok {
			continue
		}
		sname := ruleName.service
		cname := ruleName.chain
		if r.Type == "tunnel" {
			ch, svc := buildTunnelNamed(r, ruleName)
			wantedChain[cname] = ch
			wantedSvc[sname] = svc
		} else {
			wantedSvc[sname] = buildForwardNamed(r, ruleName)
		}
	}

	// 删除多余服务/链
	for name := range existingSvc {
		if _, ok := wantedSvc[name]; !ok {
			path := "/config/services/" + name
			if code, _ := c.Request("DELETE", path, nil); !isSuccessfulStatus(code) {
				return http.StatusBadGateway, fmt.Sprintf("gost API DELETE %s 失败 (%d)", path, code)
			}
		}
	}
	for name := range existingChain {
		if _, ok := wantedChain[name]; !ok {
			path := "/config/chains/" + name
			if code, _ := c.Request("DELETE", path, nil); !isSuccessfulStatus(code) {
				return http.StatusBadGateway, fmt.Sprintf("gost API DELETE %s 失败 (%d)", path, code)
			}
		}
	}
	// 新增/更新链与服务
	for name, ch := range wantedChain {
		method := "POST"
		path := "/config/chains"
		if existingChain[name] {
			method = "PUT"
			path += "/" + name
		}
		if code, _ := c.Request(method, path, ch); !isSuccessfulStatus(code) {
			return http.StatusBadGateway, fmt.Sprintf("gost API %s %s（转发链 %q）失败 (%d)", method, path, name, code)
		}
	}
	for name, svc := range wantedSvc {
		method := "POST"
		path := "/config/services"
		if existingSvc[name] {
			method = "PUT"
			path += "/" + name
		}
		if code, _ := c.Request(method, path, svc); !isSuccessfulStatus(code) {
			return http.StatusBadGateway, fmt.Sprintf("gost API %s %s（服务 %q）失败 (%d)", method, path, name, code)
		}
	}

	// 持久化：写回 gost 配置文件，防止 gost 重启后丢失
	if err := c.persist(rules); err != nil {
		return http.StatusInternalServerError, "写入 gost 配置失败: " + err.Error()
	}
	return http.StatusOK, fmt.Sprintf("已同步 %d 条规则", len(wantedSvc))
}

func isSuccessfulStatus(code int) bool {
	return code >= http.StatusOK && code < http.StatusMultipleChoices
}

func (c *Client) persist(rules []store.Rule) error {
	b, err := json.MarshalIndent(c.buildFullConfig(rules), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.ConfigPath, b, 0o600)
}

// ServiceCount 查询 gost 当前 service 数量（status 页用）。
func (c *Client) ServiceCount() (int, bool) {
	code, raw := c.Request("GET", "/config", nil)
	if code != 200 || raw == nil {
		return 0, false
	}
	var cfg struct {
		Services []any `json:"services"`
	}
	if json.Unmarshal(raw, &cfg) != nil {
		return 0, false
	}
	return len(cfg.Services), true
}

// PullServices 从 gost 拉取当前运行的服务列表，返回原始 JSON。
// 用于面板比对：让用户看到 gost 实际在跑什么，和数据库规则是否一致。
func (c *Client) PullServices() (int, json.RawMessage) {
	return c.Request("GET", "/config/services", nil)
}

// ClientCmd 生成客户端连接命令（入站隧道场景，用户在自己电脑上运行）。
func ClientCmd(r store.Rule) string {
	if r.Type != "tunnel" {
		return ""
	}
	auth := ""
	if r.TunnelUser != "" {
		auth = fmt.Sprintf("%s:%s@", r.TunnelUser, r.TunnelPass)
	}
	path := ""
	if r.TunnelPath != "" {
		path = "?path=" + r.TunnelPath
	}
	return fmt.Sprintf("gost -L tcp://:1080 -F \"%s://%sSERVER_IP:%d%s\"",
		r.TunnelProto, auth, r.ListenPort, path)
}
