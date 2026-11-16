// MCP server for the Tailscale API (policy file, devices, anything in the OpenAPI spec) and the Aperture admin API.
//
// Modes: stdio (default), or -tsnet: join the tailnet as its own node and serve MCP over HTTPS at /mcp, allowing
// only callers whose tailnet identity matches ALLOWED_LOGINS / ALLOWED_TAGS (comma-separated). Fails closed if both are empty.
// Env: TS_OAUTH_CLIENT_ID, TS_OAUTH_CLIENT_SECRET (Tailscale API), TS_TAILNET ("-"), APERTURE_URL (http://ai/aperture).
// tsnet env: TS_AUTHKEY or TS_CLIENT_SECRET (node registration), TSNET_HOSTNAME, TSNET_TAGS, TSNET_DIR (state dir).
// Writes require the ETag from the matching get call, so a stale view can't clobber live config.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pmezard/go-difflib/difflib"
	"gopkg.in/yaml.v3"
	"tailscale.com/tsnet"
)

const tsAPI = "https://api.tailscale.com/api/v2"

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// httpc has a timeout so a hung upstream cannot freeze the server (the token fetch holds a lock).
var httpc = &http.Client{Timeout: 30 * time.Second}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

type app struct {
	tailnet, aperture string
	aph               *http.Client // reaches Aperture: the tsnet node's client in -tsnet mode, so it uses that node's identity
	mu                sync.Mutex
	tok               string
	exp               time.Time
	specMu            sync.Mutex
	spec              map[string]map[string]map[string]any // cached only after a good fetch
}

type resp struct {
	status     int
	etag, body string
}

func (r resp) String() string {
	return fmt.Sprintf("HTTP %d\netag: %s\n\n%s", r.status, r.etag, r.body)
}

func do(ctx context.Context, c *http.Client, method, u, body, ct string, hdr map[string]string) (resp, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, strings.NewReader(body))
	if err != nil {
		return resp{}, err
	}
	if body != "" && ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	r, err := c.Do(req)
	if err != nil {
		return resp{}, err
	}
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	return resp{r.StatusCode, r.Header.Get("Etag"), string(b)}, err
}

func (a *app) token(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tok != "" && time.Now().Add(time.Minute).Before(a.exp) {
		return a.tok, nil
	}
	id, secret := os.Getenv("TS_OAUTH_CLIENT_ID"), os.Getenv("TS_OAUTH_CLIENT_SECRET")
	if id == "" || secret == "" {
		return "", fmt.Errorf("TS_OAUTH_CLIENT_ID / TS_OAUTH_CLIENT_SECRET not set")
	}
	form := url.Values{"client_id": {id}, "client_secret": {secret}}.Encode()
	r, err := do(ctx, httpc, "POST", tsAPI+"/oauth/token", form, "application/x-www-form-urlencoded", nil)
	if err != nil {
		return "", err
	}
	var j struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if r.status != 200 || json.Unmarshal([]byte(r.body), &j) != nil || j.AccessToken == "" {
		return "", fmt.Errorf("oauth token: HTTP %d", r.status)
	}
	a.tok, a.exp = j.AccessToken, time.Now().Add(time.Duration(j.ExpiresIn)*time.Second)
	return a.tok, nil
}

// ts calls the Tailscale API; {tailnet} in path is filled in.
func (a *app) ts(ctx context.Context, method, path, body, ct string, q url.Values, hdr map[string]string) (resp, error) {
	t, err := a.token(ctx)
	if err != nil {
		return resp{}, err
	}
	u := tsAPI + strings.ReplaceAll(path, "{tailnet}", a.tailnet)
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	h := map[string]string{"Authorization": "Bearer " + t}
	for k, v := range hdr {
		h[k] = v
	}
	return do(ctx, httpc, strings.ToUpper(method), u, body, ct, h)
}

func (a *app) acl(ctx context.Context, sub, policy string, q url.Values, hdr map[string]string) (string, error) {
	r, err := a.ts(ctx, "POST", "/tailnet/{tailnet}/acl"+sub, policy, "application/hujson", q, hdr)
	return r.String(), err
}

func (a *app) livePolicy(ctx context.Context) (resp, error) {
	return a.ts(ctx, "GET", "/tailnet/{tailnet}/acl", "", "", nil, map[string]string{"Accept": "application/hujson"})
}

func (a *app) apertureGet(ctx context.Context) (resp, error) {
	return do(ctx, a.aph, "GET", a.aperture+"/config", "", "", nil)
}

func (a *app) paths(ctx context.Context) (map[string]map[string]map[string]any, error) {
	a.specMu.Lock()
	defer a.specMu.Unlock()
	if a.spec != nil {
		return a.spec, nil
	}
	r, err := do(ctx, httpc, "GET", tsAPI, "", "", nil)
	if err != nil {
		return nil, err
	}
	if r.status != 200 {
		return nil, fmt.Errorf("fetch API spec: HTTP %d", r.status)
	}
	var sp struct {
		Paths map[string]map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal([]byte(r.body), &sp); err != nil {
		return nil, err
	}
	if len(sp.Paths) == 0 {
		return nil, fmt.Errorf("fetch API spec: no paths in response")
	}
	a.spec = sp.Paths
	return a.spec, nil
}

// checkEtag rejects an empty ETag so a write can never skip the stale-view check.
func checkEtag(e string) error {
	if strings.Trim(strings.TrimSpace(e), `"`) == "" {
		return fmt.Errorf("etag is required: read the current config first and pass its ETag")
	}
	return nil
}

// isACLWrite reports whether a call_api request would replace the policy file, which must go through set_policy.
func isACLWrite(method, path string) bool {
	if m := strings.ToUpper(method); m == "GET" || m == "HEAD" {
		return false
	}
	p, _, _ := strings.Cut(path, "?")
	return strings.HasSuffix(strings.TrimRight(strings.ToLower(p), "/"), "/acl")
}

// allowed decides who may call the MCP: tagged nodes by tag, user nodes by login.
func allowed(tagged bool, nodeTags []string, login string, logins, tags map[string]bool) bool {
	if tagged {
		return anyIn(tags, nodeTags)
	}
	return login != "" && logins[login]
}

// tool registers a handler that takes typed input and returns text.
func tool[In any](s *mcp.Server, name, desc string, fn func(context.Context, In) (string, error)) {
	mcp.AddTool(s, &mcp.Tool{Name: name, Description: desc},
		func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
			out, err := fn(ctx, in)
			if err != nil {
				return nil, nil, err
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: out}}}, nil, nil
		})
}

type none struct{}
type policyIn struct {
	Policy string `json:"policy" jsonschema:"HuJSON policy text"`
}
type setPolicyIn struct {
	Policy string `json:"policy" jsonschema:"HuJSON policy text"`
	Etag   string `json:"etag" jsonschema:"ETag from get_policy; rejected if the live policy changed since"`
}
type previewIn struct {
	Policy string `json:"policy"`
	Kind   string `json:"kind" jsonschema:"user or ipport"`
	Target string `json:"target" jsonschema:"user email, or ip:port"`
}
type configIn struct {
	Config string `json:"config" jsonschema:"Aperture config (HuJSON string)"`
}
type setConfigIn struct {
	Config string `json:"config"`
	Etag   string `json:"etag" jsonschema:"ETag from aperture_get_config"`
}
type pricingIn struct {
	Model string `json:"model,omitempty" jsonschema:"exact model string, e.g. anthropic/claude-opus-4-7; empty for the whole catalog"`
}
type diffIn struct {
	Which string `json:"which" jsonschema:"tailscale or aperture"`
	Local string `json:"local" jsonschema:"rendered local copy to compare against, e.g. output of op inject -i policy.hujson.j2"`
}
type queryIn struct {
	Query string `json:"query" jsonschema:"space-separated keywords; all must match path, summary, operationId or description"`
}
type describeIn struct {
	Method string `json:"method"`
	Path   string `json:"path" jsonschema:"path as written in the spec, e.g. /tailnet/{tailnet}/keys"`
}
type callIn struct {
	Method string            `json:"method"`
	Path   string            `json:"path" jsonschema:"path; {tailnet} is filled in from TS_TAILNET"`
	Body   string            `json:"body,omitempty" jsonschema:"JSON request body"`
	Query  map[string]string `json:"query,omitempty"`
}

func (a *app) server() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "tailscale-admin-mcp", Version: version},
		&mcp.ServerOptions{Instructions: "Tailscale tailnet + Aperture admin. Read with get_*, write with set_* using the ETag you read."})

	tool(s, "get_policy", "Live tailnet policy file (HuJSON, comments preserved) plus its ETag. Pass the ETag to set_policy. Needs OAuth scope policy_file:read.",
		func(ctx context.Context, _ none) (string, error) { r, err := a.livePolicy(ctx); return r.String(), err })
	tool(s, "validate_policy", "Validate a HuJSON policy (including its tests) without applying it. Needs policy_file:read.",
		func(ctx context.Context, in policyIn) (string, error) {
			return a.acl(ctx, "/validate", in.Policy, nil, nil)
		})
	tool(s, "set_policy", "Replace the live tailnet policy. etag must be the one from get_policy. Needs the write scope policy_file.",
		func(ctx context.Context, in setPolicyIn) (string, error) {
			if err := checkEtag(in.Etag); err != nil {
				return "", err
			}
			return a.acl(ctx, "", in.Policy, nil, map[string]string{"If-Match": in.Etag})
		})
	tool(s, "preview_policy", "Rules a hypothetical policy applies to a user (kind=user, target=email) or ip:port (kind=ipport). Needs policy_file:read.",
		func(ctx context.Context, in previewIn) (string, error) {
			return a.acl(ctx, "/preview", in.Policy, url.Values{"type": {in.Kind}, "previewFor": {in.Target}}, nil)
		})

	tool(s, "list_devices", "Every device with tags, owner, OS, addresses and last-seen, as compact JSON lines. Needs devices:core:read.",
		func(ctx context.Context, _ none) (string, error) {
			r, err := a.ts(ctx, "GET", "/tailnet/{tailnet}/devices", "", "", nil, nil)
			if err != nil || r.status != 200 {
				return r.String(), err
			}
			var v struct {
				Devices []map[string]any `json:"devices"`
			}
			if err := json.Unmarshal([]byte(r.body), &v); err != nil {
				return "", err
			}
			rows := make([]map[string]any, 0, len(v.Devices))
			for _, d := range v.Devices {
				name, _ := d["name"].(string)
				tags := d["tags"]
				if tags == nil {
					tags = []any{}
				}
				rows = append(rows, map[string]any{"id": d["id"], "name": strings.SplitN(name, ".", 2)[0], "tags": tags,
					"user": d["user"], "os": d["os"], "ips": d["addresses"], "lastSeen": d["lastSeen"], "authorized": d["authorized"]})
			}
			sort.Slice(rows, func(i, j int) bool { return rows[i]["name"].(string) < rows[j]["name"].(string) })
			var sb strings.Builder
			for _, row := range rows {
				b, _ := json.Marshal(row)
				sb.Write(b)
				sb.WriteByte('\n')
			}
			return sb.String(), nil
		})

	tool(s, "aperture_get_config", "Live Aperture config plus ETag (admin role). Provider API keys are redacted, so do not edit this output and send it back with aperture_set_config; start from the rendered infra template instead.",
		func(ctx context.Context, _ none) (string, error) {
			r, err := a.apertureGet(ctx)
			return r.String(), err
		})
	tool(s, "aperture_validate_config", "Validate an Aperture config without applying it.",
		func(ctx context.Context, in configIn) (string, error) {
			b, _ := json.Marshal(map[string]string{"config": in.Config})
			r, err := do(ctx, a.aph, "POST", a.aperture+"/config:validate", string(b), "application/json", nil)
			return r.String(), err
		})
	tool(s, "aperture_set_config", "Replace the entire live Aperture config (admin role). etag must be from aperture_get_config. Returns 412 if the config changed since, 422 if invalid. The body must contain real provider API keys, since aperture_get_config redacts them.",
		func(ctx context.Context, in setConfigIn) (string, error) {
			if err := checkEtag(in.Etag); err != nil {
				return "", err
			}
			b, _ := json.Marshal(map[string]string{"config": in.Config})
			r, err := do(ctx, a.aph, "PUT", a.aperture+"/config", string(b), "application/json", map[string]string{"If-Match": strings.Trim(in.Etag, `"`)})
			return r.String(), err
		})

	tool(s, "aperture_get_pricing", "Aperture pricing catalog, or one model's pricing if model is set. Needs an explicit read_pricing grant (admin alone is not enough).",
		func(ctx context.Context, in pricingIn) (string, error) {
			u := a.aperture + "/pricing"
			if in.Model != "" {
				u += "/" + url.PathEscape(in.Model)
			}
			r, err := do(ctx, a.aph, "GET", u, "", "", nil)
			return r.String(), err
		})

	tool(s, "diff_live", "Unified diff of a local copy vs the live config (which=tailscale|aperture). Use to find drift from the infra repo. Aperture provider API keys are redacted live, so expect apikey lines to differ.",
		func(ctx context.Context, in diffIn) (string, error) {
			var live string
			switch in.Which {
			case "tailscale":
				r, err := a.livePolicy(ctx)
				if err != nil || r.status != 200 {
					return r.String(), err
				}
				live = r.body
			case "aperture":
				r, err := a.apertureGet(ctx)
				if err != nil || r.status != 200 {
					return r.String(), err
				}
				var j struct {
					Config string `json:"config"`
				}
				if json.Unmarshal([]byte(r.body), &j) == nil && j.Config != "" {
					live = j.Config
				} else {
					live = r.body
				}
			default:
				return "", fmt.Errorf("which must be %q or %q", "tailscale", "aperture")
			}
			d, err := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
				A: difflib.SplitLines(in.Local), B: difflib.SplitLines(live), FromFile: "local", ToFile: "live", Context: 3})
			if d == "" {
				d = "no differences"
			}
			return d, err
		})

	tool(s, "search_api", "Search the Tailscale OpenAPI spec by keyword. Returns METHOD path - summary.",
		func(ctx context.Context, in queryIn) (string, error) {
			paths, err := a.paths(ctx)
			if err != nil {
				return "", err
			}
			words := strings.Fields(strings.ToLower(in.Query))
			var out []string
			for p, ops := range paths {
				for m, op := range ops {
					str := func(k string) string { v, _ := op[k].(string); return v }
					desc := str("description")
					if len(desc) > 300 {
						desc = desc[:300]
					}
					hay := strings.ToLower(p + " " + str("summary") + " " + str("operationId") + " " + desc)
					match := true
					for _, w := range words {
						match = match && strings.Contains(hay, w)
					}
					if match {
						out = append(out, fmt.Sprintf("%s %s - %s", strings.ToUpper(m), p, str("summary")))
					}
				}
			}
			sort.Strings(out)
			if len(out) == 0 {
				return "no matches", nil
			}
			if len(out) > 40 {
				out = out[:40]
			}
			return strings.Join(out, "\n"), nil
		})
	tool(s, "describe_api", "Full spec entry (params, body, description) for one operation.",
		func(ctx context.Context, in describeIn) (string, error) {
			paths, err := a.paths(ctx)
			if err != nil {
				return "", err
			}
			op, ok := paths[in.Path][strings.ToLower(in.Method)]
			if !ok {
				return "not found", nil
			}
			b, err := yaml.Marshal(op)
			return string(b), err
		})
	tool(s, "call_api", "Call any Tailscale API endpoint. {tailnet} is filled in. body is a JSON string. Each operation lists its OAuth scope (describe_api); the server's OAuth client must have it. Check describe_api first for writes.",
		func(ctx context.Context, in callIn) (string, error) {
			if isACLWrite(in.Method, in.Path) {
				return "", fmt.Errorf("use set_policy (with the ETag from get_policy) to change the policy file")
			}
			q := url.Values{}
			for k, v := range in.Query {
				q.Set(k, v)
			}
			r, err := a.ts(ctx, in.Method, in.Path, in.Body, "application/json", q, nil)
			return r.String(), err
		})
	return s
}

func split(s string) map[string]bool {
	m := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			m[p] = true
		}
	}
	return m
}

func serveTsnet(a *app) error {
	logins, tags := split(os.Getenv("ALLOWED_LOGINS")), split(os.Getenv("ALLOWED_TAGS"))
	if len(logins) == 0 && len(tags) == 0 {
		return fmt.Errorf("-tsnet requires ALLOWED_LOGINS and/or ALLOWED_TAGS (refusing to serve admin tools to the whole tailnet)")
	}
	// An OAuth secret without a query string registers an ephemeral, unapproved node
	// (tailscale's oauthkey defaults). This is a long-lived service, so default the other way.
	if s := os.Getenv("TS_CLIENT_SECRET"); s != "" && !strings.Contains(s, "?") {
		q := "ephemeral=" + env("TSNET_EPHEMERAL", "false") + "&preauthorized=" + env("TSNET_PREAUTHORIZED", "true")
		os.Setenv("TS_CLIENT_SECRET", s+"?"+q)
	}
	srv := &tsnet.Server{Hostname: env("TSNET_HOSTNAME", "tailscale-admin-mcp"), Dir: os.Getenv("TSNET_DIR")}
	for t := range split(os.Getenv("TSNET_TAGS")) {
		srv.AdvertiseTags = append(srv.AdvertiseTags, t)
	}
	defer srv.Close()
	lc, err := srv.LocalClient()
	if err != nil {
		return err
	}
	a.aph = srv.HTTPClient()
	a.aph.Timeout = 30 * time.Second
	ln, err := srv.ListenTLS("tcp", ":443")
	if err != nil {
		return err
	}
	mcpH := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return a.server() }, nil)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, err := lc.WhoIs(r.Context(), r.RemoteAddr)
		ok := err == nil && who != nil && who.Node != nil
		if ok {
			login := ""
			if who.UserProfile != nil {
				login = who.UserProfile.LoginName
			}
			ok = allowed(who.Node.IsTagged(), who.Node.Tags, login, logins, tags)
		}
		if !ok {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		mcpH.ServeHTTP(w, r)
	})
	log.Printf("serving https on tsnet node %q at /mcp", srv.Hostname)
	mux := http.NewServeMux()
	mux.Handle("/mcp", h)
	return (&http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}).Serve(ln)
}

func anyIn(set map[string]bool, xs []string) bool {
	for _, x := range xs {
		if set[x] {
			return true
		}
	}
	return false
}

func main() {
	useTsnet := flag.Bool("tsnet", false, "join the tailnet and serve MCP over HTTPS at /mcp")
	flag.Parse()
	a := &app{tailnet: env("TS_TAILNET", "-"), aperture: strings.TrimRight(env("APERTURE_URL", "http://ai/aperture"), "/"), aph: httpc}
	var err error
	if *useTsnet {
		err = serveTsnet(a)
	} else {
		err = a.server().Run(context.Background(), &mcp.StdioTransport{})
	}
	if err != nil {
		log.Fatal(err)
	}
}
