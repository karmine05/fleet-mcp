package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func newTestClient(serverURL string) *FleetClient {
	return &FleetClient{
		baseURL:    serverURL,
		apiKey:     "test",
		httpClient: http.DefaultClient,
	}
}

func TestIsTempQueryName(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"global temp", tempQueryNamePrefix + "1234-abc", true},
		{"team-scoped temp", "[Workstations] " + tempQueryNamePrefix + "1234-abc", true},
		{"team-scoped temp with emoji", "[💻 Workstations] " + tempQueryNamePrefix + "1234-abc", true},
		{"unrelated global query", "Top-level CPU usage", false},
		{"unrelated team query", "[Servers] Disk space check", false},
		{"prefix substring not at start", "prefixed-" + tempQueryNamePrefix + "abc", false},
		{"empty", "", false},
		{"just brackets", "[abc]", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTempQueryName(tc.in); got != tc.want {
				t.Errorf("isTempQueryName(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestEndpointMatchesHostname(t *testing.T) {
	cases := []struct {
		name string
		ep   Endpoint
		in   string
		want bool
	}{
		{
			name: "matches Name exactly",
			ep:   Endpoint{Name: "alpha.local"},
			in:   "alpha.local",
			want: true,
		},
		{
			name: "matches ComputerName case-insensitively",
			ep:   Endpoint{ComputerName: "MyMac"},
			in:   "mymac",
			want: true,
		},
		{
			name: "matches DisplayName",
			ep:   Endpoint{DisplayName: "USS Protostar"},
			in:   "USS Protostar",
			want: true,
		},
		{
			name: "no match — substring on serial only",
			ep:   Endpoint{Name: "host123.local", HardwareSerial: "trex-serial"},
			in:   "trex",
			want: false,
		},
		{
			name: "no match — substring on IP only",
			ep:   Endpoint{Name: "host.local", PrimaryIP: "192.168.1.42"},
			in:   "192.168",
			want: false,
		},
		{
			name: "different hostname does not match",
			ep:   Endpoint{Name: "alpha.local", ComputerName: "alpha", DisplayName: "Alpha"},
			in:   "beta.local",
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := endpointMatchesHostname(tc.ep, tc.in); got != tc.want {
				t.Errorf("endpointMatchesHostname(%+v, %q) = %v, want %v", tc.ep, tc.in, got, tc.want)
			}
		})
	}
}

func TestFetchHostsFromPathBounded_PaginatesUntilShortPage(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		page := r.URL.Query().Get("page")
		var n int
		switch page {
		case "0":
			n = 500
		case "1":
			n = 200
		default:
			t.Errorf("unexpected page %q", page)
			http.Error(w, "unexpected page", http.StatusBadRequest)
			return
		}
		hosts := make([]Endpoint, n)
		for i := range hosts {
			hosts[i] = Endpoint{ID: uint(i + 1)}
		}
		_ = json.NewEncoder(w).Encode(struct {
			Hosts []Endpoint `json:"hosts"`
		}{Hosts: hosts})
	}))
	defer srv.Close()

	fc := newTestClient(srv.URL)
	out, truncated, err := fc.fetchHostsFromPathBounded(context.Background(), "/api/v1/fleet/hosts", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if truncated {
		t.Errorf("expected truncated=false")
	}
	if got, want := len(out), 700; got != want {
		t.Errorf("len(out) = %d, want %d", got, want)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("expected 2 page calls, got %d", got)
	}
}

func TestFetchHostsFromPathBounded_HardCapTruncates(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		hosts := make([]Endpoint, 500)
		for i := range hosts {
			hosts[i] = Endpoint{ID: uint(n)*1000 + uint(i+1)}
		}
		_ = json.NewEncoder(w).Encode(struct {
			Hosts []Endpoint `json:"hosts"`
		}{Hosts: hosts})
	}))
	defer srv.Close()

	fc := newTestClient(srv.URL)
	out, truncated, err := fc.fetchHostsFromPathBounded(context.Background(), "/api/v1/fleet/hosts", 600)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !truncated {
		t.Errorf("expected truncated=true")
	}
	if got, want := len(out), 600; got != want {
		t.Errorf("len(out) = %d, want %d (cap)", got, want)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("expected 2 page calls before cap kicks in, got %d", got)
	}
}

func TestGetVulnerabilityImpact_PropagatesTruncated(t *testing.T) {
	// Lower the cap so a small mock host set trips truncation.
	orig := fetchHostsHardCap
	fetchHostsHardCap = 5
	t.Cleanup(func() { fetchHostsHardCap = orig })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/fleet/hosts":
			// Step 3: return more hosts than the cap (set to 5 above) so the
			// page-truncate branch fires and sets truncated=true.
			hosts := make([]Endpoint, 10)
			for i := range hosts {
				hosts[i] = Endpoint{ID: uint(i + 1)}
			}
			_ = json.NewEncoder(w).Encode(struct {
				Hosts []Endpoint `json:"hosts"`
			}{Hosts: hosts})
		case strings.HasPrefix(r.URL.Path, "/api/v1/fleet/software/titles/"):
			// Step 2: one version per title.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"software_title": map[string]any{
					"versions": []map[string]any{{"id": 99}},
				},
			})
		case r.URL.Path == "/api/v1/fleet/software/titles":
			// Step 1: one title, short page → stop.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"software_titles": []map[string]any{{"id": 1}},
			})
		case r.URL.Path == "/api/v1/fleet/hosts/count":
			_ = json.NewEncoder(w).Encode(map[string]any{"count": 1000})
		default:
			t.Errorf("unexpected request path %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	fc := newTestClient(srv.URL)
	impact, err := fc.GetVulnerabilityImpact(context.Background(), "CVE-2026-12345")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !impact.Truncated {
		t.Errorf("expected Truncated=true to propagate from per-version-id fetch")
	}
	if impact.ImpactedSystems == 0 {
		t.Errorf("expected ImpactedSystems > 0, got %d", impact.ImpactedSystems)
	}
}

func TestBearerAuthMiddleware(t *testing.T) {
	const token = "secret-token"
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	h := bearerAuthMiddleware(token, next)

	cases := []struct {
		name       string
		header     string
		wantStatus int
		wantCalled bool
	}{
		{"missing header", "", http.StatusUnauthorized, false},
		{"wrong scheme", "Basic " + token, http.StatusUnauthorized, false},
		{"wrong token", "Bearer wrong", http.StatusUnauthorized, false},
		{"correct token", "Bearer " + token, http.StatusOK, true},
		{"trailing junk", "Bearer " + token + "x", http.StatusUnauthorized, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called = false
			req := httptest.NewRequest("GET", "/", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if called != tc.wantCalled {
				t.Errorf("next called = %v, want %v", called, tc.wantCalled)
			}
		})
	}
}

func TestRateLimiterMiddleware_BurstThen429(t *testing.T) {
	rl := newIPRateLimiter(1, 2) // 2-token bucket, 1 rps refill
	allowed := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { allowed++ })
	h := rl.Middleware(next)

	send := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "203.0.113.7:5000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// First 2 in burst should pass.
	if rec := send(); rec.Code != http.StatusOK {
		t.Errorf("burst req 1: status = %d, want 200", rec.Code)
	}
	if rec := send(); rec.Code != http.StatusOK {
		t.Errorf("burst req 2: status = %d, want 200", rec.Code)
	}
	// 3rd within the same instant should 429 with Retry-After.
	rec := send()
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Errorf("missing Retry-After header on 429")
	}
	if allowed != 2 {
		t.Errorf("next called %d times, want 2", allowed)
	}
}

func TestValidateCVEID(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"CVE-2026-12345", false},
		{"CVE-1999-0001", false},      // 4-digit minimum
		{"  CVE-2026-12345  ", false}, // trims
		{"", true},
		{"   ", true},
		{"cve-2026-12345", true},  // case-sensitive
		{"CVE-26-12345", true},    // year too short
		{"CVE-2026-123", true},    // suffix too short
		{"CVE-2026-12345x", true}, // trailing junk
		{"CVE-2026", true},        // missing suffix
		{"<script>", true},        // injection-shaped junk
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			err := validateCVEID(tc.in)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateCVEID(%q) err=%v, wantErr=%v", tc.in, err, tc.wantErr)
			}
		})
	}
}

func TestParsePositiveUintString(t *testing.T) {
	cases := []struct {
		in      string
		wantN   uint64
		wantErr bool
	}{
		{"1", 1, false},
		{"42", 42, false},
		{"  42  ", 42, false},
		{"0", 0, true},
		{"", 0, true},
		{"   ", 0, true},
		{"-1", 0, true},
		{"abc", 0, true},
		{"1.5", 0, true},
		{"1e2", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			n, err := parsePositiveUintString("policy_id", tc.in)
			if (err != nil) != tc.wantErr {
				t.Errorf("err=%v, wantErr=%v", err, tc.wantErr)
			}
			if n != tc.wantN {
				t.Errorf("n=%d, want %d", n, tc.wantN)
			}
		})
	}
}

func TestListSoftwareTitles_PaginatesUntilShortPage(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/fleet/software/titles" {
			t.Errorf("unexpected path %q", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		calls.Add(1)
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		var titles []SoftwareTitle
		switch page {
		case 0:
			titles = make([]SoftwareTitle, 100)
			for i := range titles {
				titles[i] = SoftwareTitle{ID: uint(i + 1), Name: fmt.Sprintf("pkg%d", i), Source: "apps"}
			}
		case 1:
			titles = make([]SoftwareTitle, 25)
			for i := range titles {
				titles[i] = SoftwareTitle{ID: uint(100 + i + 1), Name: fmt.Sprintf("pkg%d", 100+i), Source: "apps"}
			}
		default:
			t.Errorf("unexpected page %d", page)
			http.Error(w, "unexpected page", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(struct {
			SoftwareTitles []SoftwareTitle `json:"software_titles"`
		}{SoftwareTitles: titles})
	}))
	defer srv.Close()

	fc := newTestClient(srv.URL)
	// perPage 0 means "no client-side cap" — paginate until the short page.
	out, truncated, err := fc.ListSoftwareTitles(context.Background(), "", "", "", "", "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if truncated {
		t.Errorf("expected truncated=false")
	}
	if got, want := len(out), 125; got != want {
		t.Errorf("len(out) = %d, want %d", got, want)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("expected 2 page calls, got %d", got)
	}
}

func TestListSoftwareTitles_AppliesSourceFilter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/fleet/software/titles" {
			http.NotFound(w, r)
			return
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page > 0 {
			// Short page on page 1 to end pagination.
			_ = json.NewEncoder(w).Encode(struct {
				SoftwareTitles []SoftwareTitle `json:"software_titles"`
			}{})
			return
		}
		// Mixed-source payload: 3 npm, 2 python, 5 apps. Short page (8 < 100)
		// so pagination ends after this response.
		titles := []SoftwareTitle{
			{ID: 1, Name: "left-pad", Source: "npm_packages"},
			{ID: 2, Name: "lodash", Source: "npm_packages"},
			{ID: 3, Name: "axios", Source: "npm_packages"},
			{ID: 4, Name: "requests", Source: "python_packages"},
			{ID: 5, Name: "numpy", Source: "python_packages"},
			{ID: 6, Name: "Slack.app", Source: "apps"},
			{ID: 7, Name: "Chrome.app", Source: "apps"},
			{ID: 8, Name: "Zoom.app", Source: "apps"},
		}
		_ = json.NewEncoder(w).Encode(struct {
			SoftwareTitles []SoftwareTitle `json:"software_titles"`
		}{SoftwareTitles: titles})
	}))
	defer srv.Close()

	fc := newTestClient(srv.URL)
	out, _, err := fc.ListSoftwareTitles(context.Background(), "", "", "", "", "npm_packages", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := len(out), 3; got != want {
		t.Errorf("len(out) = %d, want %d (3 npm)", got, want)
	}
	for _, row := range out {
		if !strings.EqualFold(row.Source, "npm_packages") {
			t.Errorf("unexpected source %q in filtered result", row.Source)
		}
	}

	// Case-insensitive should also work.
	out2, _, err := fc.ListSoftwareTitles(context.Background(), "", "", "", "", "NPM_PACKAGES", 0)
	if err != nil {
		t.Fatalf("unexpected error (case-insensitive): %v", err)
	}
	if len(out2) != 3 {
		t.Errorf("case-insensitive filter returned %d rows, want 3", len(out2))
	}
}

func TestGetHostSoftware_PropagatesTruncated(t *testing.T) {
	// Lower the cap so a small fixture trips truncation deterministically.
	orig := fetchSoftwareHardCap
	fetchSoftwareHardCap = 4
	t.Cleanup(func() { fetchSoftwareHardCap = orig })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/fleet/hosts/") || !strings.HasSuffix(r.URL.Path, "/software") {
			http.NotFound(w, r)
			return
		}
		// Single page with 10 matching rows — hard cap of 4 should fire
		// before the page is fully consumed.
		rows := make([]HostSoftware, 10)
		for i := range rows {
			rows[i] = HostSoftware{ID: uint(i + 1), Name: fmt.Sprintf("pkg%d", i), Source: "apps"}
		}
		_ = json.NewEncoder(w).Encode(struct {
			Software []HostSoftware `json:"software"`
		}{Software: rows})
	}))
	defer srv.Close()

	fc := newTestClient(srv.URL)
	// perPage 0 — don't short-circuit on client-side cap. Force the hard-cap
	// path to fire instead. source="" matches everything.
	out, truncated, err := fc.GetHostSoftware(context.Background(), 42, "", "", "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !truncated {
		t.Errorf("expected truncated=true when hard cap fires")
	}
	if got, want := len(out), 4; got != want {
		t.Errorf("len(out) = %d, want %d (hard cap)", got, want)
	}
}

func TestResolveHostWithUsers_AmbiguousCandidates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/fleet/hosts":
			// Substring search returns multiple collisions.
			hosts := []Endpoint{
				{ID: 1, Name: "mac-1.local"},
				{ID: 2, Name: "mac-2.local"},
				{ID: 3, Name: "mac-3.local"},
			}
			_ = json.NewEncoder(w).Encode(struct {
				Hosts []Endpoint `json:"hosts"`
			}{Hosts: hosts})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	fc := newTestClient(srv.URL)
	host, ambiguous, candidates, err := resolveHostWithUsers(context.Background(), fc, "", "mac")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ambiguous {
		t.Errorf("expected ambiguous=true for multi-match identifier")
	}
	if host != nil {
		t.Errorf("expected host=nil when ambiguous, got %+v", host)
	}
	if got, want := len(candidates), 3; got != want {
		t.Errorf("len(candidates) = %d, want %d", got, want)
	}
}

func TestGetHostByIDWithUsers_DecodesUsers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/fleet/hosts/42" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"host": map[string]any{
				"id":       42,
				"hostname": "test.local",
				"users": []map[string]any{
					{"uid": "501", "username": "alice", "type": "regular", "groupname": "staff", "shell": "/bin/zsh"},
					{"uid": "502", "username": "bob", "type": "regular", "groupname": "staff", "shell": "/bin/bash"},
				},
			},
		})
	}))
	defer srv.Close()

	fc := newTestClient(srv.URL)
	host, err := fc.GetHostByIDWithUsers(context.Background(), 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host == nil {
		t.Fatalf("nil host")
	}
	if got, want := host.ID, uint(42); got != want {
		t.Errorf("host.ID = %d, want %d", got, want)
	}
	if got, want := len(host.Users), 2; got != want {
		t.Errorf("len(users) = %d, want %d", got, want)
	}
	if host.Users[0].Username != "alice" || host.Users[1].Shell != "/bin/bash" {
		t.Errorf("user decode mismatch: %+v", host.Users)
	}
}

func TestFilterHostUsers_CaseInsensitiveAcrossFields(t *testing.T) {
	users := []HostUser{
		{UID: "501", Username: "alice", GroupName: "staff", Shell: "/bin/zsh"},
		{UID: "502", Username: "bob", GroupName: "wheel", Shell: "/bin/bash"},
		{UID: "0", Username: "root", GroupName: "wheel", Shell: "/bin/sh"},
	}
	cases := []struct {
		query string
		want  int
	}{
		{"alice", 1}, // username exact
		{"ALICE", 1}, // case-insensitive
		{"wheel", 2}, // groupname
		{"bash", 1},  // shell
		{"50", 2},    // uid prefix (matches 501, 502)
		{"nomatch", 0},
	}
	for _, tc := range cases {
		got := filterHostUsers(users, tc.query)
		if len(got) != tc.want {
			t.Errorf("filterHostUsers(%q) returned %d, want %d", tc.query, len(got), tc.want)
		}
	}
}

func TestGetHostsForCVE_PaginatesTitles(t *testing.T) {
	var titlesCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v1/fleet/software/titles/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"software_title": map[string]any{"versions": []any{}},
			})
		case r.URL.Path == "/api/v1/fleet/software/titles":
			titlesCalls.Add(1)
			page := r.URL.Query().Get("page")
			n, _ := strconv.Atoi(page)
			var count int
			switch n {
			case 0:
				count = 100
			case 1:
				count = 30
			default:
				t.Errorf("unexpected titles page %d", n)
				http.Error(w, "unexpected page", http.StatusBadRequest)
				return
			}
			type title struct {
				ID uint `json:"id"`
			}
			titles := make([]title, count)
			for i := range titles {
				titles[i].ID = uint(n*1000 + i + 1)
			}
			_ = json.NewEncoder(w).Encode(struct {
				SoftwareTitles []title `json:"software_titles"`
			}{SoftwareTitles: titles})
		default:
			t.Errorf("unexpected request path %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	fc := newTestClient(srv.URL)
	hosts, truncated, err := fc.GetHostsForCVE(context.Background(), "CVE-2026-12345", "", "", "", "", "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if truncated {
		t.Errorf("expected truncated=false (no per-version-id fan-out hit cap)")
	}
	if len(hosts) != 0 {
		t.Errorf("expected 0 hosts (titles had no versions), got %d", len(hosts))
	}
	if got := titlesCalls.Load(); got != 2 {
		t.Errorf("expected 2 titles pages (100 + 30 short page), got %d", got)
	}
}
