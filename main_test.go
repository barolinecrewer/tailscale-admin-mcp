package main

import "testing"

func TestCheckEtag(t *testing.T) {
	for _, e := range []string{"", "  ", `""`} {
		if checkEtag(e) == nil {
			t.Errorf("etag %q should be rejected", e)
		}
	}
	if checkEtag(`"abc"`) != nil {
		t.Error("real etag rejected")
	}
}

func TestIsACLWrite(t *testing.T) {
	cases := []struct {
		method, path string
		want         bool
	}{
		{"POST", "/tailnet/{tailnet}/acl", true},
		{"post", "/tailnet/-/ACL/", true},
		{"PUT", "/tailnet/-/acl?x=1", true},
		{"GET", "/tailnet/-/acl", false},
		{"POST", "/tailnet/-/acl/validate", false},
		{"POST", "/tailnet/-/devices", false},
	}
	for _, c := range cases {
		if got := isACLWrite(c.method, c.path); got != c.want {
			t.Errorf("isACLWrite(%s, %s) = %v, want %v", c.method, c.path, got, c.want)
		}
	}
}

func TestAllowed(t *testing.T) {
	logins := map[string]bool{"a@x.com": true}
	tags := map[string]bool{"tag:ok": true}
	cases := []struct {
		name   string
		tagged bool
		nt     []string
		login  string
		want   bool
	}{
		{"listed user", false, nil, "a@x.com", true},
		{"other user", false, nil, "b@x.com", false},
		{"no login", false, nil, "", false},
		{"listed tag", true, []string{"tag:ok"}, "", true},
		{"other tag", true, []string{"tag:no"}, "", false},
		{"tagged node with listed login is not allowed by login", true, []string{"tag:no"}, "a@x.com", false},
	}
	for _, c := range cases {
		if got := allowed(c.tagged, c.nt, c.login, logins, tags); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
