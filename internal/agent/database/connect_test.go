package database

import (
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
)

// TestMysqlDriverDSN proves the mysql:// URL the Console delivers rewrites to
// a DSN the real go-sql-driver accepts - including query params, special
// chars in the password (@ and /), and IPv6 hosts. This is the whole reason
// normalization lives on the agent: the driver is here.
func TestMysqlDriverDSN(t *testing.T) {
	cases := []struct{ in, wantAddr, wantDB, wantUser, wantPass string }{
		{"mysql://sh_agent:PASSWORD@10.0.0.5:3306/app", "10.0.0.5:3306", "app", "sh_agent", "PASSWORD"},
		{"mysql://u:p@h:3306/db?tls=skip-verify", "h:3306", "db", "u", "p"},
		{"mysql://sh_agent:p%40ss%2Fw0rd@10.0.0.5:3306/app", "10.0.0.5:3306", "app", "sh_agent", "p@ss/w0rd"},
		{"mysql://user:pass@[::1]:3306/app", "[::1]:3306", "app", "user", "pass"},
		// Legacy native form must pass through untouched.
		{"u:p@tcp(h:3306)/db", "h:3306", "db", "u", "p"},
	}
	for _, c := range cases {
		got := mysqlDriverDSN(c.in)
		if strings.HasPrefix(got, "mysql://") {
			t.Fatalf("mysqlDriverDSN(%q) still a URL: %q", c.in, got)
		}
		cfg, err := mysql.ParseDSN(got)
		if err != nil {
			t.Fatalf("ParseDSN(%q from %q): %v", got, c.in, err)
		}
		if cfg.Addr != c.wantAddr || cfg.DBName != c.wantDB || cfg.User != c.wantUser || cfg.Passwd != c.wantPass {
			t.Fatalf("from %q -> %q: addr=%q db=%q user=%q pass=%q (want %q/%q/%q/%q)",
				c.in, got, cfg.Addr, cfg.DBName, cfg.User, cfg.Passwd, c.wantAddr, c.wantDB, c.wantUser, c.wantPass)
		}
	}
}

func TestNodeKeyFromDSN(t *testing.T) {
	cases := []struct{ engine, in, want string }{
		{"mysql", "mysql://u:p@10.0.0.5:3306/app", "10.0.0.5:3306"},
		{"mysql", "u:p@tcp(10.0.0.5:3306)/app", "10.0.0.5:3306"},
		{"postgres", "postgres://u:p@10.0.0.5:5432/app", "10.0.0.5:5432"},
	}
	for _, c := range cases {
		if got := nodeKeyFromDSN(c.engine, c.in); got != c.want {
			t.Fatalf("nodeKeyFromDSN(%q, %q) = %q, want %q", c.engine, c.in, got, c.want)
		}
	}
}
