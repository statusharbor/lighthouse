package database

import "testing"

func TestPlannable(t *testing.T) {
	for q, want := range map[string]bool{
		"SELECT * FROM users WHERE id = $1":                       true,
		"  with x as (select 1) select * from x":                  true,
		"/* app=api */ UPDATE orders SET paid = $1 WHERE id = $2": true,
		"-- report\nSELECT count(*) FROM t":                       true,
		"(SELECT 1) UNION (SELECT 2)":                             true,
		"INSERT INTO t VALUES ($1)":                               true,
		"ALTER ROLE app PASSWORD 'hunter2'":                       false,
		"CREATE USER x WITH PASSWORD 'secret'":                    false,
		"COPY t FROM '/tmp/x'":                                    false,
		"SET search_path = app":                                   false,
		"/* unterminated":                                         false,
		"":                                                        false,
	} {
		if got := plannable(q); got != want {
			t.Errorf("plannable(%q) = %v, want %v", q, got, want)
		}
	}
}
