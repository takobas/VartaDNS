package app

import "testing"

func TestMigrateLists(t *testing.T) {
	old := "https://urlhaus.abuse.ch/downloads/hostfile/"
	repl := listURLMigrations[old].URL
	in := []ListSpec{
		{Name: "HaGeZi", URL: "https://example.org/a.txt", Enabled: true},
		{Name: "URLhaus (malware)", URL: old, Enabled: true},
	}
	out, changed := migrateLists(in)
	if !changed || len(out) != 2 || out[1].URL != repl || !out[1].Enabled {
		t.Fatalf("migration failed: %+v", out)
	}
	// Old and new both present (user already added the new one): no duplicate.
	out, changed = migrateLists(append(in, ListSpec{Name: "new", URL: repl, Enabled: true}))
	if !changed || len(out) != 2 {
		t.Fatalf("duplicate not removed: %+v", out)
	}
	// Nothing to migrate.
	if _, changed = migrateLists(out); changed {
		t.Fatal("reported a change on an already migrated list")
	}
}
