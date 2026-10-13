package firewall

import (
	"context"
	"os"
	"strings"
	"testing"
)

const testSiteMSS = "-A WW-SITE-MSS -p tcp --tcp-flags SYN,RST SYN -o wg0 -m conntrack --ctorigsrc 192.168.20.0/24 --ctorigdst 192.168.0.0/24 --ctdir ORIGINAL -m comment --comment wirewarp-site-links -j TCPMSS --set-mss 1240\n"

func TestSiteMSSJournalRestoreAndRelease(t *testing.T) {
	s, tables, calls := testStore(t)
	foreign := tables["mangle"] + "-A POSTROUTING -o eth0 -p tcp -j TCPMSS --clamp-mss-to-pmtu\n"
	tables["mangle"] = foreign + "-N WW-SITE-MSS\n-A POSTROUTING -m comment --comment wirewarp-site-links -j WW-SITE-MSS\n" + testSiteMSS
	if err := s.Save(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(s.Path)
	if err != nil || !strings.Contains(string(data), "WW-SITE-MSS") || strings.Contains(string(data), "clamp-mss-to-pmtu") {
		t.Fatal("journal lost scoped clamp or captured foreign rule", err)
	}
	*calls = nil
	if err := s.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	restored := strings.Join(*calls, "\n")
	if !strings.Contains(restored, "*mangle") || !strings.Contains(restored, "--set-mss 1240") || strings.Contains(restored, "clamp-mss-to-pmtu") {
		t.Fatal("restore lost owned scope", restored)
	}
	tables["mangle"] = foreign
	if err := s.Save(context.Background()); err != nil {
		t.Fatal(err)
	}
	*calls = nil
	if err := s.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(*calls, "\n"), "--set-mss 1240") {
		t.Fatal("released clamp revived")
	}
}

func TestSiteMSSJournalRejectsUnsafeScopeBeforeWrites(t *testing.T) {
	for _, kind := range []string{"foreign-empty-chain", "wrong-table", "missing-source", "missing-syn", "wrong-limit", "wrong-parent"} {
		t.Run(kind, func(t *testing.T) {
			s, tables, calls := testStore(t)
			table := "mangle"
			rule := testSiteMSS
			jump := "-A POSTROUTING -m comment --comment wirewarp-site-links -j WW-SITE-MSS\n"
			switch kind {
			case "wrong-table":
				table = "filter"
			case "missing-source":
				rule = strings.ReplaceAll(rule, "--ctorigsrc 192.168.20.0/24 ", "")
			case "missing-syn":
				rule = strings.ReplaceAll(rule, "--tcp-flags SYN,RST SYN ", "")
			case "wrong-limit":
				rule = strings.ReplaceAll(rule, "1240", "1380")
			case "wrong-parent":
				jump = strings.ReplaceAll(jump, "POSTROUTING", "OUTPUT")
			case "foreign-empty-chain":
				jump = ""
				rule = ""
			}
			tables[table] += "-N WW-SITE-MSS\n" + jump + rule
			if s.Preflight(context.Background(), nil) == nil {
				t.Fatal("unsafe chain accepted")
			}
			for _, call := range *calls {
				if !strings.HasPrefix(call, "iptables ") {
					t.Fatal("effects before ownership validation", call)
				}
			}
			if _, err := os.Stat(s.Path); !os.IsNotExist(err) {
				t.Fatal("invalid inventory persisted")
			}
		})
	}
}
