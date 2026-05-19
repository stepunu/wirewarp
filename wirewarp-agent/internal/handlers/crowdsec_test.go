package handlers

import "testing"

// realCSCli17AlertShape is a minimal sample of the JSON `cscli decisions
// list -o json` returns in cscli 1.7 — an array of alert envelopes, each
// containing a nested `decisions` slice. Captured from a live VPS, fields
// not exercised by the parser trimmed for readability.
const realCSCli17AlertShape = `[
 {
  "capacity": 10,
  "decisions": [
   {"value": "5.223.60.225", "scope": "Ip", "type": "ban"}
  ],
  "events": [{"meta": []}]
 },
 {
  "capacity": 5,
  "decisions": [
   {"value": "5.223.60.225", "scope": "Ip", "type": "ban"},
   {"value": "8.8.8.8",      "scope": "Ip", "type": "ban"}
  ],
  "events": []
 }
]`

func TestSummariseDecisions_AlertEnvelopeShape(t *testing.T) {
	total, top := summariseDecisions(realCSCli17AlertShape)
	if total != 3 {
		t.Fatalf("total: want 3, got %d", total)
	}
	// 5.223.60.225 appears twice → top of the list.
	if len(top) == 0 {
		t.Fatalf("top: empty")
	}
	first := top[0]
	if first["ip"] != "5.223.60.225" || first["count"].(int) != 2 {
		t.Fatalf("top[0]: want {5.223.60.225, 2}, got %+v", first)
	}
}

func TestSummariseDecisions_FlatShape(t *testing.T) {
	raw := `[{"value":"1.2.3.4","scope":"Ip"},{"value":"1.2.3.4","scope":"Ip"},{"value":"9.9.9.9","scope":"Ip"}]`
	total, top := summariseDecisions(raw)
	if total != 3 {
		t.Fatalf("total: want 3, got %d", total)
	}
	if top[0]["ip"] != "1.2.3.4" || top[0]["count"].(int) != 2 {
		t.Fatalf("top[0]: want {1.2.3.4, 2}, got %+v", top[0])
	}
}

func TestSummariseDecisions_WrappedShape(t *testing.T) {
	raw := `{"decisions":[{"value":"7.7.7.7","scope":"Ip"}]}`
	total, top := summariseDecisions(raw)
	if total != 1 {
		t.Fatalf("total: want 1, got %d", total)
	}
	if top[0]["ip"] != "7.7.7.7" {
		t.Fatalf("top[0]: want 7.7.7.7, got %+v", top[0])
	}
}

func TestSummariseDecisions_EmptyArray(t *testing.T) {
	total, top := summariseDecisions(`[]`)
	if total != 0 || len(top) != 0 {
		t.Fatalf("want (0, nil/empty), got (%d, %+v)", total, top)
	}
}

func TestSummariseDecisions_Garbage(t *testing.T) {
	total, top := summariseDecisions(`not json at all`)
	if total != 0 || top != nil {
		t.Fatalf("want (0, nil), got (%d, %+v)", total, top)
	}
}
