package handlers

import (
	"bytes"
	"io"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestAppSecAcquisitionSeparatesMixedRouteModes(t *testing.T) {
	data, err := renderAppSecAcquisition()
	if err != nil {
		t.Fatal(err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	seen := map[string]string{}
	for {
		var acquisition map[string]any
		err := decoder.Decode(&acquisition)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		listener := acquisition["listen_addr"].(string)
		labels := acquisition["labels"].(map[string]any)
		mode := labels["wirewarp_mode"].(string)
		if seen[listener] != "" {
			t.Fatalf("duplicate listener %s", listener)
		}
		seen[listener] = mode
		configs := acquisition["appsec_configs"].([]any)
		expected := appSecBlockName
		if mode == "observe" {
			expected = appSecObserveName
		}
		if configs[len(configs)-1] != expected {
			t.Fatalf("mode override must follow default ban policy: %#v", configs)
		}
	}
	if len(seen) != 2 || seen["127.0.0.1:7422"] != "block" || seen["127.0.0.1:7423"] != "observe" {
		t.Fatalf("wrong modes: %#v", seen)
	}
}
