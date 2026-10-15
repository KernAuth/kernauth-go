package main

import "testing"

func TestCheckBody(t *testing.T) {
	body := checkBody("pub_harbor_desktop", "KERN-ABCD-EFGH-IJKL-MNOP")
	if body["protocol_version"] != 1 || body["public_app_id"] != "pub_harbor_desktop" ||
		body["client_version"] != "1.0.0" || body["license_key"] != "KERN-ABCD-EFGH-IJKL-MNOP" {
		t.Fatal(body)
	}
	if apiMessage(map[string]any{"error": map[string]any{"message": "Update required"}}, "no") != "Update required" {
		t.Fatal("message")
	}
	if apiMessage(map[string]any{}, "no") != "no" {
		t.Fatal("fallback")
	}
}
