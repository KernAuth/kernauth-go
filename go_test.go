package main

import (
  "encoding/json"
  "os"
  "testing"
  "time"
)

func TestWorkerVectors(t *testing.T) {
  raw, err := os.ReadFile("vectors.json")
  if err != nil { t.Fatal(err) }
  var fixture struct { Vectors []struct {
    Name string `json:"name"`
    Fields map[string]json.RawMessage `json:"fields"`
    Canonical string `json:"canonical"`
    PublicKey string `json:"public_key"`
    Signature string `json:"signature"`
  } `json:"vectors"` }
  if err := json.Unmarshal(raw, &fixture); err != nil { t.Fatal(err) }
  now := time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)
  for _, vector := range fixture.Vectors {
    t.Run(vector.Name, func(t *testing.T) {
      message, err := canonical(vector.Fields)
      if err != nil || string(message) != vector.Canonical { t.Fatal("canonical bytes differ", err) }
      g := grant{Entitlement: vector.Fields, Signature: vector.Signature}
      nonce, _ := field(vector.Fields, "nonce")
      app, _ := field(vector.Fields, "application_id")
      key, _ := field(vector.Fields, "key_id")
      if !verifyGrant(g, nonce, app, key, vector.PublicKey, now) { t.Fatal("valid signature rejected") }
      if verifyGrant(g, "wrong", app, key, vector.PublicKey, now) { t.Fatal("wrong nonce accepted") }
      if verifyGrant(g, nonce, "pub_other_app", key, vector.PublicKey, now) { t.Fatal("wrong app accepted") }
      if verifyGrant(g, nonce, app, "wrong-key", vector.PublicKey, now) { t.Fatal("wrong key id accepted") }
      badSig := grant{Entitlement: vector.Fields, Signature: vector.Signature + "AA"}
      if verifyGrant(badSig, nonce, app, key, vector.PublicKey, now) { t.Fatal("bad signature accepted") }
      if verifyGrant(g, nonce, app, key, vector.PublicKey, now.Add(20*time.Minute)) { t.Fatal("expiry accepted") }
      g.Entitlement = make(map[string]json.RawMessage)
      for k, v := range vector.Fields { g.Entitlement[k] = v }
      g.Entitlement["device_id"] = json.RawMessage(`"tampered"`)
      if verifyGrant(g, nonce, app, key, vector.PublicKey, now) { t.Fatal("tampering accepted") }
    })
  }
}
