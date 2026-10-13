package main

import (
  "bytes"
  "crypto/ed25519"
  "crypto/rand"
  "crypto/sha256"
  "encoding/base64"
  "encoding/hex"
  "encoding/json"
  "errors"
  "fmt"
  "io"
  "net/http"
  "os"
  "strings"
  "time"
)

const api = "https://api.kernauth.com"
const appID = "__PUBLIC_APP_ID__"
const keyID = "__KEY_ID__"
const publicKey = "__PUBLIC_KEY__"

func main() {
  licenseKey, installationID := os.Getenv("KERN_LICENSE_KEY"), os.Getenv("KERN_INSTALLATION_ID")
  if licenseKey == "" || installationID == "" { panic("Set KERN_LICENSE_KEY and KERN_INSTALLATION_ID") }
  app := Client{API: api, AppID: appID, KeyID: keyID, PublicKey: publicKey}
  if !app.Validate(licenseKey, installationID) {
    panic(app.Message)
  }
  fmt.Println(app.Message)
}

var fields = []string{"protocol_version", "entitlement_id", "application_id", "license_id", "status",
  "features", "device_id", "issued_at", "expires_at", "server_time", "nonce", "key_id"}

type grant struct {
  Entitlement map[string]json.RawMessage `json:"entitlement"`
  Signature string `json:"signature"`
}

func field(ent map[string]json.RawMessage, name string) (string, error) {
  raw, ok := ent[name]
  if !ok { return "", errors.New("missing field: " + name) }
  if name == "features" {
    decoder := json.NewDecoder(bytes.NewReader(raw)); decoder.UseNumber()
    var value any
    if err := decoder.Decode(&value); err != nil { return "", err }
    if text, ok := value.(string); ok {
      decoder = json.NewDecoder(strings.NewReader(text)); decoder.UseNumber()
      if err := decoder.Decode(&value); err != nil { return "", err }
    }
    var output bytes.Buffer
    encoder := json.NewEncoder(&output); encoder.SetEscapeHTML(false)
    if err := encoder.Encode(value); err != nil { return "", err }
    return strings.TrimSuffix(output.String(), "\n"), nil
  }
  var value string
  if name == "protocol_version" { return string(raw), nil }
  if err := json.Unmarshal(raw, &value); err != nil { return "", err }
  return value, nil
}

func canonical(ent map[string]json.RawMessage) ([]byte, error) {
  var output strings.Builder
  for _, name := range fields {
    value, err := field(ent, name); if err != nil { return nil, err }
    if strings.ContainsAny(value, "\r\n") { return nil, errors.New("invalid field") }
    output.WriteString(name + "=" + value + "\n")
  }
  return []byte(output.String()), nil
}

func verifyGrant(g grant, nonce, expectedApp, expectedKey, pinnedKey string, now time.Time) bool {
  ent := g.Entitlement
  app, e1 := field(ent, "application_id")
  key, e2 := field(ent, "key_id")
  echo, e3 := field(ent, "nonce")
  status, e4 := field(ent, "status")
  version, e5 := field(ent, "protocol_version")
  expiry, e6 := field(ent, "expires_at")
  if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil ||
      app != expectedApp || key != expectedKey || echo != nonce || status != "active" || version != "1" { return false }
  deadline, err := time.Parse(time.RFC3339Nano, expiry)
  if err != nil || !deadline.After(now) { return false }
  message, err := canonical(ent); if err != nil { return false }
  pk, err := base64.StdEncoding.DecodeString(pinnedKey)
  if err != nil || len(pk) != ed25519.PublicKeySize { return false }
  sig, err := base64.StdEncoding.DecodeString(g.Signature)
  return err == nil && ed25519.Verify(pk, message, sig)
}

type Client struct {
  API       string
  AppID     string
  KeyID     string
  PublicKey string
  Success   bool
  Message   string
}

func (c *Client) Validate(licenseKey, installationID string) bool {
  return c.call("validate", licenseKey, installationID, "License is active")
}

func (c *Client) call(mode, licenseKey, installationID, okMessage string) bool {
  if err := c.post(mode, licenseKey, installationID); err != nil {
    c.Success = false
    c.Message = err.Error()
    return false
  }
  c.Success = true
  c.Message = okMessage
  return true
}

func (c *Client) post(mode, licenseKey, installationID string) error {
  nonceBytes := make([]byte, 24)
  if _, err := rand.Read(nonceBytes); err != nil { return err }
  nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
  fingerprint := sha256.Sum256([]byte("kernauth-device-v1:" + installationID))
  body, _ := json.Marshal(map[string]any{"protocol_version": 1, "public_app_id": c.AppID,
    "client_version": "1.0.0", "license_key": licenseKey, "fingerprint_version": 1,
    "device_fingerprint": hex.EncodeToString(fingerprint[:]), "installation_id": installationID, "nonce": nonce})
  client := &http.Client{Timeout: 10 * time.Second}
  response, err := client.Post(c.API+"/v1/client/"+mode, "application/json", bytes.NewReader(body))
  if err != nil { return err }
  defer response.Body.Close()
  if response.StatusCode != 200 { return fmt.Errorf("%s failed: %d", mode, response.StatusCode) }
  raw, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
  if err != nil { return err }
  var result grant
  if err := json.Unmarshal(raw, &result); err != nil { return err }
  if !verifyGrant(result, nonce, c.AppID, c.KeyID, c.PublicKey, time.Now()) {
    return errors.New("invalid or expired signed entitlement")
  }
  return nil
}
