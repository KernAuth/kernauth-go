package main

import (
  "bufio"
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
  "os/exec"
  "regexp"
  "runtime"
  "strings"
  "time"
)

const api = "https://api.kernauth.com"
const appID = "__PUBLIC_APP_ID__"
const publicKey = "__PUBLIC_KEY__"

func licenseKey() string {
  if value := strings.TrimSpace(os.Getenv("KERN_LICENSE_KEY")); value != "" {
    return value
  }
  if info, err := os.Stdin.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
    fmt.Fprint(os.Stdout, "Enter license: ")
  }
  line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
  return strings.TrimSpace(line)
}

func installationID() string {
  if value := strings.TrimSpace(os.Getenv("KERN_INSTALLATION_ID")); value != "" {
    return value
  }
  hwid := strings.TrimSpace(machineHWID())
  if regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`).MatchString(hwid) {
    return hwid
  }
  panic("Could not read the HWID")
}

func machineHWID() string {
  switch runtime.GOOS {
  case "windows":
    out, err := exec.Command("powershell.exe", "-NoProfile", "-Command", "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value").Output()
    if err != nil {
      return ""
    }
    return string(out)
  case "darwin":
    out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
    if err != nil {
      return ""
    }
    match := regexp.MustCompile(`"IOPlatformUUID" = "([^"]+)"`).FindSubmatch(out)
    if match == nil {
      return ""
    }
    return string(match[1])
  default:
    raw, err := os.ReadFile("/etc/machine-id")
    if err != nil {
      return ""
    }
    return string(raw)
  }
}

func main() {
  app := Client{API: api, AppID: appID, PublicKey: publicKey}
  key := licenseKey()
  hwid := installationID()
  if !app.Validate(key, hwid) {
    panic(app.Message)
  }
  fmt.Printf("Status: %s\nFeatures: %s\nLicense: %s\nCheck expires: %s\n", app.Status, app.Features, app.LicenseID, app.ExpiresAt)
  for {
    time.Sleep(60 * time.Second)
    if err := app.heartbeat(key, hwid); err != nil {
      fmt.Println(err)
      os.Exit(1)
    }
  }
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

func verifyGrant(g grant, nonce, expectedApp, pinnedKey string, now time.Time) bool {
  ent := g.Entitlement
  app, e1 := field(ent, "application_id")
  echo, e3 := field(ent, "nonce")
  status, e4 := field(ent, "status")
  version, e5 := field(ent, "protocol_version")
  expiry, e6 := field(ent, "expires_at")
  if e1 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil ||
      app != expectedApp || echo != nonce || status != "active" || version != "1" { return false }
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
  PublicKey string
  Success   bool
  Message   string
  Status    string
  Features  string
  LicenseID string
  ExpiresAt string
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

func apiMessage(raw []byte, fallback string) string {
  var failure struct {
    Error struct {
      Message string `json:"message"`
    } `json:"error"`
  }
  if json.Unmarshal(raw, &failure) == nil && failure.Error.Message != "" {
    return failure.Error.Message
  }
  return fallback
}

func (c *Client) heartbeat(licenseKey, installationID string) error {
  nonceBytes := make([]byte, 24)
  if _, err := rand.Read(nonceBytes); err != nil { return err }
  fingerprint := sha256.Sum256([]byte("kernauth-device-v1:" + installationID))
  body, _ := json.Marshal(map[string]any{"protocol_version": 1, "public_app_id": c.AppID,
    "client_version": "1.0.0", "license_key": licenseKey, "fingerprint_version": 1,
    "device_fingerprint": hex.EncodeToString(fingerprint[:]), "installation_id": installationID,
    "nonce": base64.RawURLEncoding.EncodeToString(nonceBytes)})
  client := &http.Client{Timeout: 10 * time.Second}
  response, err := client.Post(c.API+"/v1/client/heartbeat", "application/json", bytes.NewReader(body))
  if err != nil { return err }
  defer response.Body.Close()
  raw, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
  if err != nil { return err }
  if response.StatusCode != 200 {
    return errors.New(apiMessage(raw, fmt.Sprintf("heartbeat failed: %d", response.StatusCode)))
  }
  var payload struct {
    OK bool `json:"ok"`
  }
  if json.Unmarshal(raw, &payload) != nil || !payload.OK {
    return errors.New("heartbeat failed")
  }
  return nil
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
  if response.StatusCode != 200 {
    raw, _ := io.ReadAll(io.LimitReader(response.Body, 64*1024))
    return errors.New(apiMessage(raw, fmt.Sprintf("%s failed: %d", mode, response.StatusCode)))
  }
  raw, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
  if err != nil { return err }
  var result grant
  if err := json.Unmarshal(raw, &result); err != nil { return err }
  if !verifyGrant(result, nonce, c.AppID, c.PublicKey, time.Now()) {
    return errors.New("invalid or expired signed entitlement")
  }
  status, err := field(result.Entitlement, "status")
  if err != nil { return err }
  features, err := field(result.Entitlement, "features")
  if err != nil { return err }
  licenseID, err := field(result.Entitlement, "license_id")
  if err != nil { return err }
  expires, err := field(result.Entitlement, "expires_at")
  if err != nil { return err }
  c.Status, c.Features, c.LicenseID, c.ExpiresAt = status, features, licenseID, expires
  return nil
}
