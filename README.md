# KernAuth Go example

Paste the public app ID, key ID, and public key from Developers into `go.go`. Go 1.23 or newer. Standard library only.

## Instance

```go
app := Client{
  API:       "https://api.kernauth.com",
  AppID:     "__PUBLIC_APP_ID__",
  KeyID:     "__KEY_ID__",
  PublicKey: "__PUBLIC_KEY__",
}
```

## Validate

```go
if !app.Validate(licenseKey, installationID) {
  panic(app.Message)
}
fmt.Printf("Status: %s\n", app.Status)
fmt.Printf("Features: %s\n", app.Features)
fmt.Printf("License: %s\n", app.LicenseID)
fmt.Printf("Check expires: %s\n", app.ExpiresAt)
```

A good check prints the status, the feature flags stored on the license, the license id, and when this check expires. Type the license key at the prompt. `KERN_LICENSE_KEY` skips the prompt. The program reads the HWID from the computer. On Windows that is the signed-in user's SID. `KERN_INSTALLATION_ID` overrides that HWID.

## Run

```
go test go.go go_test.go
go run go.go
```

A modified program can still skip the check.

Documentation: https://kernauth.apidog.io
