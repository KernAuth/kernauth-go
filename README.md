# KernAuth Go example

Example for Go 1.23 or newer. Standard library only. This file calls validate and checks the Ed25519 signature.

## Add it

Paste the public app ID, key ID, and public key from Developers over the placeholders in `go.go`.

```
go test go.go go_test.go
```

Run with `KERN_LICENSE_KEY` and `KERN_INSTALLATION_ID` set. Persist one installation ID per device.

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
```

A patched program can still skip the check. These examples do not add anti-debug or anti-VM code.

Documentation: https://kernauth.apidog.io
