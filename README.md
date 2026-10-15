# KernAuth Go example

Paste the public app ID from Developers into `main.go`. Go 1.23 or newer.

## Start

```go
app := KernAuth{API: "https://api.kernauth.com", AppID: "__PUBLIC_APP_ID__"}
```

Type the license at the prompt. `KERN_LICENSE_KEY` skips the prompt. The program checks that the key is valid and prints when it expires. It does not save a computer.

## Run

```
go test
go run .
```

A modified program can still skip the check.

Documentation: https://kernauth.apidog.io
