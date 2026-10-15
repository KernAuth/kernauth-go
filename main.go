package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func licenseKey() string {
	if value := strings.TrimSpace(os.Getenv("KERN_LICENSE_KEY")); value != "" {
		return value
	}
	fmt.Print("Enter license: ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(line)
}

func main() {
	app := KernAuth{API: "https://api.kernauth.com", AppID: "__PUBLIC_APP_ID__"}
	if !app.check(licenseKey()) {
		fmt.Println(app.Message)
		os.Exit(1)
	}
	fmt.Println("Status: active")
	if app.ExpiresAt == "" {
		fmt.Println("Expires: Lifetime")
		return
	}
	fmt.Println("Expires: " + app.ExpiresAt)
}
