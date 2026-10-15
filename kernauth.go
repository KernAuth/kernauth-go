package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func checkBody(appID, licenseKey string) map[string]any {
	return map[string]any{
		"protocol_version": 1,
		"public_app_id":    appID,
		"client_version":   "1.0.0",
		"license_key":      licenseKey,
	}
}

func apiMessage(payload map[string]any, fallback string) string {
	errorBody, _ := payload["error"].(map[string]any)
	message, _ := errorBody["message"].(string)
	if message != "" {
		return message
	}
	return fallback
}

type KernAuth struct {
	API       string
	AppID     string
	Message   string
	ExpiresAt string
}

func (app *KernAuth) check(licenseKey string) bool {
	body, _ := json.Marshal(checkBody(app.AppID, licenseKey))
	request, err := http.NewRequest(http.MethodPost, app.API+"/v1/client/check", bytes.NewReader(body))
	if err != nil {
		app.Message = err.Error()
		return false
	}
	request.Header.Set("content-type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		app.Message = err.Error()
		return false
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	var payload map[string]any
	_ = json.Unmarshal(raw, &payload)
	valid, _ := payload["valid"].(bool)
	if response.StatusCode != http.StatusOK || !valid {
		app.Message = apiMessage(payload, fmt.Sprintf("check failed (%d)", response.StatusCode))
		app.ExpiresAt = ""
		return false
	}
	expires, _ := payload["expires_at"].(string)
	app.Message = "License is active"
	app.ExpiresAt = expires
	return true
}
