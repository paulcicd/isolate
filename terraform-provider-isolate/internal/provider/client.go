package provider

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

// Client never follows redirects or disables certificate verification. Token
// material is read for each request, never retained in resource state or logs.
type Client struct {
	endpoint, tokenFile string
	http                *http.Client
}

type APIError struct {
	Status    int
	RequestID string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("Isolate API returned HTTP %d (request ID %q); reload/plan on a revision conflict and reconcile uncertain creates before retrying", e.Status, e.RequestID)
}
func isNotFound(err error) bool {
	e, ok := err.(*APIError)
	return ok && e.Status == http.StatusNotFound
}

func newClient(endpoint, tokenFile, caFile string) (*Client, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("endpoint must be a fixed HTTPS URL without credentials, query or fragment")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		material, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("cannot read CA bundle")
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(material) {
			return nil, fmt.Errorf("CA bundle contains no certificates")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	return &Client{strings.TrimRight(endpoint, "/"), tokenFile, &http.Client{Transport: transport, Timeout: 30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *Client) token() (string, error) {
	var value string
	if c.tokenFile != "" {
		info, err := os.Lstat(c.tokenFile)
		if err != nil || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
			return "", fmt.Errorf("token_file must be an existing protected regular file (0600 on Unix)")
		}
		file, err := os.Open(c.tokenFile)
		if err != nil {
			return "", fmt.Errorf("cannot open token_file")
		}
		defer file.Close()
		opened, err := file.Stat()
		if err != nil || !os.SameFile(info, opened) {
			return "", fmt.Errorf("token_file changed while opening")
		}
		material, err := io.ReadAll(io.LimitReader(file, 32769))
		if err != nil || len(material) > 32768 {
			return "", fmt.Errorf("token_file is unreadable or too large")
		}
		value = strings.TrimSpace(string(material))
	} else {
		value = strings.TrimSpace(os.Getenv("ISOLATE_TOKEN"))
	}
	if value == "" || len(value) > 32768 || strings.ContainsAny(value, "\r\n\t ") {
		return "", fmt.Errorf("provide a short-lived bearer token using ISOLATE_TOKEN or token_file")
	}
	return value, nil
}

func newIdempotencyKey() (string, error) {
	value := make([]byte, 24)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "terraform-" + hex.EncodeToString(value), nil
}

func (c *Client) request(ctx context.Context, method, path string, body any, revision, key string, out any) error {
	token, err := c.token()
	if err != nil {
		return err
	}
	var payload []byte
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("cannot encode API request")
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("cannot create API request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "terraform-provider-isolate")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if revision != "" {
		req.Header.Set("If-Match", revision)
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	response, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("Isolate transport failed; the operation was not automatically retried (reconcile uncertain creates before reapplying): %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &APIError{response.StatusCode, response.Header.Get("X-Request-ID")}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 4*1024*1024+1))
	if err != nil || len(data) > 4*1024*1024 {
		return fmt.Errorf("API response is unreadable or exceeds 4 MiB")
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("API returned malformed JSON")
		}
	}
	return nil
}
