package imagepreview

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNewServiceConfiguresClientTimeouts(t *testing.T) {
	service := NewService()
	client, ok := service.client.(*http.Client)
	if !ok {
		t.Fatalf("service.client has type %T, want *http.Client", service.client)
	}
	if client.Timeout != 5*time.Second {
		t.Errorf("client.Timeout = %s, want 5s", client.Timeout)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client.Transport has type %T, want *http.Transport", client.Transport)
	}
	if transport.ResponseHeaderTimeout != 5*time.Second {
		t.Errorf("transport.ResponseHeaderTimeout = %s, want 5s", transport.ResponseHeaderTimeout)
	}
	if transport.TLSHandshakeTimeout != 5*time.Second {
		t.Errorf("transport.TLSHandshakeTimeout = %s, want 5s", transport.TLSHandshakeTimeout)
	}
	if transport.Proxy != nil {
		t.Error("transport.Proxy is configured, want proxy discovery disabled")
	}
	if client.CheckRedirect == nil || client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Error("client.CheckRedirect should return redirect responses without following them")
	}
}

func TestFetchRejectsRedirectWithoutReadingBody(t *testing.T) {
	body := &countingBody{}
	service := &Service{client: clientFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     make(http.Header),
			Body:       body,
			Request:    request,
		}, nil
	})}

	_, err := service.Fetch(context.Background(), "https://storage.googleapis.com/redirect", 1024)
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("Fetch() error = %v, want redirect error", err)
	}
	if body.reads != 0 {
		t.Errorf("redirect body was read %d times, want 0", body.reads)
	}
}

type clientFunc func(*http.Request) (*http.Response, error)

func (function clientFunc) Do(request *http.Request) (*http.Response, error) {
	return function(request)
}

type countingBody struct {
	reads int
}

func (body *countingBody) Read([]byte) (int, error) {
	body.reads++
	return 0, io.EOF
}

func (*countingBody) Close() error { return nil }

func TestAllowedURLAcceptsPublicHTTPSImage(t *testing.T) {
	const rawURL = "https://storage.googleapis.com/example/image.png"
	parsed, valid := allowedURL(rawURL)
	if !valid || parsed.String() != rawURL {
		t.Fatalf("allowedURL(%q) = (%v, %t)", rawURL, parsed, valid)
	}
}

func TestAllowedURLRejectsMalformedURL(t *testing.T) {
	if _, valid := allowedURL("://not-a-url"); valid {
		t.Fatal("allowedURL() accepted a malformed URL")
	}
}
