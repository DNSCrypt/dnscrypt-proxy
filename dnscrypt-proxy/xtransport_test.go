package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
)

func TestFetchDirectRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	u := parseTestURL(t, server.URL)
	xTransport := newTestXTransport(t, server.Client().Transport)
	body, statusCode, _, _, err := xTransport.Get(u, "", DefaultTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("unexpected status code: got %d, want %d", statusCode, http.StatusOK)
	}
	if string(body) != "ok" {
		t.Fatalf("unexpected response body: got %q, want %q", body, "ok")
	}
}

func TestFetchRejectsRedirectStatusCodes(t *testing.T) {
	statuses := []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	}
	for _, status := range statuses {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var targetRequests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/target" {
					targetRequests.Add(1)
					w.WriteHeader(http.StatusOK)
					return
				}
				http.Redirect(w, r, "/target", status)
			}))
			defer server.Close()

			assertRedirectRejected(t, server.Client().Transport, server.URL, status, false, &targetRequests)
		})
	}
}

func TestFetchRejectsCrossOriginRedirect(t *testing.T) {
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetRequests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer server.Close()

	assertRedirectRejected(
		t,
		server.Client().Transport,
		server.URL,
		http.StatusFound,
		false,
		&targetRequests,
	)
}

func TestFetchRejectsHTTPSDowngrade(t *testing.T) {
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetRequests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	assertRedirectRejected(
		t,
		server.Client().Transport,
		server.URL,
		http.StatusTemporaryRedirect,
		false,
		&targetRequests,
	)
}

func TestFetchRejectsPostRedirect(t *testing.T) {
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetRequests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusSeeOther)
	}))
	defer server.Close()

	assertRedirectRejected(
		t,
		server.Client().Transport,
		server.URL,
		http.StatusSeeOther,
		true,
		&targetRequests,
	)
}

func assertRedirectRejected(
	t *testing.T,
	roundTripper http.RoundTripper,
	rawURL string,
	expectedStatus int,
	post bool,
	targetRequests *atomic.Int32,
) {
	t.Helper()

	u := parseTestURL(t, rawURL)
	xTransport := newTestXTransport(t, roundTripper)
	var body []byte
	var statusCode int
	var err error
	if post {
		query := []byte("query")
		body, statusCode, _, _, err = xTransport.Post(u, "", "application/dns-message", &query, DefaultTimeout)
	} else {
		body, statusCode, _, _, err = xTransport.Get(u, "", DefaultTimeout)
	}
	if err == nil {
		t.Fatal("expected redirect response to be rejected")
	}
	if statusCode != expectedStatus {
		t.Fatalf("unexpected status code: got %d, want %d", statusCode, expectedStatus)
	}
	if body != nil {
		t.Fatalf("unexpected response body: %q", body)
	}
	if got := targetRequests.Load(); got != 0 {
		t.Fatalf("redirect target received %d requests", got)
	}
}

func newTestXTransport(t *testing.T, roundTripper http.RoundTripper) *XTransport {
	t.Helper()

	transport, ok := roundTripper.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport type: %T", roundTripper)
	}
	xTransport := NewXTransport()
	xTransport.transport = transport.Clone()
	return xTransport
}

func parseTestURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()

	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
