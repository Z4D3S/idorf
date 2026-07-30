package parser

import (
	"testing"
)

func TestParseCurl_Simple(t *testing.T) {
	cmd := `curl 'https://api.example.com/users/FUZZ/orders'`
	req, err := ParseCurl(cmd)
	if err != nil {
		t.Fatalf("ParseCurl failed: %v", err)
	}
	if req.URL != "https://api.example.com/users/FUZZ/orders" {
		t.Errorf("expected URL https://api.example.com/users/FUZZ/orders, got %s", req.URL)
	}
	if req.Method != "GET" {
		t.Errorf("expected method GET, got %s", req.Method)
	}
}

func TestParseCurl_WithHeaders(t *testing.T) {
	cmd := `curl -H 'Authorization: Bearer ey123' -H 'Content-Type: application/json' 'https://api.example.com/users/FUZZ'`
	req, err := ParseCurl(cmd)
	if err != nil {
		t.Fatalf("ParseCurl failed: %v", err)
	}
	if req.Headers["Authorization"] != "Bearer ey123" {
		t.Errorf("expected Authorization header, got %v", req.Headers)
	}
	if req.Headers["Content-Type"] != "application/json" {
		t.Errorf("expected Content-Type header, got %v", req.Headers)
	}
}

func TestParseCurl_WithPOST(t *testing.T) {
	cmd := `curl -X POST -H 'Content-Type: application/json' -d '{"userId":"FUZZ"}' 'https://api.example.com/transfer'`
	req, err := ParseCurl(cmd)
	if err != nil {
		t.Fatalf("ParseCurl failed: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("expected POST, got %s", req.Method)
	}
	if req.Body != `{"userId":"FUZZ"}` {
		t.Errorf("expected body {\"userId\":\"FUZZ\"}, got %s", req.Body)
	}
}

func TestParseCurl_AutoPOST(t *testing.T) {
	cmd := `curl -d 'data=FUZZ' 'https://api.example.com/submit'`
	req, err := ParseCurl(cmd)
	if err != nil {
		t.Fatalf("ParseCurl failed: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("expected POST (auto), got %s", req.Method)
	}
	if req.Body != "data=FUZZ" {
		t.Errorf("expected body data=FUZZ, got %s", req.Body)
	}
}

func TestParseRaw_Simple(t *testing.T) {
	raw := `GET /api/users/FUZZ/profile HTTP/1.1
Host: api.example.com
Authorization: Bearer ey123

`
	req, err := ParseRaw(raw)
	if err != nil {
		t.Fatalf("ParseRaw failed: %v", err)
	}
	if req.Method != "GET" {
		t.Errorf("expected GET, got %s", req.Method)
	}
	if req.URL != "https://api.example.com/api/users/FUZZ/profile" {
		t.Errorf("expected URL, got %s", req.URL)
	}
	if req.Headers["Authorization"] != "Bearer ey123" {
		t.Errorf("expected Authorization header, got %v", req.Headers)
	}
}

func TestParseRaw_WithBody(t *testing.T) {
	raw := `POST /api/transfer HTTP/1.1
Host: api.example.com
Content-Type: application/json

{"userId": "FUZZ", "amount": 100}`
	req, err := ParseRaw(raw)
	if err != nil {
		t.Fatalf("ParseRaw failed: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("expected POST, got %s", req.Method)
	}
	if req.Body != `{"userId": "FUZZ", "amount": 100}` {
		t.Errorf("expected body, got %s", req.Body)
	}
}

func TestReplaceMarker(t *testing.T) {
	req := &Request{
		Method:  "GET",
		URL:     "https://api.example.com/users/FUZZ/orders",
		Headers: map[string]string{"X-User": "FUZZ"},
		Body:    `{"id": "FUZZ"}`,
	}

	req.ReplaceMarker("FUZZ", "12345")

	if req.URL != "https://api.example.com/users/12345/orders" {
		t.Errorf("URL not replaced: %s", req.URL)
	}
	if req.Headers["X-User"] != "12345" {
		t.Errorf("Header not replaced: %s", req.Headers["X-User"])
	}
	if req.Body != `{"id": "12345"}` {
		t.Errorf("Body not replaced: %s", req.Body)
	}
}

func TestContainsMarker(t *testing.T) {
	req := &Request{
		URL:  "https://api.example.com/users/FUZZ",
		Body: "",
	}
	if !req.ContainsMarker("FUZZ") {
		t.Error("expected ContainsMarker to return true")
	}

	req2 := &Request{
		URL:  "https://api.example.com/users/123",
		Body: "",
	}
	if req2.ContainsMarker("FUZZ") {
		t.Error("expected ContainsMarker to return false")
	}
}

func TestClone(t *testing.T) {
	req := &Request{
		Method:  "POST",
		URL:     "https://api.example.com/users/FUZZ",
		Headers: map[string]string{"X-Test": "value"},
		Body:    `{"id": "FUZZ"}`,
	}

	clone := req.Clone()
	clone.Headers["X-Test"] = "modified"

	if req.Headers["X-Test"] != "value" {
		t.Error("Clone modified original headers")
	}
}

func TestParseCurl_BurpFormat(t *testing.T) {
	cmd := `curl 'https://api.theperfumeshop.com/api/v2/tpsgb/users/FUZZ/orders/12345' \
    -H 'User-Agent: Mozilla/5.0' \
    -H 'Authorization: Bearer ey...' \
    -H 'Content-Type: application/json'`
	req, err := ParseCurl(cmd)
	if err != nil {
		t.Fatalf("ParseCurl failed: %v", err)
	}
	if req.URL != "https://api.theperfumeshop.com/api/v2/tpsgb/users/FUZZ/orders/12345" {
		t.Errorf("URL mismatch: %s", req.URL)
	}
	if req.Headers["Authorization"] != "Bearer ey..." {
		t.Errorf("Auth header mismatch: %s", req.Headers["Authorization"])
	}
}
