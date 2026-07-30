package detector

import (
	"testing"
)

func TestDetectInURL_Integer(t *testing.T) {
	r := Detect("https://api.example.com/users/12345/profile", "")
	if len(r.IDs) != 1 {
		t.Fatalf("expected 1 ID, got %d: %+v", len(r.IDs), r.IDs)
	}
	if r.IDs[0].Type != TypeInteger {
		t.Errorf("expected integer, got %s", r.IDs[0].Type)
	}
	if r.IDs[0].Value != "12345" {
		t.Errorf("expected 12345, got %s", r.IDs[0].Value)
	}
}

func TestDetectInURL_UUID(t *testing.T) {
	r := Detect("https://api.example.com/orders/550e8400-e29b-41d4-a716-446655440000", "")
	if len(r.IDs) != 1 {
		t.Fatalf("expected 1 ID, got %d", len(r.IDs))
	}
	if r.IDs[0].Type != TypeUUID {
		t.Errorf("expected uuid, got %s", r.IDs[0].Type)
	}
}

func TestDetectInURL_Prefixed(t *testing.T) {
	r := Detect("https://api.example.com/orders/ORD-001", "")
	found := false
	for _, id := range r.IDs {
		if id.Type == TypePrefixed && id.Value == "ORD-001" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected prefixed ORD-001, got %+v", r.IDs)
	}
}

func TestDetectInQuery(t *testing.T) {
	r := Detect("https://api.example.com/search?query=test&user_id=12345&limit=10", "")
	found := false
	for _, id := range r.IDs {
		if id.Key == "user_id" && id.Value == "12345" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected user_id=12345, got %+v", r.IDs)
	}
}

func TestDetectInJSONBody(t *testing.T) {
	body := `{"user_id": "12345", "name": "alice", "order_id": "ORD-002"}`
	r := Detect("https://api.example.com/transfer", body)
	if len(r.IDs) < 2 {
		t.Fatalf("expected at least 2 IDs, got %d: %+v", len(r.IDs), r.IDs)
	}
	hasUserID := false
	hasOrderID := false
	for _, id := range r.IDs {
		if id.Key == "user_id" && id.Value == "12345" {
			hasUserID = true
		}
		if id.Key == "order_id" && id.Value == "ORD-002" {
			hasOrderID = true
		}
	}
	if !hasUserID {
		t.Error("missing user_id detection")
	}
	if !hasOrderID {
		t.Error("missing order_id detection")
	}
}

func TestDetectInFormBody(t *testing.T) {
	body := "user_id=12345&action=transfer"
	r := Detect("https://api.example.com/transfer", body)
	found := false
	for _, id := range r.IDs {
		if id.Key == "user_id" && id.Value == "12345" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected user_id=12345 in form body, got %+v", r.IDs)
	}
}

func TestClassifyValue(t *testing.T) {
	tests := []struct {
		value string
		want  IDType
	}{
		{"12345", TypeInteger},
		{"550e8400-e29b-41d4-a716-446655440000", TypeUUID},
		{"ORD-001", TypePrefixed},
		{"a1b2c3d4e5f6", TypeHash},
		{"MTIzNDU=", TypeBase64},
		{"alice", TypeUnknown},
		{"", TypeUnknown},
	}
	for _, tt := range tests {
		got, matched := classifyValue(tt.value)
		if tt.want == TypeUnknown {
			if matched {
				t.Errorf("classifyValue(%q) = %s, want unknown", tt.value, got)
			}
		} else {
			if got != tt.want {
				t.Errorf("classifyValue(%q) = %s, want %s", tt.value, got, tt.want)
			}
		}
	}
}

func TestDetectMultiple(t *testing.T) {
	r := Detect("https://api.example.com/users/12345/orders/550e8400-e29b-41d4-a716-446655440000?token=abc&ref=ORD-001", "")
	if len(r.IDs) < 3 {
		t.Fatalf("expected at least 3 IDs, got %d: %+v", len(r.IDs), r.IDs)
	}
}

func TestDetectNoIDs(t *testing.T) {
	r := Detect("https://api.example.com/health", "")
	if len(r.IDs) > 0 {
		t.Errorf("expected 0 IDs for /health, got %d: %+v", len(r.IDs), r.IDs)
	}
}
