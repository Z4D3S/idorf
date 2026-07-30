package diff

import (
	"strings"
	"testing"
)

func TestDiff_Identical(t *testing.T) {
	e := NewEngine()
	r := e.Diff(`{"id":1,"name":"alice"}`, `{"id":1,"name":"alice"}`)
	if len(r.Changes) != 0 {
		t.Errorf("expected 0 changes, got %d: %+v", len(r.Changes), r.Changes)
	}
	if r.Score != 0 {
		t.Errorf("expected score 0, got %d", r.Score)
	}
}

func TestDiff_EmailChanged(t *testing.T) {
	e := NewEngine()
	r := e.Diff(
		`{"id":3,"name":"charlie","email":"charlie@test.com"}`,
		`{"id":1,"name":"alice","email":"alice@test.com"}`,
	)
	if !r.HasDataLeak {
		t.Error("expected HasDataLeak=true (email is sensitive)")
	}
	if r.Score < 30 {
		t.Errorf("expected score >= 30 for sensitive changes, got %d", r.Score)
	}
}

func TestDiff_NewFieldAdded(t *testing.T) {
	e := NewEngine()
	r := e.Diff(
		`{"id":1,"name":"alice"}`,
		`{"id":1,"name":"alice","email":"alice@test.com"}`,
	)
	if !r.HasAccessGain {
		t.Error("expected HasAccessGain=true (new email field)")
	}
}

func TestDiff_ArraySize(t *testing.T) {
	e := NewEngine()
	r := e.Diff(
		`{"orders":[{"id":1},{"id":2}]}`,
		`{"orders":[{"id":1},{"id":2},{"id":3}]}`,
	)
	if len(r.Changes) == 0 {
		t.Error("expected changes for different array sizes")
	}
	if !containsChangeType(r.Changes, "array_size_changed") {
		t.Error("expected array_size_changed change")
	}
}

func TestDiff_NestedObject(t *testing.T) {
	e := NewEngine()
	r := e.Diff(
		`{"user":{"profile":{"name":"alice","phone":"123"}}}`,
		`{"user":{"profile":{"name":"bob","phone":"456"}}}`,
	)
	if !r.HasDataLeak {
		t.Error("expected HasDataLeak for changed name/phone")
	}
}

func TestDiff_RemovedField(t *testing.T) {
	e := NewEngine()
	r := e.Diff(
		`{"id":1,"name":"alice","email":"alice@test.com"}`,
		`{"id":1,"name":"alice"}`,
	)
	if !containsChangeType(r.Changes, "removed") {
		t.Error("expected 'removed' change type")
	}
}

func TestDiff_NonJSON(t *testing.T) {
	e := NewEngine()
	r := e.Diff("Access Denied", "Access Denied")
	if len(r.Changes) != 0 {
		t.Errorf("expected 0 changes for identical strings, got %d", len(r.Changes))
	}

	r = e.Diff("Access Denied", `{"id":1,"name":"alice"}`)
	if !r.HasDataLeak {
		t.Error("expected HasDataLeak for non-JSON diff")
	}
}

func TestIsSensitiveKey(t *testing.T) {
	e := NewEngine()
	tests := []struct {
		key  string
		want bool
	}{
		{"email", true},
		{"EmailAddress", true},
		{"phone_number", true},
		{"credit_card", true},
		{"id", false},
		{"created_at", false},
		{"status", false},
		{"admin", true},
		{"role", true},
	}
	for _, tt := range tests {
		got := e.isSensitiveKey(tt.key)
		if got != tt.want {
			t.Errorf("isSensitiveKey(%q) = %v, want %v", tt.key, got, tt.want)
		}
	}
}

func TestDiff_IDOR_Scenario(t *testing.T) {
	e := NewEngine()
	// Baseline: your own profile (user 3)
	baseline := `{"id":3,"name":"charlie","email":"charlie@test.com","phone":"555-0103"}`
	// Actual: accessing user 1's profile (IDOR)
	actual := `{"id":1,"name":"alice","email":"alice@test.com","phone":"555-0101"}`

	r := e.Diff(baseline, actual)
	if !r.HasDataLeak {
		t.Error("IDOR scenario should have HasDataLeak=true")
	}
	if r.Score < 60 {
		t.Errorf("IDOR scenario should score high, got %d", r.Score)
	}
	if !strings.Contains(r.Summary, "sensitive") {
		t.Errorf("summary should mention sensitive data: %s", r.Summary)
	}
}

func TestDiff_EmptyActual(t *testing.T) {
	e := NewEngine()
	r := e.Diff(`{"id":1}`, "")
	if r.HasDataLeak {
		t.Error("empty response should not be HasDataLeak")
	}
	if !strings.Contains(r.Summary, "empty") {
		t.Errorf("summary should mention 'empty': %s", r.Summary)
	}
}

func containsChangeType(changes []Change, changeType string) bool {
	for _, c := range changes {
		if c.Type == changeType {
			return true
		}
	}
	return false
}

func TestIsJSONResponse(t *testing.T) {
	if !IsJSONResponse(`{"key":"value"}`) {
		t.Error("expected IsJSONResponse=true for object")
	}
	if !IsJSONResponse(`[1,2,3]`) {
		t.Error("expected IsJSONResponse=true for array")
	}
	if IsJSONResponse("hello") {
		t.Error("expected IsJSONResponse=false for plain text")
	}
	if IsJSONResponse("") {
		t.Error("expected IsJSONResponse=false for empty")
	}
	if IsJSONResponse("<html>") {
		t.Error("expected IsJSONResponse=false for HTML")
	}
}
