package session

import (
	"net/http"
	"testing"
)

func TestFromString(t *testing.T) {
	s := FromString("sessionid=ABC123; token=XYZ789")
	if len(s.Cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(s.Cookies))
	}
	if s.Cookies[0].Name != "sessionid" || s.Cookies[0].Value != "ABC123" {
		t.Errorf("cookie 0 mismatch: %+v", s.Cookies[0])
	}
	if s.Cookies[1].Name != "token" || s.Cookies[1].Value != "XYZ789" {
		t.Errorf("cookie 1 mismatch: %+v", s.Cookies[1])
	}
}

func TestToCookieHeader(t *testing.T) {
	s := FromString("a=1; b=2; c=3")
	header := s.ToCookieHeader()
	expected := "a=1; b=2; c=3"
	if header != expected {
		t.Errorf("expected %s, got %s", expected, header)
	}
}

func TestToCookieHeader_Empty(t *testing.T) {
	s := &Session{}
	if s.ToCookieHeader() != "" {
		t.Errorf("expected empty string, got %s", s.ToCookieHeader())
	}
}

func TestApplyHeaders(t *testing.T) {
	s := &Session{
		Headers: []Header{
			{Name: "Authorization", Value: "Bearer token123"},
			{Name: "X-Custom", Value: "test"},
		},
	}
	headers := map[string]string{"Content-Type": "application/json"}
	s.ApplyHeaders(headers)

	if headers["Authorization"] != "Bearer token123" {
		t.Errorf("Authorization not applied: %s", headers["Authorization"])
	}
	if headers["X-Custom"] != "test" {
		t.Errorf("X-Custom not applied: %s", headers["X-Custom"])
	}
	if headers["Content-Type"] != "application/json" {
		t.Errorf("Content-Type overwritten: %s", headers["Content-Type"])
	}
}

func TestAddCookie(t *testing.T) {
	s := &Session{}
	s.AddCookie("test", "value", ".example.com")
	if len(s.Cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(s.Cookies))
	}

	s.AddCookie("test", "updated", ".example.com")
	if s.Cookies[0].Value != "updated" {
		t.Errorf("expected updated, got %s", s.Cookies[0].Value)
	}
	if len(s.Cookies) != 1 {
		t.Errorf("expected 1 cookie after update, got %d", len(s.Cookies))
	}
}

func TestUpdateFromResponse(t *testing.T) {
	s := FromString("old=val1")

	resp := &http.Response{
		Header: http.Header{},
	}
	resp.Header.Add("Set-Cookie", "new=val2; Path=/; Domain=.example.com")
	resp.Header.Add("Set-Cookie", "old=val3; Path=/")

	s.UpdateFromResponse(resp)

	cookieMap := make(map[string]string)
	for _, c := range s.Cookies {
		cookieMap[c.Name] = c.Value
	}

	if cookieMap["new"] != "val2" {
		t.Errorf("expected new=val2, got %s", cookieMap["new"])
	}
	if cookieMap["old"] != "val3" {
		t.Errorf("expected old=val3, got %s", cookieMap["old"])
	}
}

func TestClone(t *testing.T) {
	s := &Session{
		Cookies: []Cookie{{Name: "a", Value: "1"}},
		Headers: []Header{{Name: "X", Value: "y"}},
	}

	clone := s.Clone()
	clone.AddCookie("b", "2", "")

	if len(s.Cookies) != 1 {
		t.Errorf("original modified: %d cookies", len(s.Cookies))
	}
	if len(clone.Cookies) != 2 {
		t.Errorf("clone should have 2 cookies: %d", len(clone.Cookies))
	}
}

func TestIsEmpty(t *testing.T) {
	if !(&Session{}).IsEmpty() {
		t.Error("empty session should be IsEmpty")
	}
	s := FromString("a=1")
	if s.IsEmpty() {
		t.Error("session with cookies should not be IsEmpty")
	}
}