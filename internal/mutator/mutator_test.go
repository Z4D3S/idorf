package mutator

import (
	"testing"

	"github.com/z4d3s/idorf/internal/detector"
)

func TestMutateInteger(t *testing.T) {
	id := detector.DetectedID{Type: detector.TypeInteger, Value: "12345"}
	mutations := Mutate(id, DefaultConfig())
	if len(mutations) == 0 {
		t.Fatal("expected mutations for integer")
	}
	// Should include 12346 (+1)
	found := false
	for _, m := range mutations {
		if m.Value == "12346" {
			found = true
		}
	}
	if !found {
		t.Error("expected 12346 in mutations")
	}
}

func TestMutateUUID(t *testing.T) {
	id := detector.DetectedID{Type: detector.TypeUUID, Value: "550e8400-e29b-41d4-a716-446655440000"}
	mutations := Mutate(id, DefaultConfig())
	if len(mutations) != 3 {
		t.Fatalf("expected 3 UUID mutations, got %d", len(mutations))
	}
	for _, m := range mutations {
		if m.Value == id.Value {
			t.Error("mutated UUID should differ from original")
		}
	}
}

func TestMutatePrefixed(t *testing.T) {
	id := detector.DetectedID{Type: detector.TypePrefixed, Value: "ORD-001"}
	mutations := Mutate(id, DefaultConfig())
	if len(mutations) == 0 {
		t.Fatal("expected mutations for prefixed ID")
	}
	// Should include ORD-002
	found := false
	for _, m := range mutations {
		if m.Value == "ORD-002" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ORD-002 in mutations, got %+v", mutations)
	}
}

func TestMutateBase64(t *testing.T) {
	// MTIzNDU= is base64 for "12345"
	id := detector.DetectedID{Type: detector.TypeBase64, Value: "MTIzNDU="}
	mutations := Mutate(id, DefaultConfig())
	if len(mutations) == 0 {
		t.Fatal("expected mutations for base64 ID")
	}
}

func TestMutateHash(t *testing.T) {
	id := detector.DetectedID{Type: detector.TypeHash, Value: "a1b2c3d4e5f6a1b2"}
	mutations := Mutate(id, DefaultConfig())
	if len(mutations) == 0 {
		t.Fatal("expected mutations for hash ID")
	}
	for _, m := range mutations {
		if len(m.Value) != len(id.Value) {
			t.Errorf("hash mutation length mismatch: %s vs %s", m.Value, id.Value)
		}
	}
}

func TestMutateAll(t *testing.T) {
	ids := []detector.DetectedID{
		{Type: detector.TypeInteger, Value: "12345"},
		{Type: detector.TypePrefixed, Value: "ORD-001"},
	}
	result := MutateAll(ids, DefaultConfig())
	if len(result) == 0 {
		t.Fatal("expected non-empty mutation list")
	}
	// Should not include original values
	seen := make(map[string]bool)
	for _, v := range result {
		if v == "12345" || v == "ORD-001" {
			t.Errorf("original value should not be in mutations: %s", v)
		}
		seen[v] = true
	}
	// Should be unique
	if len(seen) != len(result) {
		t.Errorf("mutations should be unique: %d seen vs %d total", len(seen), len(result))
	}
}
