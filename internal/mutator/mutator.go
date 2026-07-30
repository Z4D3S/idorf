// Package mutator generates ID mutations for IDOR testing.
//
// Given a detected ID, the mutator produces variations to test:
//   - Sequential: ID + 1, ID - 1, ID + 100
//   - UUID: random UUIDs
//   - Base64: decode, increment, re-encode
//   - Prefixed: keep prefix, change number (ORD-001 -> ORD-002, ORD-003)
//   - Hash: random hex strings
package mutator

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/z4d3s/idorf/internal/detector"
)

// Mutation holds a single mutated ID value.
type Mutation struct {
	Value    string `json:"value"`
	Strategy string `json:"strategy"` // "sequential", "uuid", "base64", "prefixed", "hash"
}

// Config holds mutator configuration.
type Config struct {
	SequentialRange int // how many IDs to try above and below (default: 5)
	RandomUUIDCount int // how many random UUIDs to generate (default: 3)
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		SequentialRange: 5,
		RandomUUIDCount: 3,
	}
}

// Mutate generates mutations for a detected ID based on its type.
func Mutate(id detector.DetectedID, cfg Config) []Mutation {
	switch id.Type {
	case detector.TypeInteger:
		return mutateInteger(id.Value, cfg.SequentialRange)
	case detector.TypeUUID:
		return mutateUUID(cfg.RandomUUIDCount)
	case detector.TypeBase64:
		return mutateBase64(id.Value, cfg.SequentialRange)
	case detector.TypePrefixed:
		return mutatePrefixed(id.Value, cfg.SequentialRange)
	case detector.TypeHash:
		return mutateHash(len(id.Value))
	default:
		return nil
	}
}

// mutateInteger generates sequential +/-1, +/-5, +/-100 variations.
func mutateInteger(value string, rangeSize int) []Mutation {
	n, err := strconv.Atoi(value)
	if err != nil {
		return nil
	}

	var mutations []Mutation
	offsets := []int{1, -1, 2, -2, 5, -5, 10, -10, 100, -100, 1000, -1000}

	for _, offset := range offsets {
		newVal := n + offset
		if newVal > 0 {
			mutations = append(mutations, Mutation{
				Value:    strconv.Itoa(newVal),
				Strategy: "sequential",
			})
		}
	}

	return mutations
}

// mutateUUID generates random UUIDs.
func mutateUUID(count int) []Mutation {
	var mutations []Mutation
	for i := 0; i < count; i++ {
		mutations = append(mutations, Mutation{
			Value:    generateUUID(),
			Strategy: "uuid",
		})
	}
	return mutations
}

// mutateBase64 decodes, increments, and re-encodes.
func mutateBase64(value string, rangeSize int) []Mutation {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil
	}

	// Try to interpret as integer
	n, err := strconv.Atoi(string(decoded))
	if err != nil {
		// Not an integer — return random base64
		return []Mutation{{
			Value:    base64.StdEncoding.EncodeToString([]byte("999999")),
			Strategy: "base64",
		}}
	}

	var mutations []Mutation
	offsets := []int{1, -1, 5, -5, 100, -100}
	for _, offset := range offsets {
		newVal := n + offset
		if newVal > 0 {
			encoded := base64.StdEncoding.EncodeToString([]byte(strconv.Itoa(newVal)))
			mutations = append(mutations, Mutation{
				Value:    encoded,
				Strategy: "base64",
			})
		}
	}
	return mutations
}

// mutatePrefixed keeps the prefix and changes the number.
// e.g. ORD-001 -> ORD-002, ORD-003, ORD-000
func mutatePrefixed(value string, rangeSize int) []Mutation {
	// Split into prefix and number
	parts := strings.SplitN(value, "-", 2)
	if len(parts) != 2 {
		parts = strings.SplitN(value, "_", 2)
	}
	if len(parts) != 2 {
		return nil
	}

	prefix := parts[0]
	numStr := parts[1]

	n, err := strconv.Atoi(numStr)
	if err != nil {
		// Check for YYYY-NNNN format
		if strings.Contains(numStr, "-") {
			subParts := strings.SplitN(numStr, "-", 2)
			n, err = strconv.Atoi(subParts[1])
			if err != nil {
				return nil
			}
			prefix = prefix + "-" + subParts[0]
		} else {
			return nil
		}
	}

	// Determine zero-padding
	padLen := len(numStr)
	if padLen > len(fmt.Sprintf("%d", n)) {
		// Has leading zeros
	}

	var mutations []Mutation
	offsets := []int{1, -1, 2, -2, 5, 10, -5, 100, -10}
	for _, offset := range offsets {
		newVal := n + offset
		if newVal > 0 {
			formatted := fmt.Sprintf("%0*d", padLen, newVal)
			mutations = append(mutations, Mutation{
				Value:    prefix + "-" + formatted,
				Strategy: "prefixed",
			})
		}
	}
	return mutations
}

// mutateHash generates random hex strings of the same length.
func mutateHash(length int) []Mutation {
	var mutations []Mutation
	for i := 0; i < 3; i++ {
		b := make([]byte, length/2)
		rand.Read(b)
		mutations = append(mutations, Mutation{
			Value:    hex.EncodeToString(b),
			Strategy: "hash",
		})
	}
	return mutations
}

// generateUUID creates a random UUID v4.
func generateUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// MutateAll generates mutations for all detected IDs and returns unique values.
func MutateAll(ids []detector.DetectedID, cfg Config) []string {
	seen := make(map[string]bool)
	var result []string

	for _, id := range ids {
		mutations := Mutate(id, cfg)
		for _, m := range mutations {
			if !seen[m.Value] && m.Value != id.Value {
				seen[m.Value] = true
				result = append(result, m.Value)
			}
		}
	}

	return result
}
