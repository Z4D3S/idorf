// Package detector automatically identifies object references (IDs) in HTTP requests.
package detector

import (
	"fmt"
	"regexp"
	"strings"
)

// IDType represents the type of detected ID.
type IDType string

const (
	TypeInteger  IDType = "integer"
	TypeUUID     IDType = "uuid"
	TypeBase64   IDType = "base64"
	TypeHash     IDType = "hash"
	TypePrefixed IDType = "prefixed"
	TypeUnknown  IDType = "unknown"
)

// DetectedID represents an ID found in a request.
type DetectedID struct {
	Type     IDType `json:"type"`
	Location string `json:"location"` // "url", "query", "body"
	Key      string `json:"key"`
	Value    string `json:"value"`
	Path     string `json:"path"`
}

// DetectionResult holds all IDs found in a request.
type DetectionResult struct {
	IDs []DetectedID `json:"ids"`
}

var (
	uuidPattern     = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	integerPattern  = regexp.MustCompile(`^\d{3,}$`)
	shortIntPattern = regexp.MustCompile(`^\d{1,2}$`)
	hashPattern     = regexp.MustCompile(`(?i)^[0-9a-f]{8,64}$`)
	base64Pattern   = regexp.MustCompile(`^[A-Za-z0-9+/]{6,}={0,2}$`)
	prefixedPattern = regexp.MustCompile(`(?i)^[A-Z]{2,6}[-_]\d{2,}([-_]\d{2,})?$`)

	idParamNames = regexp.MustCompile(`(?i)(id|uid|user|order|account|customer|doc|file|item|product|ref|token|uuid|key|session|owner|author|workspace|project|task|ticket|msg|thread|comment|post|invoice|subscription|member|team|org|company|client|profile|cart|record|entry)`)

	idPathSegments = regexp.MustCompile(`(?i)(user|users|order|orders|account|accounts|customer|customers|doc|docs|file|files|item|items|product|products|message|messages|thread|threads|comment|comments|post|posts|invoice|invoices|subscription|members|team|teams|org|organization|project|projects|task|tasks|ticket|tickets|workspace|cart|listing|record|profile|resource|workspace|channel|conversation|session|event|booking|reservation|payment|transaction|transfer|wallet|report|template|campaign|survey|form|application|request|job|run|build|release|version|artifact|module|package|service|endpoint|route|config|notification|alert|webhook|integration|connection|token|credential|secret|certificate|role|group|policy|rule|permission|flag|feature|tag|label|category|collection|folder|directory|vault|storage|bucket|queue|topic|stream|feed|review|rating|vote|like|share|follow|friend|contact|address|calendar|event|reminder|note|todo|goal|milestone|sprint|epic|story|issue|bug|change|deployment|pipeline|stage|step|action|trigger|hook|script|snippet|template|page|screen|tab|menu|form|field|table|grid|list|tree|chart|graph|log|setting|preference)`)
)

// Detect scans a URL and request body for potential object references.
func Detect(rawURL, body string) DetectionResult {
	result := DetectionResult{}
	result.IDs = append(result.IDs, detectInURL(rawURL)...)
	result.IDs = append(result.IDs, detectInQuery(rawURL)...)
	if body != "" {
		result.IDs = append(result.IDs, detectInBody(body)...)
	}
	return result
}

func detectInURL(rawURL string) []DetectedID {
	var ids []DetectedID
	pathPart := rawURL
	if idx := strings.Index(pathPart, "?"); idx != -1 {
		pathPart = pathPart[:idx]
	}
	segments := strings.Split(strings.Trim(pathPart, "/"), "/")
	for i, seg := range segments {
		if seg == "" || strings.HasPrefix(seg, "http") {
			continue
		}
		idType, matched := classifyValue(seg)
		if !matched || idType == TypeUnknown {
			// Try short integers (1-2 digits) if preceded by an ID-like path segment
			if i > 0 && idPathSegments.MatchString(segments[i-1]) {
				if shortIntPattern.MatchString(seg) {
					idType = TypeInteger
					matched = true
				}
			}
		}
		if !matched || idType == TypeUnknown {
			continue
		}
		isLikelyID := false
		if i > 0 && idPathSegments.MatchString(segments[i-1]) {
			isLikelyID = true
		}
		if idType == TypeUUID || idType == TypePrefixed {
			isLikelyID = true
		}
		if idType == TypeInteger && len(seg) >= 1 {
			isLikelyID = true
		}
		if isLikelyID {
			ids = append(ids, DetectedID{
				Type: idType, Location: "url", Key: seg, Value: seg,
				Path: fmt.Sprintf("url.path[%d]", i),
			})
		}
	}
	return ids
}

func detectInQuery(rawURL string) []DetectedID {
	var ids []DetectedID
	qStart := strings.Index(rawURL, "?")
	if qStart == -1 {
		return ids
	}
	queryStr := rawURL[qStart+1:]
	for _, param := range strings.Split(queryStr, "&") {
		kv := strings.SplitN(param, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key, value := kv[0], kv[1]
		isIDParam := idParamNames.MatchString(key)
		idType, matched := classifyValue(value)
		if isIDParam || (matched && idType != TypeUnknown) {
			ids = append(ids, DetectedID{
				Type: idType, Location: "query", Key: key, Value: value,
				Path: "query." + key,
			})
		}
	}
	return ids
}

func detectInBody(body string) []DetectedID {
	var ids []DetectedID
	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		ids = append(ids, detectInJSONBody(body)...)
	} else if strings.Contains(body, "=") {
		ids = append(ids, detectInFormBody(body)...)
	}
	return ids
}

func detectInJSONBody(body string) []DetectedID {
	var ids []DetectedID
	jsonPairPattern := regexp.MustCompile(`"([^"]+)":\s*"([^"]*)"`)
	for _, m := range jsonPairPattern.FindAllStringSubmatch(body, -1) {
		key, value := m[1], m[2]
		isIDParam := idParamNames.MatchString(key)
		idType, matched := classifyValue(value)
		if isIDParam || (matched && idType != TypeUnknown) {
			ids = append(ids, DetectedID{
				Type: idType, Location: "body", Key: key, Value: value,
				Path: "body." + key,
			})
		}
	}
	return ids
}

func detectInFormBody(body string) []DetectedID {
	var ids []DetectedID
	for _, param := range strings.Split(body, "&") {
		kv := strings.SplitN(param, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key, value := kv[0], kv[1]
		isIDParam := idParamNames.MatchString(key)
		idType, matched := classifyValue(value)
		if isIDParam || (matched && idType != TypeUnknown) {
			ids = append(ids, DetectedID{
				Type: idType, Location: "body", Key: key, Value: value,
				Path: "body." + key,
			})
		}
	}
	return ids
}

func classifyValue(value string) (IDType, bool) {
	if uuidPattern.MatchString(value) {
		return TypeUUID, true
	}
	if prefixedPattern.MatchString(value) {
		return TypePrefixed, true
	}
	if integerPattern.MatchString(value) {
		return TypeInteger, true
	}
	if hashPattern.MatchString(value) {
		return TypeHash, true
	}
	if base64Pattern.MatchString(value) {
		return TypeBase64, true
	}
	return TypeUnknown, false
}
