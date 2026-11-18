package contract

import "encoding/json"

// AuthType defines supported authentication mechanisms
type AuthType string

const (
	AuthBearer JWTAuth = "Bearer"
	AuthAPIKey APIKeyAuth = "APIKey"
	AuthMTLS   MTLSAuth   = "mTLS"
)

type JWTAuth = string
type APIKeyAuth = string
type MTLSAuth = string

// SecurityExpectations captures security constraints expected by a consumer
type SecurityExpectations struct {
	AuthRequired      bool              `json:"auth_required"`
	AllowedAuthTypes  []string          `json:"allowed_auth_types,omitempty"`
	RequiredClaims    map[string]string `json:"required_claims,omitempty"`    // e.g. "role": "admin"
	RequiredHeaders   []string          `json:"required_headers,omitempty"`   // e.g. "X-Frame-Options"
	ForbiddenHeaders  []string          `json:"forbidden_headers,omitempty"`  // e.g. "Server", "X-Powered-By"
	RequireTLS        bool              `json:"require_tls"`
	MinTLSVersion     uint16            `json:"min_tls_version,omitempty"`
}

// RequestDetails defines the HTTP request template for the contract test
type RequestDetails struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// SecurityContract represents a single Consumer-Driven Security Contract
type SecurityContract struct {
	ConsumerName string               `json:"consumer_name"`
	ProviderName string               `json:"provider_name"`
	Description  string               `json:"description"`
	Request      RequestDetails       `json:"request"`
	Expectations SecurityExpectations `json:"expectations"`
}

func (c *SecurityContract) ToJSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}
