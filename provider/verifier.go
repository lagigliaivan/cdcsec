package provider

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
	"strings"

	"cdc-sec/contract"

)


type VerificationResult struct {
	Passed bool
	Errors []string
}

type Verifier struct {
	targetHandler http.Handler
}

func NewVerifier(handler http.Handler) *Verifier {
	return &Verifier{targetHandler: handler}
}

func (v *Verifier) VerifyContract(c contract.SecurityContract) VerificationResult {
	res := VerificationResult{Passed: true}

	// 1. Verify Unauthenticated Request Rejection
	if c.Expectations.AuthRequired {
		req := httptest.NewRequest(c.Request.Method, c.Request.Path, nil)
		rec := httptest.NewRecorder()

		v.targetHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
			res.Passed = false
			res.Errors = append(res.Errors, fmt.Sprintf(
				"[FAIL] Auth Enforcement: Expected 401/403 without token, got %d", rec.Code,
			))
		}
	}

	// 2. Verify JWT Claims Validation
	authHeader := c.Request.Headers["Authorization"]
	if c.Expectations.AuthRequired && strings.HasPrefix(authHeader, "Bearer ") {
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := extractJWTClaims(tokenStr)
		if err != nil {
			res.Passed = false
			res.Errors = append(res.Errors, fmt.Sprintf("[FAIL] Malformed JWT in request header: %v", err))
		} else {
			for key, expectedVal := range c.Expectations.RequiredClaims {
				actualVal, exists := claims[key]
				if !exists {
					res.Passed = false
					res.Errors = append(res.Errors, fmt.Sprintf(
						"[FAIL] Missing Claim: Expected claim '%s' missing from JWT", key,
					))
				} else if fmt.Sprintf("%v", actualVal) != expectedVal {
					res.Passed = false
					res.Errors = append(res.Errors, fmt.Sprintf(
						"[FAIL] Claim Mismatch: Claim '%s' expected '%s', got '%v'", key, expectedVal, actualVal,
					))
				}
			}
		}
	}

	// 3. Verify Response Headers against target handler
	req := httptest.NewRequest(c.Request.Method, c.Request.Path, nil)
	for k, v := range c.Request.Headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	v.targetHandler.ServeHTTP(rec, req)

	for _, h := range c.Expectations.RequiredHeaders {
		if rec.Header().Get(h) == "" {
			res.Passed = false
			res.Errors = append(res.Errors, fmt.Sprintf("[FAIL] Missing Required Header: '%s'", h))
		}
	}

	for _, h := range c.Expectations.ForbiddenHeaders {
		if rec.Header().Get(h) != "" {
			res.Passed = false
			res.Errors = append(res.Errors, fmt.Sprintf("[FAIL] Forbidden Header Present: '%s'", h))
		}
	}

	return res
}

// Helper to extract unverified claims from JWT payload
func extractJWTClaims(tokenString string) (map[string]interface{}, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JSON claims: %w", err)
	}

	return claims, nil
}


// VerifyJWTSignature validates both signature and claim matches
func VerifyJWTSignature(tokenStr string, pubKey interface{}, expectedClaims map[string]string) error {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		// Validate algorithm match
		switch pubKey.(type) {
		case *rsa.PublicKey:
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return pubKey, nil
		case *ecdsa.PublicKey:
			if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return pubKey, nil
		default:
			return nil, fmt.Errorf("unsupported key type")
		}
	})

	if err != nil || !token.Valid {
		return fmt.Errorf("invalid token signature: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("unable to parse token claims")
	}

	// Validate expected contract claims
	for k, expectedVal := range expectedClaims {
		if actualVal, exists := claims[k]; !exists || fmt.Sprintf("%v", actualVal) != expectedVal {
			return fmt.Sprintf("claim violation: expected %s=%s, got %v", k, expectedVal, actualVal)
		}
	}

	return nil
}
