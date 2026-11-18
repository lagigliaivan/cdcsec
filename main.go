package main

import (
	"fmt"

	"github.com/lagigliaivan/cdcsec/auth"
	"github.com/lagigliaivan/cdcsec/consumer"
)

func main() {
	// 1. Generate RSA key pair for testing
	rsaKey, err := auth.GenerateRSAKeyPair()
	if err != nil {
		panic(err)
	}

	// 2. Define claims required by consumer contract
	claims := map[string]interface{}{
		"sub":  "user-123",
		"role": "admin",
		"iss":  "auth-service",
	}

	// 3. Create real RS256 signed token
	signedToken, err := auth.CreateSignedJWT(claims, rsaKey)
	if err != nil {
		panic(err)
	}

	// 4. Build github.com/lagigliaivan/cdcsec contract with real token
	builder := consumer.NewContract("PaymentService", "UserService")
	contract := builder.
		Requesting("GET", "/api/v1/user/profile").
		WithHeader("Authorization", "Bearer "+signedToken).
		ExpectsJWTAuth(map[string]string{
			"role": "admin",
			"iss":  "auth-service",
		}).
		Build()

	fmt.Printf("Generated github.com/lagigliaivan/cdcsec Contract with signed token:\nAuthorization: Bearer %s...\n", signedToken[:30])
}
