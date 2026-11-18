package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GenerateRSAKeyPair creates a temporary RSA keypair for testing
func GenerateRSAKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// GenerateECDSAKeyPair creates a temporary ECDSA keypair for testing
func GenerateECDSAKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// CreateSignedJWT creates a valid JWT with given claims signed by an RSA or ECDSA key
func CreateSignedJWT(claims map[string]interface{}, key interface{}) (string, error) {
	jwtClaims := jwt.MapClaims{
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	for k, v := range claims {
		jwtClaims[k] = v
	}

	var token *jwt.Token
	switch k := key.(type) {
	case *rsa.PrivateKey:
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, jwtClaims)
		return token.SignedString(k)
	case *ecdsa.PrivateKey:
		token = jwt.NewWithClaims(jwt.SigningMethodES256, jwtClaims)
		return token.SignedString(k)
	default:
		return "", jwt.ErrInvalidKey
	}
}
