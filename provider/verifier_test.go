// provider/verifier_test.go
package provider_test

import (
	"encoding/json"
	"os"
	"testing"

	"cdc-sec/contract"
	"cdc-sec/provider"
)

func TestVerifySecurityContract(t *testing.T) {
	contractData, err := os.ReadFile("../contracts/user-service-sec-contract.json")
	if err != nil {
		t.Fatalf("Failed to load contract file: %v", err)
	}

	var secContract contract.SecurityContract
	if err := json.Unmarshal(contractData, &secContract); err != nil {
		t.Fatalf("Failed to parse contract JSON: %v", err)
	}

	verifier := provider.NewVerifier(sampleProviderHandler())
	result := verifier.VerifyContract(secContract)

	if !result.Passed {
		for _, errStr := range result.Errors {
			t.Errorf("CDC-Sec Failure: %s", errStr)
		}
	}
}
