package consumer

import (
	"cdc-sec/contract"
	"os"
)

type ContractBuilder struct {
	contract contract.SecurityContract
}

func NewContract(consumer, provider string) *ContractBuilder {
	return &ContractBuilder{
		contract: contract.SecurityContract{
			ConsumerName: consumer,
			ProviderName: provider,
			Expectations: contract.SecurityExpectations{
				RequiredClaims: make(map[string]string),
			},
		},
	}
}

func (b *ContractBuilder) Requesting(method, path string) *ContractBuilder {
	b.contract.Request = contract.RequestDetails{
		Method:  method,
		Path:    path,
		Headers: make(map[string]string),
	}
	return b
}

func (b *ContractBuilder) WithHeader(key, value string) *ContractBuilder {
	b.contract.Request.Headers[key] = value
	return b
}

func (b *ContractBuilder) ExpectsJWTAuth(requiredClaims map[string]string) *ContractBuilder {
	b.contract.Expectations.AuthRequired = true
	b.contract.Expectations.AllowedAuthTypes = append(b.contract.Expectations.AllowedAuthTypes, "Bearer")
	for k, v := range requiredClaims {
		b.contract.Expectations.RequiredClaims[k] = v
	}
	return b
}

func (b *ContractBuilder) ExpectsHeaderPresent(header string) *ContractBuilder {
	b.contract.Expectations.RequiredHeaders = append(b.contract.Expectations.RequiredHeaders, header)
	return b
}

func (b *ContractBuilder) ExpectsHeaderForbidden(header string) *ContractBuilder {
	b.contract.Expectations.ForbiddenHeaders = append(b.contract.Expectations.ForbiddenHeaders, header)
	return b
}

func (b *ContractBuilder) SaveToFile(filename string) error {
	data, err := b.contract.ToJSON()
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func (b *ContractBuilder) Build() contract.SecurityContract {
	return b.contract
}
