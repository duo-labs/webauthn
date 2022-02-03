package metadata

import (
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
)

func TestMetadataTOCParsing(t *testing.T) {
	Conformance = true
	httpClient := &http.Client{
		Timeout: time.Second * 30,
	}

	tests := []struct {
		name    string
		file    string
		wantErr error
	}{
		{
			"success",
			"../testdata/MetadataTOCParsing-P1.jwt",
			nil,
		},
		{
			"verification_failure",
			"../testdata/MetadataTOCParsing-F1.jwt",
			errIntermediateCertRevoked,
		},
		{
			"intermediate_revoked",
			"../testdata/MetadataTOCParsing-F2.jwt",
			jwt.ErrECDSAVerification,
		},
		{
			"leaf_revoked",
			"../testdata/MetadataTOCParsing-F3.jwt",
			errLeafCertRevoked,
		},
		{
			"asn1_parse_error",
			"../testdata/MetadataTOCParsing-F4.jwt",
			errCRLUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, _ := ioutil.ReadFile(tt.file)
			_, _, err := unmarshalMDSTOC(b, *httpClient)
			failed := true
			if err != nil {
				failed = (tt.wantErr == nil || err.Error() != tt.wantErr.Error())
			} else {
				failed = tt.wantErr != nil
			}
			if failed {
				t.Errorf("unmarshalMDSTOC() got %v, wanted %v", err, tt.wantErr)
			}
		})
	}
}

func TestMetadataStatementParsing(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		hash    string
		wantErr error
	}{
		{
			"success",
			"../testdata/TestMetadataStatementParsing-P1.json",
			"bEtEyoVkc-X-ypuFoAIj8s4xKKTZw3wzD7IuDnoBUE8",
			nil,
		},
		{
			"hash_value_mismatch",
			"../testdata/TestMetadataStatementParsing-F1.json",
			"eq28frELluGyBesOw_xE_10Tj25NG0pDS7Oa0DP2kVk",
			errHashValueMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, _ := ioutil.ReadFile(tt.file)
			_, err := unmarshalMetadataStatement(b, tt.hash)
			if err != tt.wantErr {
				t.Errorf("unmarshalMetadataStatement() error %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
