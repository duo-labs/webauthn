package metadata

import (
	"errors"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
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
			"../testdata/TestMetadataTOCParsing-P1.jwt",
			nil,
		},
		{
			"verification_failure",
			"../testdata/TestMetadataTOCParsing-F1.jwt",
			jwt.ErrECDSAVerification,
		},
		{
			"intermediate_revoked",
			"../testdata/TestMetadataTOCParsing-F2.jwt",
			errIntermediateCertRevoked,
		},
		{
			"leaf_revoked",
			"../testdata/TestMetadataTOCParsing-F3.jwt",
			errLeafCertRevoked,
		},
		{
			"asn1_parse_error",
			"../testdata/TestMetadataTOCParsing-F4.jwt",
			errors.New("asn1: structure error: tags don't match (16 vs {class:0 tag:4 length:22 isCompound:false}) {optional:false explicit:false application:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} authKeyId @2"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, _ := ioutil.ReadFile(tt.file)
			_, _, err := unmarshalMDSTOC(b, *httpClient)
			failed := true
			if err != nil {
				failed = (err.Error() != tt.wantErr.Error())
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
