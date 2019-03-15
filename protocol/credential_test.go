package protocol

import (
	"net/http"
	"reflect"
	"testing"
)

func TestParseCredentialCreationResponse(t *testing.T) {
	type args struct {
		response *http.Request
	}
	tests := []struct {
		name    string
		args    args
		want    *ParsedCredentialCreationData
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCredentialCreationResponse(tt.args.response)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCredentialCreationResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseCredentialCreationResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsedCredentialCreationData_Verify(t *testing.T) {
	type fields struct {
		ParsedPublicKeyCredential ParsedPublicKeyCredential
		Response                  ParsedAttestationResponse
		Raw                       CredentialCreationResponse
	}
	type args struct {
		storedChallenge    Challenge
		verifyUser         bool
		relyingPartyID     string
		relyingPartyOrigin string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pcc := &ParsedCredentialCreationData{
				ParsedPublicKeyCredential: tt.fields.ParsedPublicKeyCredential,
				Response:                  tt.fields.Response,
				Raw:                       tt.fields.Raw,
			}
			if err := pcc.Verify(tt.args.storedChallenge, tt.args.verifyUser, tt.args.relyingPartyID, tt.args.relyingPartyOrigin); (err != nil) != tt.wantErr {
				t.Errorf("ParsedCredentialCreationData.Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
