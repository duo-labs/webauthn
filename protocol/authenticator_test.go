package protocol

import (
	"reflect"
	"testing"
)

func TestAuthenticatorFlags_UserPresent(t *testing.T) {
	tests := []struct {
		name string
		flag AuthenticatorFlags
		want bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.flag.UserPresent(); got != tt.want {
				t.Errorf("AuthenticatorFlags.UserPresent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthenticatorFlags_UserVerified(t *testing.T) {
	tests := []struct {
		name string
		flag AuthenticatorFlags
		want bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.flag.UserVerified(); got != tt.want {
				t.Errorf("AuthenticatorFlags.UserVerified() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthenticatorFlags_HasAttestedCredentialData(t *testing.T) {
	tests := []struct {
		name string
		flag AuthenticatorFlags
		want bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.flag.HasAttestedCredentialData(); got != tt.want {
				t.Errorf("AuthenticatorFlags.HasAttestedCredentialData() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthenticatorFlags_HasExtensions(t *testing.T) {
	tests := []struct {
		name string
		flag AuthenticatorFlags
		want bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.flag.HasExtensions(); got != tt.want {
				t.Errorf("AuthenticatorFlags.HasExtensions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthenticatorData_Unmarshal(t *testing.T) {
	type fields struct {
		RPIDHash []byte
		Flags    AuthenticatorFlags
		Counter  uint32
		AttData  AttestedCredentialData
		ExtData  []byte
	}
	type args struct {
		rawAuthData []byte
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
			a := &AuthenticatorData{
				RPIDHash: tt.fields.RPIDHash,
				Flags:    tt.fields.Flags,
				Counter:  tt.fields.Counter,
				AttData:  tt.fields.AttData,
				ExtData:  tt.fields.ExtData,
			}
			if err := a.Unmarshal(tt.args.rawAuthData); (err != nil) != tt.wantErr {
				t.Errorf("AuthenticatorData.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuthenticatorData_unmarshalAttestedData(t *testing.T) {
	type fields struct {
		RPIDHash []byte
		Flags    AuthenticatorFlags
		Counter  uint32
		AttData  AttestedCredentialData
		ExtData  []byte
	}
	type args struct {
		rawAuthData []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &AuthenticatorData{
				RPIDHash: tt.fields.RPIDHash,
				Flags:    tt.fields.Flags,
				Counter:  tt.fields.Counter,
				AttData:  tt.fields.AttData,
				ExtData:  tt.fields.ExtData,
			}
			a.unmarshalAttestedData(tt.args.rawAuthData)
		})
	}
}

func Test_unmarshalCredentialPublicKey(t *testing.T) {
	type args struct {
		keyBytes []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unmarshalCredentialPublicKey(tt.args.keyBytes); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("unmarshalCredentialPublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthenticatorData_Verify(t *testing.T) {
	type fields struct {
		RPIDHash []byte
		Flags    AuthenticatorFlags
		Counter  uint32
		AttData  AttestedCredentialData
		ExtData  []byte
	}
	type args struct {
		rpIdHash                 []byte
		userVerificationRequired bool
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
			a := &AuthenticatorData{
				RPIDHash: tt.fields.RPIDHash,
				Flags:    tt.fields.Flags,
				Counter:  tt.fields.Counter,
				AttData:  tt.fields.AttData,
				ExtData:  tt.fields.ExtData,
			}
			if err := a.Verify(tt.args.rpIdHash, tt.args.userVerificationRequired); (err != nil) != tt.wantErr {
				t.Errorf("AuthenticatorData.Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
