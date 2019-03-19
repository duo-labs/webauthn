package webauthn

import (
	"reflect"
	"testing"

	p "github.com/duo-labs/webauthn/protocol"
)

func TestAuthenticator_UpdateCounter(t *testing.T) {
	type fields struct {
		AAGUID       []byte
		SignCount    uint32
		CloneWarning bool
	}
	type args struct {
		authDataCount uint32
	}
	tests := []struct {
		name        string
		fields      fields
		args        args
		wantWarning bool
	}{
		{
			"Update Counter",
			fields{
				AAGUID:       make([]byte, 16),
				SignCount:    1,
				CloneWarning: false,
			},
			args{
				authDataCount: 2,
			},
			false,
		},
		{
			"Update Counter",
			fields{
				AAGUID:       make([]byte, 16),
				SignCount:    2,
				CloneWarning: false,
			},
			args{
				authDataCount: 1,
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authenticator{
				AAGUID:       tt.fields.AAGUID,
				SignCount:    tt.fields.SignCount,
				CloneWarning: tt.fields.CloneWarning,
			}
			a.UpdateCounter(tt.args.authDataCount)
			if !tt.wantWarning && a.CloneWarning {
				t.Errorf("Got clone warning when it should be false")
				return
			}
		})
	}
}

func TestSelectAuthenticator(t *testing.T) {
	type args struct {
		att string
		rrk bool
		uv  string
	}
	tests := []struct {
		name string
		args args
		want p.AuthenticatorSelection
	}{
		{"Generate Correct Authenticator Selection",
			args{
				att: "platform",
				rrk: true,
				uv:  "preferred",
			},
			p.AuthenticatorSelection{
				AuthenticatorAttachment: p.Platform,
				RequireResidentKey:      true,
				UserVerification:        p.VerificationPreferred,
			},
		},
		{"Generate Correct Authenticator Selection",
			args{
				att: "cross-platform",
				rrk: true,
				uv:  "required",
			},
			p.AuthenticatorSelection{
				AuthenticatorAttachment: p.CrossPlatform,
				RequireResidentKey:      true,
				UserVerification:        p.VerificationRequired,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SelectAuthenticator(tt.args.att, tt.args.rrk, tt.args.uv); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SelectAuthenticator() = %v, want %v", got, tt.want)
			}
		})
	}
}
