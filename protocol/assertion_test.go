package protocol

import (
	"net/http"
	"reflect"
	"testing"
)

func TestParseCredentialRequestResponse(t *testing.T) {
	type args struct {
		response *http.Request
	}
	tests := []struct {
		name    string
		args    args
		want    *ParsedCredentialAssertionData
		wantErr bool
	}{
		// {
		// 	name: ""
		// }
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCredentialRequestResponse(tt.args.response)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCredentialRequestResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseCredentialRequestResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}
