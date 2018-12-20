package protocol

import (
	"reflect"
	"testing"
)

func TestCreateChallenge(t *testing.T) {
	tests := []struct {
		name    string
		want    Challenge
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateChallenge()
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateChallenge() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateChallenge() = %v, want %v", got, tt.want)
			}
		})
	}
}
