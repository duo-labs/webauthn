package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestBase64UnmarshalJSON(t *testing.T) {
	type testData struct {
		StringData  string           `json:"string_data"`
		EncodedData URLEncodedBase64 `json:"encoded_data"`
	}

	message := "test base64 data"

	expected := testData{
		StringData:  "test string",
		EncodedData: URLEncodedBase64(message),
	}

	encoded := base64.RawURLEncoding.EncodeToString([]byte(message))
	raw := fmt.Sprintf(`{"string_data": "test string", "encoded_data": "%s"}`, encoded)

	got := testData{}
	err := json.NewDecoder(strings.NewReader(raw)).Decode(&got)
	if err != nil {
		t.Fatalf("error decoding JSON: %v", err)
	}

	if !bytes.Equal(expected.EncodedData, got.EncodedData) {
		t.Fatalf("invalid URLEncodedBase64 data received: expected %s got %s", expected.EncodedData, got.EncodedData)
	}
	if expected.StringData != got.StringData {
		t.Fatalf("invalid string data received: expected %s got %s", expected.StringData, got.StringData)
	}
}
