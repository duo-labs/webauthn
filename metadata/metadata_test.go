package metadata

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

type ConformanceResponse struct {
	Status string            `json:"status"`
	Result MetadataStatement `json:"result"`
}

func getEndpoints(c http.Client) ([]string, error) {
	jsonBody := []byte(`{"endpoint": "https://webauthn.io"}`)
	bodyReader := bytes.NewReader(jsonBody)
	req, err := c.Post("https://mds3.certinfra.fidoalliance.org/getEndpoints", "application/json", bodyReader)
	if err != nil {
		return nil, err
	}
	defer req.Body.Close()
	body, _ := ioutil.ReadAll(req.Body)

	var resp MDSGetEndpointsResponse

	err = json.Unmarshal(body, &resp)
	if err != nil {
		return nil, err
	}
	return resp.Result, err
}

func getTestMetadata(s string, c http.Client) (MetadataStatement, error) {
	var statement MetadataStatement

	jsonBody := []byte(`{"endpoint": "https://webauthn.io", "testcase": "` + s + `"}`)
	bodyReader := bytes.NewReader(jsonBody)
	req, err := c.Post("https://mds3.certinfra.fidoalliance.org/getTestMetadata", "application/json", bodyReader)
	if err != nil {
		return statement, err
	}

	defer req.Body.Close()
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return statement, err
	}

	var resp ConformanceResponse
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return statement, err
	}
	statement = resp.Result
	return statement, err
}

func TestMetadataTOCParsing(t *testing.T) {
	Conformance = true
	httpClient := &http.Client{
		Timeout: time.Second * 30,
	}

	tests := []struct {
		name string
		pass bool
	}{
		{
			"fido2_good",
			true,
		},
		{
			"fido2_badReports",
			false,
		},
		{
			"fido2_badSignature",
			false,
		},
		{
			"fido2_badCertificateChain",
			false,
		},
		{
			"fido2_intermediateCertificateRevoked",
			false,
		},
		{
			"fido2_subjectCertificateRevoked",
			false,
		},
	}

	endpoints, err := getEndpoints(*httpClient)
	if err != nil {
		t.Fatal(err)
	}

	for _, endpoint := range endpoints {
		bytes, err := downloadBytes(endpoint, *httpClient)
		if err != nil {
			t.Fatal(err)
		}

		blob, _, err := unmarshalMDSTOC(bytes, *httpClient)
		if err != nil {
			if me, ok := err.(*MetadataError); ok {
				t.Log(me.Details)
			}
		}
		for _, entry := range blob.Entries {
			aaguid, _ := uuid.Parse(entry.AaGUID)
			Metadata[aaguid] = entry
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statement, err := getTestMetadata(tt.name, *httpClient)
			if err != nil {
				t.Fatal(err)
			}
			aaguid, _ := uuid.Parse(statement.AaGUID)
			if meta, ok := Metadata[aaguid]; ok {
				if tt.pass {
					t.Logf("Found aaguid %s in test metadata", meta.AaGUID)
				} else {
					if IsUndesiredAuthenticatorStatus(AuthenticatorStatus(meta.StatusReports[0].Status)) {
						t.Logf("Found authenticator %s with bad status in test metadata, %s", meta.AaGUID, meta.StatusReports[0].Status)
					} else {
						t.Fail()
					}
				}
			} else {
				if !tt.pass {
					t.Logf("Metadata for aaguid %s not found in test metadata", statement.AaGUID)
				} else {
					t.Fail()
				}
			}
		})
	}
}
