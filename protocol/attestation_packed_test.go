package protocol

import (
	"crypto/sha256"
	"testing"

	"github.com/duo-labs/webauthn/metadata"
)

func Test_verifyPackedFormat(t *testing.T) {
	type args struct {
		att            AttestationObject
		clientDataHash []byte
	}
	successAttResponseES256 := attestationTestUnpackResponse(t, packedTestResponseES256["success"]).Response.AttestationObject
	successClientDataHashES256 := sha256.Sum256(attestationTestUnpackResponse(t, packedTestResponseES256["success"]).Raw.AttestationResponse.ClientDataJSON)
	successAttResponseES512 := attestationTestUnpackResponse(t, packedTestResponseES512["success"]).Response.AttestationObject
	successClientDataHashES512 := sha256.Sum256(attestationTestUnpackResponse(t, packedTestResponseES512["success"]).Raw.AttestationResponse.ClientDataJSON)
	successAttResponseSolo2 := attestationTestUnpackResponse(t, packedTestResponseSolo2["success"]).Response.AttestationObject
	successClientDataHashSolo2 := sha256.Sum256(attestationTestUnpackResponse(t, packedTestResponseSolo2["success"]).Raw.AttestationResponse.ClientDataJSON)
	tests := []struct {
		name    string
		args    args
		want    string
		want1   []interface{}
		wantErr bool
	}{
		{
			"success",
			args{
				successAttResponseES256,
				successClientDataHashES256[:],
			},
			string(metadata.BasicFull),
			nil,
			false,
		},
		{
			"success 512",
			args{
				successAttResponseES512,
				successClientDataHashES512[:],
			},
			string(metadata.BasicSurrogate),
			nil,
			false,
		},
		{
			"success Solo2",
			args{
				successAttResponseSolo2,
				successClientDataHashSolo2[:],
			},
			string(metadata.BasicFull),
			nil,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := verifyPackedFormat(tt.args.att, tt.args.clientDataHash)
			if (err != nil) != tt.wantErr {
				t.Errorf("verifyPackedFormat() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("verifyPackedFormat() got = %v, want %v", got, tt.want)
			}
			//if !reflect.DeepEqual(got1, tt.want1) {
			//	t.Errorf("verifyPackedFormat() got1 = %v, want %v", got1, tt.want1)
			//}
		})
	}
}

var packedTestResponseES256 = map[string]string{
	`success`: `{
		"rawId": "hUf7WI3IZmoLOzYhHFe7U-df4QD17lQBMi9iS-z3dWFlr79MXOoTR8dJzb_Y7sAstHBrcC1nv8pOr6aFz50K65juYXWt8k26bKu-Hu4CulPo53bIStJ4kpOr2Dlr6Z4D",
		"id": "hUf7WI3IZmoLOzYhHFe7U-df4QD17lQBMi9iS-z3dWFlr79MXOoTR8dJzb_Y7sAstHBrcC1nv8pOr6aFz50K65juYXWt8k26bKu-Hu4CulPo53bIStJ4kpOr2Dlr6Z4D",
		"response": {
		  "clientDataJSON": "ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5jcmVhdGUiLA0KCSJjaGFsbGVuZ2UiIDogIlBfSktRaWQxdHZzNEJsdGlaMUNzRWZYbDNHWjBJcG1MUFVRRmxZLW8weDlzZ3ZDS3lXNXpQUkpjTzc3M2VpOE93WEN5Rjl1Wk42X3B5elhOT0FKUjdBIiwNCgkib3JpZ2luIiA6ICJodHRwczovL2xvY2FsaG9zdDo0NDMyOSIsDQoJInRva2VuQmluZGluZyIgOiANCgl7DQoJCSJzdGF0dXMiIDogInN1cHBvcnRlZCINCgl9DQp9",
		  "attestationObject": "o2NmbXRmcGFja2VkaGF1dGhEYXRhWORJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0UAAChiQjgyRUQ3M0M4RkI0RTVBMgBghUf7WI3IZmoLOzYhHFe7U-df4QD17lQBMi9iS-z3dWFlr79MXOoTR8dJzb_Y7sAstHBrcC1nv8pOr6aFz50K65juYXWt8k26bKu-Hu4CulPo53bIStJ4kpOr2Dlr6Z4DpQECAyYgASFYIA9RHvpjfWoWN_Im7eYwG1Y8kA77s7QH9uf9TePknT3mIlggJ8tNsMrPPrewstqf65ItALMxBIi4VUoTIZEyAkXN6U1nYXR0U3RtdKNjYWxnJmNzaWdYRzBFAiBsbcx3U1xgYinrnczLOUDOlYGvYENDGzv77WdM1W3FTQIhAJ16HUK8XyG83cOVQFKkijdgHyDV97XylRMU_rWHAkP_Y3g1Y4NZAkUwggJBMIIB6KADAgECAhAVn3vCzYkY8Shrk0j6nzPiMAoGCCqGSM49BAMCMEkxCzAJBgNVBAYTAkNOMR0wGwYDVQQKDBRGZWl0aWFuIFRlY2hub2xvZ2llczEbMBkGA1UEAwwSRmVpdGlhbiBGSURPMiBDQS0xMCAXDTE4MDQxMTAwMDAwMFoYDzIwMzMwNDEwMjM1OTU5WjBvMQswCQYDVQQGEwJDTjEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xHTAbBgNVBAMMFEZUIEJpb1Bhc3MgRklETzIgVVNCMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgAZ1XFn7yUmwFajSCpJYl76DCrLv6Cz4j-2gkJZj5UjHHxEnBTO0JEZ4nUz-4QFDipTpgz3iACwvKh3Xb03bXaOBiTCBhjAdBgNVHQ4EFgQUelSCQoBi2Irnr4SYJcSvkak0mPIwHwYDVR0jBBgwFoAUTTvYxGcVG7sT6POE2DBPnWkVwIMwDAYDVR0TAQH_BAIwADATBgsrBgEEAYLlHAIBAQQEAwIFIDAhBgsrBgEEAYLlHAEBBAQSBBBCODJFRDczQzhGQjRFNUEyMAoGCCqGSM49BAMCA0cAMEQCICRLRaO-iNy34CWixqMSz_uG7bwnSiLBBS4xSFHw6LCHAiA0Gr9OHCTyCxpz1T2swqn5FbQbsjprAW8f7_jg5_iQwFkB_zCCAfswggGgoAMCAQICEBWfe8LNiRjxKGuTSPqfM-EwCgYIKoZIzj0EAwIwSzELMAkGA1UEBhMCQ04xHTAbBgNVBAoMFEZlaXRpYW4gVGVjaG5vbG9naWVzMR0wGwYDVQQDDBRGZWl0aWFuIEZJRE8gUm9vdCBDQTAgFw0xODA0MTAwMDAwMDBaGA8yMDM4MDQwOTIzNTk1OVowSTELMAkGA1UEBhMCQ04xHTAbBgNVBAoMFEZlaXRpYW4gVGVjaG5vbG9naWVzMRswGQYDVQQDDBJGZWl0aWFuIEZJRE8yIENBLTEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASOfmAJ7MEWZcyg-sPpb-UIO5VtVyUR61sy9NZnOVfdZ9i2FzUd_0u5gOYLqbkzuZo0MPMX6iETB1a9agd03nWPo2YwZDAdBgNVHQ4EFgQUTTvYxGcVG7sT6POE2DBPnWkVwIMwHwYDVR0jBBgwFoAU0aGYTYF_w7lr9gdnvVAS_pBF8VQwEgYDVR0TAQH_BAgwBgEB_wIBADAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDSQAwRgIhAPt_o9JAR6ERUMJ4Vm0hzJAWmOyhf087SDRTecpg5MJlAiEA6wpDwYjB172IPpEkYFbCsLlbWKJ0bwufPKkcKS0rWexZAdwwggHYMIIBfqADAgECAhAVn3vCzYkY8Shrk0j6nzPWMAoGCCqGSM49BAMCMEsxCzAJBgNVBAYTAkNOMR0wGwYDVQQKDBRGZWl0aWFuIFRlY2hub2xvZ2llczEdMBsGA1UEAwwURmVpdGlhbiBGSURPIFJvb3QgQ0EwIBcNMTgwNDAxMDAwMDAwWhgPMjA0ODAzMzEyMzU5NTlaMEsxCzAJBgNVBAYTAkNOMR0wGwYDVQQKDBRGZWl0aWFuIFRlY2hub2xvZ2llczEdMBsGA1UEAwwURmVpdGlhbiBGSURPIFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASd8ApuO8xfUTLVvqT5ZBB01Uy30mAZbInc-8zgFIrlepN-j77SgCP_i2fDIgvQcUFH1K36S2OpJcN-OJcC6uzzo0IwQDAdBgNVHQ4EFgQU0aGYTYF_w7lr9gdnvVAS_pBF8VQwDwYDVR0TAQH_BAUwAwEB_zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDSAAwRQIhALexPWUGMZ4X7EpOnNXUphTZyRqFN3iYsnLNg6Foe_iKAiAPYliR_IflDgGmjyuug7Qi3uhiMXaSDL95JndT0aVqrA"
		},
		"type": "public-key"
	  }`,
}

var packedTestResponseES512 = map[string]string{
	`success`: `{
		"rawId": "6YIJExgLDzTvfys9WgQlIGTL1L9Ys9bhaaA1Pr-OAPc",
		"id": "6YIJExgLDzTvfys9WgQlIGTL1L9Ys9bhaaA1Pr-OAPc",
		"response": {
		  "clientDataJSON": "eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDo0NDMyOSIsImNoYWxsZW5nZSI6IlFQQS1GckNTd2ctcUhoell2UklkbkEiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
		  "attestationObject": "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzgjY3NpZ1iKMIGHAkE9Vr0j3zGzH6_YASuNse-D4bIDPU4ralNkJqgbCyv_tPNdt27VKaPDnK3WKWgv1qna04qMA7yukZeOPods8arRVQJCAZibACvAfmwBNT4cvR32MNvgGienLXmi2q8MwytcGrtOMnyhnxgco0pOFH7eWHXzn64mVqdSD-wPRTIfJ3McBxW0aGF1dGhEYXRhWOlJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0EAAABmI4irjYkVQUaTutQ-Zx0lOAAg6YIJExgLDzTvfys9WgQlIGTL1L9Ys9bhaaA1Pr-OAPelAQIDOCMgAyFYQgGzEwyupDz8u1IHtClxewg8CYWBRqD6_SufCj6-LevV57awHyeFGbyfS78ZB4e_I7RmndDI-jO24T3WZ1JMoE1mMCJYQgCpx32yAvYCfKWILgd5aLYuE5L8lEWuN5lhzGwNXoi6pj0JcQR60yCzI8HPlESzEvpqtCNBqF99eD2JETVIqkiwvQ"
		},
		"type": "public-key"
	  }`,
}

var packedTestResponseSolo2 = map[string]string{
	`success`: `{
		"id":"owBY6F5857tda9Pg5iFNCg6ksHpGOYhrNqIn46pkvhEMKIgNGcKS-vDGAUEroq0-VHnl1LhzQkPRQmYBTHjGcpLKZKSLa2m2ANI-91HjXzoJd_zFOiEnu7CDwQTff9KZ6uPlx7kUK-JJOHar-IyRKcNhc_kOJ2ezglmj1JYuIJLoDEyXlKkkviFdwk1vbWLnO3p_oWROUeIgH_S4CLVLPIJXkPe0YvMgp3ESs9CsrN6kvMTysVRIt_h5KUqpZo0TKCL96zwFk1X_2PwCLKWmOxVL35lJfUKOHG9rc3bmKlqZR6aOgZjerY6BpU8BTJkAqfOvdVlqFeEcywJQgveR7FOvnVtoqzd5oaEwjA",
		"rawId":"owBY6F5857tda9Pg5iFNCg6ksHpGOYhrNqIn46pkvhEMKIgNGcKS-vDGAUEroq0-VHnl1LhzQkPRQmYBTHjGcpLKZKSLa2m2ANI-91HjXzoJd_zFOiEnu7CDwQTff9KZ6uPlx7kUK-JJOHar-IyRKcNhc_kOJ2ezglmj1JYuIJLoDEyXlKkkviFdwk1vbWLnO3p_oWROUeIgH_S4CLVLPIJXkPe0YvMgp3ESs9CsrN6kvMTysVRIt_h5KUqpZo0TKCL96zwFk1X_2PwCLKWmOxVL35lJfUKOHG9rc3bmKlqZR6aOgZjerY6BpU8BTJkAqfOvdVlqFeEcywJQgveR7FOvnVtoqzd5oaEwjA",
		"response":{
			"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAIXRMqmC2_bHTkKUwOvLvmAikuQPCk__9clILwjhOz3VAiEApJXTrN4WMiPwFXqTIh0oI8AZBm3vs-y_UotbQFSnX99jeDVjgVkCqzCCAqcwggJMoAMCAQICFGqj6W3EVhRWQJPun0qqCMyTlnqKMAoGCCqGSM49BAMCMC0xETAPBgNVBAoMCFNvbG9LZXlzMQswCQYDVQQGEwJDSDELMAkGA1UEAwwCRjEwIBcNMjEwNTIzMDA1MjA2WhgPMjA3MTA1MTEwMDUyMDZaMIGDMQswCQYDVQQGEwJVUzERMA8GA1UECgwIU29sb0tleXMxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xPTA7BgNVBAMMNFNvbG8gMiBORkMrVVNCLUMgMjM2OUQ0RDAxM0NFNDhDQjlGMjZGN0VEOEM5QTYwNjggQjIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS6N5V2fT-agh34bRiW--Wl6CQPSsnLqqSEID0t5RRKjjl1NDI__mzuyYuOrWyb5yzGZRHgnHq65cm2ROpxo6AOo4HwMIHtMB0GA1UdDgQWBBQ6CEDC5W8_zAMOhVgV8wHJI8n3bzAfBgNVHSMEGDAWgBRBa7ZL76IZDeRiX_0pBJa5gim0-DAJBgNVHRMEAjAAMAsGA1UdDwQEAwIE8DAyBggrBgEFBQcBAQQmMCQwIgYIKwYBBQUHMAKGFmh0dHA6Ly9pLnMycGtpLm5ldC9mMS8wJwYDVR0fBCAwHjAcoBqgGIYWaHR0cDovL2MuczJwa2kubmV0L3IxLzAhBgsrBgEEAYLlHAEBBAQSBBAjadTQE85Iy58m9-2MmmBoMBMGCysGAQQBguUcAgEBBAQDAgQwMAoGCCqGSM49BAMCA0kAMEYCIQCP82Rolr0U2FvOJq53AZYcA6xfC4-cNDczvf0FtU1SQAIhAIvb21Z3D8RCvwk2-Ryn4wpsGnn2vma6Bw3E1f48hyVwaGF1dGhEYXRhWQFtarm78N-aFvkduzO7sTL6-dF8eCxIJsbscOzuWNl-9SpBAAAAJyNp1NATzkjLnyb37YyaYGgBDKMAWOhefOe7XWvT4OYhTQoOpLB6RjmIazaiJ-OqZL4RDCiIDRnCkvrwxgFBK6KtPlR55dS4c0JD0UJmAUx4xnKSymSki2tptgDSPvdR4186CXf8xTohJ7uwg8EE33_Smerj5ce5FCviSTh2q_iMkSnDYXP5Didns4JZo9SWLiCS6AxMl5SpJL4hXcJNb21i5zt6f6FkTlHiIB_0uAi1SzyCV5D3tGLzIKdxErPQrKzepLzE8rFUSLf4eSlKqWaNEygi_es8BZNV_9j8AiylpjsVS9-ZSX1Cjhxva3N25ipamUemjoGY3q2OgaVPAUyZAKnzr3VZahXhHMsCUIL3kexTr51baKs3eaGhMIykAQEDJyAGIVggjz9UkJ7cKooE3blSuzlqxkdLppMuFl3CIiST8odWS6k",
			"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQ1dieENUMEc0TDJ5T1JwQkw2U1dWaWd3ZTJrUUVYQmhvNUw2d0U0Ny1FcyIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4uZmlyc3R5ZWFyLmlkLmF1IiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"
		},
	"type":"public-key"
	}`,
}
