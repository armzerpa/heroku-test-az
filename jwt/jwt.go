package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	jose "github.com/go-jose/go-jose/v3"
)

const rootPEM = `
-----BEGIN CERTIFICATE-----
MIIGqzCCBZOgAwIBAgIQCxe4C5hTBxSp8iq4fvd4QjANBgkqhkiG9w0BAQsFADBP
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMSkwJwYDVQQDEyBE
aWdpQ2VydCBUTFMgUlNBIFNIQTI1NiAyMDIwIENBMTAeFw0yMjA4MDkwMDAwMDBa
Fw0yMzA5MDkyMzU5NTlaMFwxCzAJBgNVBAYTAkNPMQ8wDQYDVQQHEwZCT0dPVEEx
HzAdBgNVBAoTFlJFREVCQU4gTVVMVElDT0xPUiBTLkExGzAZBgNVBAMTEnd3dy50
eHN0ZXN0cmJtLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK+T
0DEzBlSdSXtjbHzMjoZKUEWXyKkEU4QMKCI7Zm4ejAqFOK9lBYooUeWm66s+/wsE
lBkLSURmA9pisjp+wWBagZLHJOyyorWPBy+pkvYZRGVnizsph0DXXBy6y5yNZ7u/
gdh6FB53gs0JI1P0cvzRApUOkukg+E1oPRx4z/ubNy58B5oIRXRZ5obC3codQb0N
EApDi3VaBOS6eVh4symBA6vFSGAvZB1uw55dp+UksvJ1Fidao0JCZ5yefi5g9KjT
WctWSHVGvOjaXdzz7iUM3xOr9UcIJvny30HyayG3DemcBYeQgIxZrQ+lyO4aPqex
jvcfYC6B2EoOpvL8raECAwEAAaOCA3QwggNwMB8GA1UdIwQYMBaAFLdrouqoqoSM
eeq02g+YssWVdrn0MB0GA1UdDgQWBBSzfYSAIb93PuKTP6WB4o9OC86zWDAdBgNV
HREEFjAUghJ3d3cudHhzdGVzdHJibS5jb20wDgYDVR0PAQH/BAQDAgWgMB0GA1Ud
JQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjCBjwYDVR0fBIGHMIGEMECgPqA8hjpo
dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUTFNSU0FTSEEyNTYyMDIw
Q0ExLTQuY3JsMECgPqA8hjpodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNl
cnRUTFNSU0FTSEEyNTYyMDIwQ0ExLTQuY3JsMD4GA1UdIAQ3MDUwMwYGZ4EMAQIC
MCkwJwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzB/Bggr
BgEFBQcBAQRzMHEwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNv
bTBJBggrBgEFBQcwAoY9aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lD
ZXJ0VExTUlNBU0hBMjU2MjAyMENBMS0xLmNydDAJBgNVHRMEAjAAMIIBgAYKKwYB
BAHWeQIEAgSCAXAEggFsAWoAdgDoPtDaPvUGNTLnVyi8iWvJA9PL0RFr7Otp4Xd9
bQa9bgAAAYKBEDTXAAAEAwBHMEUCIFcrvpZc7E3/0JSo/kYN0mpYjwwwRcyzJfC4
E2XwkL0FAiEAji+RiZ4T8ceSV7Zs6yC4FdFcigyuRD2nkm7qhPAlRiUAdwA1zxkb
v7FsV78PrUxtQsu7ticgJlHqP+Eq76gDwzvWTAAAAYKBEDUYAAAEAwBIMEYCIQCI
yZww+gxXHgj00nwbN7RqGQPnWYAv0IgSs7lQgmx+rAIhAMRyOZjTqEM5V1RjlTHz
JkVNITA/BNq6w+pPBkH3WRnfAHcAtz77JN+cTbp18jnFulj0bF38Qs96nzXEnh0J
gSXttJkAAAGCgRA1LgAABAMASDBGAiEAlHOf65l9t/heqo+RuG91AlQD/W7sKTV4
XEH9oj3PNeECIQC116WfNhA1xPdtpb5HHdiuKJdJqY0ydanxJhXjmxIQnDANBgkq
hkiG9w0BAQsFAAOCAQEAbqDCmJxGB0GRfBKe23Wb8i3pJLZhPAjC5mnANTlcnHoz
sdK5Zc6/XS8zb6r8K49TvfGrI6f8nCkM2k9GXuxz2H7UXEGcpoyE008bASTfRYkc
UmZMB/PM8UFxg21KuQ4/MZlKN9XK1XFWblBQe2Zf6/hAXtR8bnAd6NpdHgF2rmWN
OB6RVHVJykBt84I5Ml9DWFcIwQXSX5XcmRCq9MeTgR3xlFoAyK4QIp14IKwXMScS
jaDNwr8sQcPBzjv6Odw8s2MCxGaR/MQpxAiGXJhSPorY3CjLLtCx2RX3g9EIePlN
A2BUJt1pQu+ZlGi1tsE/ps2s9jgebnNpoxGumXaRNg==
-----END CERTIFICATE-----`

const privateKEY = `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC3zZ6ifKVxnzYK
+FBDaz/TKGippOE5767kKssKmPp70X0dYIhfLdzbrgr1LYgEblN4/aDzWip73ap4
Upm+Z9QoDgD5GUJteqkxZhcSi75aJaORn6EqA3+XvhLQl1JvPYxuwnkXbHakrz+r
joQIm05rxwfaCu5QFPZslXQv97lsXdgvKkLavIiNLB7l+sZGxT8xRlvj1/QudPst
RhF8YfLRLwe+40Fyv1HaHLhDhyv2nlmJ3rvx5JDcpQSirNknK94P2uxIy6UN4NXv
3KdPJFWus0zDFCUrScF4rxiq22QIH5znwij8ODcpfun/1TPNNA6+rXgClCuac8ty
kwGLHqFBAgMBAAECggEAAZFYbAxiIOD5xgguLxUIG1X55pCId0ULGdkfmDyLzmiQ
B6MeJqmue5U1dLfptBf40ExhhhHb0OioHpSdyRj7n0fXTEih32svbENxqO/WNNCj
X4ecCU60VOgDIxJXWqmMvBkejUuYi3kPMvhpOeWROqwc7ggv1jEHlQ+FSS90vm7e
yNhqQFtc6zVIeCAWQeyiL7XR25+WO4vceBWks7j4j2eNoqrBNXQ7nSdnHNaLFJ/F
Pss/0i85xAve4Xh/ykM2v6BJHRHM83EZ08puufLZhKVuekI8WHGuxzuiTu3eaIQO
I+CtxvMU+ftmGtqf0Ebfg4ZOv7LHM1HLlYtDCKsh0QKBgQDXiYe0iVUQ96Nbjicx
19AXDg7yx0fraWZqOxPRGkKavH8Ejzga7Wa7rKIUUTvIkkneBJPYj1uPOJIv/Z/R
jYYXwP7nU0x4zFKAHfsb0H1CfpK/N1qnW2mVtl4/h8/il38ngFwyo3+SeIeX5Zvf
eAM9ib0pcv5t7zs+bwwOYUxKZQKBgQDaTv0wFSFF3OI2j+ajinw0WFZKrugHVbrA
mUzpNASnItUWxxMqFsZ3UTE+oHojM2V8otVeYK6U+stsEsmXDQ1Ex0mXV/9keWdJ
C+xMlF72G//7I+YYSpigk9976bgAk61wZaY8IHTmJn12n51RLB4i/+WmB1RMggGj
waa+EmO/rQKBgQCZgeYY+saPMxAxoOjhYuddxDF5T901GPhMKI9Qmfdd5WpBgQ9g
fjxw5d75wXFmxGm/qlryHggD1TKo42X0BWu/d0EU2Ara7grEHJY/lRnhReyWK4Jx
N3XXnu85KC0zINr68zy3BCNT2mwYDvwZCIymQ3dqEfCLs5rqOITJqRqA0QKBgFJ7
D4vwH88eglVtDw3xD7ZTPd8fsEi9Kj8EbJubbLqdHXdqpaH8UuXXxkxMI3lTPN/X
QdhTnQJqsxrVCldIth+rT/GfbL3QZKajm5bfY/WGZLPFP3UkEgBxfjl592w4X4oc
za7f8GrYVgTQj4aQrZ45otGU6VOytt3hF5euqQNNAoGAI0Ckzja7JG5DY+CdG4JB
lZZgsChYCP2NYjJXtwDkA0TTshZfPWwCfIC18RP69fODG2jKh29AwrayNQQIv4RE
s68+Y5x16wTEju4Mbh8t5T/O5KEtNHSobB+eJV9t3PUffdp1fpT3tee4Db7a8xti
NfI6QA6OUXeDdcapoN1PQ3c=
-----END PRIVATE KEY-----`

const publicKEY = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr5PQMTMGVJ1Je2NsfMyO
hkpQRZfIqQRThAwoIjtmbh6MCoU4r2UFiihR5abrqz7/CwSUGQtJRGYD2mKyOn7B
YFqBksck7LKitY8HL6mS9hlEZWeLOymHQNdcHLrLnI1nu7+B2HoUHneCzQkjU/Ry
/NEClQ6S6SD4TWg9HHjP+5s3LnwHmghFdFnmhsLdyh1BvQ0QCkOLdVoE5Lp5WHiz
KYEDq8VIYC9kHW7Dnl2n5SSy8nUWJ1qjQkJnnJ5+LmD0qNNZy1ZIdUa86Npd3PPu
JQzfE6v1Rwgm+fLfQfJrIbcN6ZwFh5CAjFmtD6XI7ho+p7GO9x9gLoHYSg6m8vyt
oQIDAQAB
-----END PUBLIC KEY-----`

func EncryptStringData(data string) string {
	jws := jws(data)
	jwe := jwe(jws)
	return jwe
}

func EncryptRawData(data []byte) string {
	jws := jwsRaw(data)
	jwe := jwe(jws)
	return jwe
}

func jwsRaw(data []byte) string {
	var privateKey = getPrivateKey(privateKEY)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS512, Key: privateKey}, nil)
	if err != nil {
		panic(err)
	}
	var payload = data
	object, err := signer.Sign(payload)
	if err != nil {
		panic(err)
	}
	serialized := object.FullSerialize()
	return serialized
}

func jws(data string) string {
	var privateKey = getPrivateKey(privateKEY)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS512, Key: privateKey}, nil)
	if err != nil {
		panic(err)
	}
	var payload = []byte(data)
	object, err := signer.Sign(payload)
	if err != nil {
		panic(err)
	}
	serialized := object.FullSerialize()
	return serialized
}

func getPrivateKey(data string) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		panic("failed to decode key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic("failed to parse RSA key: " + err.Error())
	}
	if key, ok := key.(*rsa.PrivateKey); ok {
		return key
	}
	panic("key is not of type *rsa.PrivateKey")
}

func getPublicKey(data string) *rsa.PublicKey {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		panic("failed to decode key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("failed to parse RSA key: " + err.Error())
	}
	if key, ok := key.(*rsa.PublicKey); ok {
		return key
	}
	panic("key is not of type *rsa.PrivateKey")
}

func jwe(jws string) string {
	var cert = getCertificate(rootPEM)

	encrypter, err := jose.NewEncrypter(jose.A256CBC_HS512, jose.Recipient{Algorithm: jose.RSA_OAEP, Key: cert.PublicKey}, nil)
	if err != nil {
		panic(err)
	}

	var plaintext = []byte(jws)
	object, err := encrypter.Encrypt(plaintext)
	if err != nil {
		panic(err)
	}

	serialized := object.FullSerialize()

	object, err = jose.ParseEncrypted(serialized)
	if err != nil {
		panic(err)
	}

	return serialized
}

func getCertificate(data string) *x509.Certificate {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		panic("failed to decode certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	return cert
}
