// Package mpcvault provides the SDK for interacting with MPCVault
package mpcvault

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"github.com/mpcvault/mpcvault-go-sdk/proto/mpcvault/cloudmpc/v1"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"time"
)

//
// Public constants (DO NOT CHANGE THE FOLLOWING)
//

const (
	APIEndpoint         string = "api.mpcvault.com:443"
	ClientVersion       string = clientVersion
	MPCEnclavePublicKey string = mpcEnclavePublicKey
	GRPCServerCert      string = grpcServerCert
)

//
// Private constants (DO NOT CHANGE THE FOLLOWING)
//

const (
	clientVersion       = "1.0.0"
	mpcEnclavePublicKey = "Np0WXMI+b1/Zxkfm1QicN/vIrBjtSvZgfQ+NAyOiu1E="
	grpcServerCert      = `-----BEGIN CERTIFICATE-----
MIIEtDCCBFqgAwIBAgIQGEpDbE6YW1wzUeee8BcxNjAKBggqhkjOPQQDAjCBjzEL
MAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE
BxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTcwNQYDVQQDEy5T
ZWN0aWdvIEVDQyBEb21haW4gVmFsaWRhdGlvbiBTZWN1cmUgU2VydmVyIENBMB4X
DTIyMDkxMTAwMDAwMFoXDTIzMDkxMTIzNTk1OVowGzEZMBcGA1UEAxMQYXBpLm1w
Y3ZhdWx0LmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJnfPq9Dye6Ix1c4
ShPIDoNkTDMHmrvUXImS/bgLG5/AqSUviEKWWnNXNIJ/AHNmeNsYYXba4huu8BGl
bgcNZtCjggMJMIIDBTAfBgNVHSMEGDAWgBT2hQo7EYbhBH0Oqgss0u7MZHt7rjAd
BgNVHQ4EFgQUif6M3Xr+uVSPmjguui0E2yVSA2gwDgYDVR0PAQH/BAQDAgeAMAwG
A1UdEwEB/wQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMEkGA1Ud
IARCMEAwNAYLKwYBBAGyMQECAgcwJTAjBggrBgEFBQcCARYXaHR0cHM6Ly9zZWN0
aWdvLmNvbS9DUFMwCAYGZ4EMAQIBMIGEBggrBgEFBQcBAQR4MHYwTwYIKwYBBQUH
MAKGQ2h0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb0VDQ0RvbWFpblZhbGlk
YXRpb25TZWN1cmVTZXJ2ZXJDQS5jcnQwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3Nw
LnNlY3RpZ28uY29tMDEGA1UdEQQqMCiCEGFwaS5tcGN2YXVsdC5jb22CFHd3dy5h
cGkubXBjdmF1bHQuY29tMIIBfwYKKwYBBAHWeQIEAgSCAW8EggFrAWkAdgCt9776
fP8QyIudPZwePhhqtGcpXc+xDCTKhYY069yCigAAAYMr5f6lAAAEAwBHMEUCIQD/
uss8qxaEs/VKrhqpNhskk3Uex+WQb1FskOq2bAIhSwIgLfhY9u7uOKOBo8Uzpk+A
vm6DIFVYRml6gjZhGT1gF+AAdwB6MoxU2LcttiDqOOBSHumEFnAyE4VNO9IrwTpX
o1LrUgAAAYMr5f6MAAAEAwBIMEYCIQD8D3oEM6zQAKgZz/ljikOdoSauncbBzGWR
5IUfCV/YNgIhAOccFukiLXuFZ0xkOhLlSBsaOUF5G8bkLjFU2CbpRlY6AHYA6D7Q
2j71BjUy51covIlryQPTy9ERa+zraeF3fW0GvW4AAAGDK+X+YwAABAMARzBFAiEA
o9nDR4zHmKrmbSI627G++h4SZOAEkIObpccNfAn3MPkCIHLCUMGGfNysnazpEWp4
1nGeOclnG6k1ETj4oBG18+WbMAoGCCqGSM49BAMCA0gAMEUCIQCqn20qsd1bvRfa
5ocCPvpQpgNcWafqbR/Th62I5Em25wIgWll0fkIvGYaZjW9tWJ9VjTWMeF9gefCR
ZcUF8z8U+vQ=
-----END CERTIFICATE-----`
)

// API is a MPCVault API client
type API struct {
	CloudMPCServiceClient cloudmpc.CloudMPCServiceClient

	apiKey            string
	ed25519PrivateKey *ed25519.PrivateKey
	sealedKey         string

	PrintRequestLog bool
}

type idempotentRequestCallOption struct {
	grpc.EmptyCallOption
	idempotentKey string
}

// NewIdempotentRequestCallOption creates a grpc call option which sets the idempotent key of this reqeust
func NewIdempotentRequestCallOption(idempotentKey string) grpc.CallOption {
	return idempotentRequestCallOption{idempotentKey: idempotentKey}
}

func (a *API) f(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	start := time.Now()
	ctx = a.createHeader(ctx, opts...)
	err := invoker(ctx, method, req, reply, cc, opts...)
	// Logic after invoking the invoker
	if a.PrintRequestLog {
		log.WithField("Method", method).
			WithField("Duration", time.Since(start)).
			WithField("Error", err).
			Infof("Invoked RPC")
	}
	return err
}

// SetUp initialises the client with apiKey, ed25519PrivateKey in SSH key format and ed25519PrivateKeyPassword
func (a *API) SetUp(apiKey string, ed25519PrivateKey string, ed25519PrivateKeyPassword string) (err error) {
	a.apiKey = apiKey
	a.PrintRequestLog = true

	// process ed25519 key certificate
	var passwordsBytes []byte
	if len(ed25519PrivateKeyPassword) != 0 {
		passwordsBytes = []byte(ed25519PrivateKeyPassword)
	}
	a.ed25519PrivateKey, err = LoadPrivateKeyFromBytes([]byte(ed25519PrivateKey), passwordsBytes)
	if err != nil {
		return err
	}

	// calculate and assign sealed key
	serverPublicKeyBytes, err := base64.StdEncoding.DecodeString(MPCEnclavePublicKey)
	if err != nil {
		panic(err)
	}
	serverPublicKey := ed25519.PublicKey(serverPublicKeyBytes)
	sealedBytes, err := box(
		a.ed25519PrivateKey.Seed(),
		&serverPublicKey,
	)
	if err != nil {
		panic(err)
	}
	a.sealedKey = base64.StdEncoding.EncodeToString(sealedBytes)

	// grpc TLS certificate
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM([]byte(GRPCServerCert)) {
		panic("credentials: failed to append certificates")
	}
	creds := credentials.NewTLS(&tls.Config{RootCAs: cp})

	// create grpc client
	conn, err := grpc.Dial(
		APIEndpoint,
		grpc.WithTransportCredentials(creds),
		grpc.WithUnaryInterceptor(a.f),
	)
	if err != nil {
		return err
	}
	a.CloudMPCServiceClient = cloudmpc.NewCloudMPCServiceClient(conn)

	return nil
}

func (a *API) createHeader(context context.Context, opts ...grpc.CallOption) context.Context {
	md := metadata.MD{}
	md.Set("api-token", a.apiKey)
	md.Set("sealed-key", a.sealedKey)
	md.Set("client-version", ClientVersion)
	for _, o := range opts {
		if v, ok := o.(idempotentRequestCallOption); ok {
			md.Set("idempotency-key", v.idempotentKey)
			break
		}
	}
	return metadata.NewOutgoingContext(context, md)
}
