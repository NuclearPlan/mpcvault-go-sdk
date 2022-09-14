package example

import (
	"context"
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/google/uuid"
	sdk "github.com/mpcvault/mpcvault-go-sdk"
	"github.com/mpcvault/mpcvault-go-sdk/proto/mpcvault/cloudmpc/v1"
	"math/big"
	"testing"

	"fmt"
)

// Initialization variables (please change the following value to your apikey and private key
var apiKey = "FtCeDztyafURQcYC5wpvouqXsxvgxPqt4thdhf9a7u4="

var privateKey = `
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBxUORWXl
z0HeGDdvfKJ1DjAAAAZAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIDcjhEh4X89v8gHT
MYRR3r7Jxd/fQuU7ZD9pMQ5EIL53AAAAoOJFbcFWr9bTfnWixq2Ucrr/uwzumGxlOxpgQK
8TOzY43rELvlSgCC6wnJb0hk+H2iD1sREfR1xEPwcxOwZLdYm+7maIxotzUKtRnHJGOEDC
PtBBXIzUrD1TPvMRjlUst9aw017xf1zrQiL6grVsu3Um4Lniq3orWYT92pRgh0iw48M5MV
ej9RRBh1dhR52V74k8CHyDVPpV3mLTtMFG00g=
-----END OPENSSH PRIVATE KEY-----
`

var mpcvault *sdk.API

func init() {
	mpcvault = &sdk.API{}
	err := mpcvault.SetUp(apiKey, privateKey, "1234qwer")
	if err != nil {
		panic(err)
	}
}

func GenerateEthereumAddressFromPublicKey(x, y string) string {
	parsedX, _ := (&big.Int{}).SetString(x, 10)
	parsedY, _ := (&big.Int{}).SetString(y, 10)
	parsedPubKey := &ecdsa.PublicKey{Curve: secp256k1.S256(), X: parsedX, Y: parsedY}
	return crypto.PubkeyToAddress(*parsedPubKey).String()
}

func TestGenerateWalletAddress(t *testing.T) {
	idempotentKey := uuid.NewString()
	resp, err := mpcvault.CloudMPCServiceClient.CreateKey(
		context.Background(),
		&cloudmpc.CreateKeyRequest{
			KeyType: cloudmpc.KeyType_KEY_TYPE_ECC_SECP256K1,
		},
		// setting idempotent key using sdk.NewIdempotentRequestCallOption
		// if you reuse the same idempotent key within the first 24 hours of making the reqeust,
		//you get back the same response and by extension, the same key
		sdk.NewIdempotentRequestCallOption(idempotentKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("idempotentKey:", idempotentKey)
	fmt.Println("key id:", resp.KeyId)
	fmt.Println("ethereum address:", GenerateEthereumAddressFromPublicKey(resp.X, resp.Y))
}

func TestDescribeKeyAndGenerateWalletAddress(t *testing.T) {
	resp, err := mpcvault.CloudMPCServiceClient.DescribeKey(context.Background(), &cloudmpc.DescribeKeyRequest{
		KeyId: "793a91b7-fa8d-4578-bb2e-8d008987a01d",
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("ethereum address:", GenerateEthereumAddressFromPublicKey(resp.X, resp.Y))
}

func TestSignAndVerify(t *testing.T) {
	// Sign message
	message := []byte("test-message")
	keyID := "793a91b7-fa8d-4578-bb2e-8d008987a01d"
	resp, err := mpcvault.CloudMPCServiceClient.Sign(context.Background(), &cloudmpc.SignRequest{
		KeyId:       keyID,
		SigningAlgo: cloudmpc.SigningAlgo_SIGNING_ALGO_ECDSA,
		Message:     message,
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Message Signature S:", resp.S)
	fmt.Println("Message Signature R:", resp.R)
	fmt.Println("Message Signature V:", resp.V)

	r, _ := (&big.Int{}).SetString(resp.R, 10)
	s, _ := (&big.Int{}).SetString(resp.S, 10)

	resp1, err := mpcvault.CloudMPCServiceClient.DescribeKey(context.Background(), &cloudmpc.DescribeKeyRequest{
		KeyId: keyID,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify signature
	parsedX, _ := (&big.Int{}).SetString(resp1.X, 10)
	parsedY, _ := (&big.Int{}).SetString(resp1.Y, 10)
	parsedPubKey := &ecdsa.PublicKey{Curve: secp256k1.S256(), X: parsedX, Y: parsedY}

	pass := ecdsa.Verify(
		parsedPubKey,
		message, r, s)
	if !pass {
		t.Fatal("Sign Verify failed")
	}
	fmt.Println("Sign Verify:", pass)
}
