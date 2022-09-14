package example

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/mpcvault/mpcvault-go-sdk/proto/mpcvault/cloudmpc/v1"
	"math/big"
	"testing"
)

func TestCreateTx(t *testing.T) {
	tx := NewTx()
	fmt.Println("Tx Hash:", tx.Hash().Hex())
}

func TestSignTx(t *testing.T) {
	tx := NewTx()

	signer := types.NewLondonSigner((&big.Int{}).SetInt64(1))
	TxBytes := signer.Hash(tx).Bytes()

	resp, err := mpcvault.CloudMPCServiceClient.Sign(context.Background(), &cloudmpc.SignRequest{
		KeyId:       "793a91b7-fa8d-4578-bb2e-8d008987a01d",
		SigningAlgo: cloudmpc.SigningAlgo_SIGNING_ALGO_ECDSA,
		Message:     TxBytes,
	})

	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Message Signature S:", resp.S)
	fmt.Println("Message Signature R:", resp.R)
	fmt.Println("Message Signature V:", resp.V)

	var signature [65]byte
	r, _ := (&big.Int{}).SetString(resp.R, 10)
	s, _ := (&big.Int{}).SetString(resp.S, 10)
	v, _ := (&big.Int{}).SetString(resp.V, 10)

	copy(signature[:32], r.Bytes())
	copy(signature[32:64], s.Bytes())
	copy(signature[64:], v.Bytes())

	tx, err = tx.WithSignature(signer, signature[:])

	if err != nil {
		t.Fatal(err)
	}

	finalTxBytes, _ := tx.MarshalBinary()

	fmt.Println("sign tx (broadcast this):", hexutil.Encode(finalTxBytes))
	fmt.Println("You can decode the transaction here: https://flightwallet.github.io/decode-eth-tx/")
}

func NewTx() *types.Transaction {
	var nonce, gas uint64 = 3, 21000
	gasPrice, _ := (&big.Int{}).SetString("24000000000", 10) // 24Gwei
	value, _ := (&big.Int{}).SetString("1000000000000000000", 10)
	to := common.HexToAddress("0xea674fdde714fd979de3edf0f56aa9716b898ec8")

	tx := &types.LegacyTx{
		Nonce:    nonce,
		Gas:      gas,
		GasPrice: gasPrice,
		To:       &to,
		Value:    value,
		Data:     []byte{},
	}
	return types.NewTx(tx)
}
