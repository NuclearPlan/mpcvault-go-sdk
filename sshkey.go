package mpcvault

import (
	"crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"os"
)

func LoadPrivateKeyFromBytes(b []byte, password []byte) (*ed25519.PrivateKey, error) {
	key, err := parseEncryptedRawPrivateKey(b, password)
	if err != nil {
		return nil, err
	}
	k := key.(*ed25519.PrivateKey)

	return k, nil
}

func LoadPrivateKeyFromFile(path string, password []byte) (*ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadPrivateKeyFromBytes(b, password)
}

// parseEncryptedRawPrivateKey returns a private key from an encrypted private key. It
// supports RSA (PKCS#1 or OpenSSH), DSA (OpenSSL), and ECDSA private keys.
//
// ErrIncorrectPassword will be returned if the supplied passphrase is wrong,
// but some formats like RSA in PKCS#1 detecting a wrong passphrase is difficult,
// and other parse errors may be returned.
func parseEncryptedRawPrivateKey(data []byte, passphrase []byte) (interface{}, error) {
	if passphrase == nil {
		return ssh.ParseRawPrivateKey(data)
	}
	return ssh.ParseRawPrivateKeyWithPassphrase(data, passphrase)
}
