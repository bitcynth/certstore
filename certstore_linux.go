package certstore

import (
	"crypto"
	"crypto/x509"
	"math/big"

	"github.com/ThalesIgnite/crypto11"
	"github.com/pkg/errors"
)

var (
	// ErrLinuxNoU is a generic error
	ErrLinuxNoU = errors.New("No U!")
)

type linuxStore struct {
	ctx *crypto11.Context
}

type linuxIdent struct {
	cert   *x509.Certificate
	signer crypto.Signer
}

// Implement this function, just to silence other compiler errors.
func openStore() (*linuxStore, error) {
	slot := 1
	config := &crypto11.Config{
		Path:       "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so",
		SlotNumber: &slot,
	}

	ctx, err := crypto11.Configure(config)
	if err != nil {
		return nil, err
	}

	return &linuxStore{ctx: ctx}, nil
}

func (store *linuxStore) Identities() ([]Identity, error) {
	serial := new(big.Int)
	serial.SetString("04024FFB1E82B2A48FD1BA7B393DD897", 16)
	cert, err := store.ctx.FindCertificate(nil, nil, serial)
	if err != nil {
		panic(err)
	}

	signer, err := store.ctx.FindKeyPair(cert.SubjectKeyId, nil)
	if err != nil {
		panic(err)
	}

	ident := linuxIdent{
		cert:   cert,
		signer: signer,
	}
	idents := []Identity{&ident}
	return idents, nil
}

// PKCS#11 store doesn't support import (because I am lazy)
func (store *linuxStore) Import(data []byte, password string) error {
	return ErrLinuxNoU
}

func (store *linuxStore) Close() {
	store.ctx.Close()
}

func (ident *linuxIdent) Certificate() (*x509.Certificate, error) {
	return ident.cert, nil
}

func (ident *linuxIdent) CertificateChain() ([]*x509.Certificate, error) {
	return []*x509.Certificate{ident.cert}, nil
}

func (ident *linuxIdent) Delete() error {
	return ErrLinuxNoU
}

func (ident *linuxIdent) Signer() (crypto.Signer, error) {
	return ident.signer, nil
}

func (ident *linuxIdent) Close() {
}
