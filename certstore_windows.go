package main

/*
#cgo windows LDFLAGS: -lcrypt32 -lpthread -lncrypt -lbcrypt

#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <winerror.h>
#include <stdio.h>

char* errMsg(DWORD code) {
	char* lpMsgBuf;
	DWORD ret = 0;

	ret = FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			code,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR) &lpMsgBuf,
			0, NULL);

	if (ret == 0) {
		return NULL;
	} else {
		return lpMsgBuf;
	}
}
*/
import "C"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"unicode/utf16"
	"unsafe"

	"github.com/pkg/errors"
)

const (
	winTrue  C.WINBOOL = 1
	winFalse C.WINBOOL = 0
)

// winAPIFlag specifies the flags that should be passed to
// CryptAcquireCertificatePrivateKey. This impacts whether the CryptoAPI or CNG
// API will be used.
//
// Possible values are:
//   0x00000000 —                                      — Only use CryptoAPI.
//   0x00010000 — CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG  — Prefer CryptoAPI.
//   0x00020000 — CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG — Prefer CNG.
//   0x00040000 — CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG   — Only uyse CNG.
var winAPIFlag C.DWORD = C.CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG

// winIdentity implements the Identity iterface.
type winIdentity struct {
	ctx    C.PCCERT_CONTEXT
	signer *winPrivateKey
	closed bool
}

func newWinIdentity(ctx C.PCCERT_CONTEXT) *winIdentity {
	return &winIdentity{ctx: C.CertDuplicateCertificateContext(ctx)}
}

// FindIdentities returns a slice of available signing identities.
func FindIdentities() ([]Identity, error) {
	store, err := openMyCertStore()
	if err != nil {
		return nil, errors.Wrap(err, "openMyCertStore failed")
	}
	defer store.Close()

	idents, err := findIdentities(store)
	if err != nil {
		return nil, errors.Wrap(err, "findIdentities failed")
	}

	return idents, nil
}

func findIdentities(store *winStore) ([]Identity, error) {
	idents := make([]Identity, 0)

	for ctx := store.nextCert(); ctx != nil; ctx = store.nextCert() {
		idents = append(idents, newWinIdentity(ctx))
	}

	if err := store.getError(); err != nil {
		for _, ident := range idents {
			ident.Close()
		}

		return nil, errors.Wrap(err, "identity iteration failed")
	}

	return idents, nil
}

// GetCertificate implements the Identity iterface.
func (i *winIdentity) GetCertificate() (*x509.Certificate, error) {
	if err := i._check(); err != nil {
		return nil, err
	}

	der := C.GoBytes(unsafe.Pointer(i.ctx.pbCertEncoded), C.int(i.ctx.cbCertEncoded))

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.Wrap(err, "certificate parsing failed")
	}

	return cert, nil
}

// GetSigner implements the Identity interface.
func (i *winIdentity) GetSigner() (crypto.Signer, error) {
	return i.getPrivateKey()
}

// getPrivateKey gets this identity's private *winPrivateKey.
func (i *winIdentity) getPrivateKey() (*winPrivateKey, error) {
	if err := i._check(); err != nil {
		return nil, err
	}

	if i.signer != nil {
		return i.signer, nil
	}

	cert, err := i.GetCertificate()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get identity certificate")
	}

	signer, err := newWinPrivateKey(i.ctx, cert.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load identity private key")
	}

	i.signer = signer

	return i.signer, nil
}

// Destroy implements the Identity iterface.
func (i *winIdentity) Destroy() error {
	// duplicate cert context, since CertDeleteCertificateFromStore will free it.
	deleteCtx := C.CertDuplicateCertificateContext(i.ctx)

	// try deleting cert
	if ok := C.CertDeleteCertificateFromStore(deleteCtx); ok == winFalse {
		return lastError("failed to delete certificate from store")
	}

	wpk, err := i.getPrivateKey()
	if err != nil {
		return errors.Wrap(err, "failed to get identity private key")
	}

	if err := wpk.Delete(); err != nil {
		return errors.Wrap(err, "failed to delete identity private key")
	}

	return nil
}

// Close implements the Identity iterface.
func (i *winIdentity) Close() {
	if err := i._check(); err != nil {
		return
	}

	if i.signer != nil {
		i.signer.Close()
	}

	C.CertFreeCertificateContext(i.ctx)
}

func (i *winIdentity) _check() error {
	if i == nil {
		return errors.New("nil winIdentity pointer")
	}

	if i.ctx == nil {
		return errors.New("nil certificate context")
	}

	if i.closed {
		return errors.New("identity closed")
	}

	return nil
}

// winPrivateKey is a wrapper around a HCRYPTPROV_OR_NCRYPT_KEY_HANDLE.
type winPrivateKey struct {
	publicKey crypto.PublicKey

	// CryptoAPI fields
	capiProv C.HCRYPTPROV

	// CNG fields
	cngHandle C.NCRYPT_KEY_HANDLE
	keySpec   C.DWORD
}

// newWinPrivateKey gets a *winPrivateKey for the given certificate.
func newWinPrivateKey(certCtx C.PCCERT_CONTEXT, publicKey crypto.PublicKey) (*winPrivateKey, error) {
	var (
		provOrKey C.HCRYPTPROV_OR_NCRYPT_KEY_HANDLE
		keySpec   C.DWORD
		mustFree  C.WINBOOL
	)

	if publicKey == nil {
		return nil, errors.New("nil public key")
	}

	// Search for cert private key and store it's association with the cert.
	if ok := C.CryptFindCertificateKeyProvInfo(certCtx, C.CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, nil); ok == winFalse {
		return nil, lastError("failed to find private key for certificate")
	}

	// Get a handle for the found private key.
	if ok := C.CryptAcquireCertificatePrivateKey(certCtx, winAPIFlag, nil, &provOrKey, &keySpec, &mustFree); ok == winFalse {
		return nil, lastError("failed to get private key for certificate")
	}

	if mustFree != winTrue {
		// This shouldn't happen since we're not asking for cached keys.
		return nil, errors.New("CryptAcquireCertificatePrivateKey set mustFree")
	}

	if keySpec == C.CERT_NCRYPT_KEY_SPEC {
		return &winPrivateKey{
			publicKey: publicKey,
			cngHandle: C.NCRYPT_KEY_HANDLE(provOrKey),
		}, nil
	} else {
		return &winPrivateKey{
			publicKey: publicKey,
			capiProv:  C.HCRYPTPROV(provOrKey),
			keySpec:   keySpec,
		}, nil
	}
}

// PublicKey implements the crypto.Signer interface.
func (wpk *winPrivateKey) Public() crypto.PublicKey {
	return wpk.publicKey
}

// Sign implements the crypto.Signer interface.
func (wpk *winPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if wpk.capiProv != 0 {
		return wpk.capiSignHash(opts.HashFunc(), digest)
	} else if wpk.cngHandle != 0 {
		return wpk.cngSignHash(opts.HashFunc(), digest)
	} else {
		return nil, errors.New("bad private key")
	}
}

// cngSignHash signs a digest using the CNG APIs.
func (wpk *winPrivateKey) cngSignHash(hash crypto.Hash, digest []byte) ([]byte, error) {
	if len(digest) != hash.Size() {
		return nil, errors.New("bad digest for hash")
	}

	var (
		// input
		padPtr    = unsafe.Pointer(nil)
		digestPtr = (*C.BYTE)(&digest[0])
		digestLen = C.DWORD(len(digest))
		flags     = C.DWORD(0)

		// output
		sigLen = C.DWORD(0)
	)

	// setup pkcs1v1.5 padding for RSA
	if _, isRSA := wpk.publicKey.(*rsa.PublicKey); isRSA {
		flags |= C.BCRYPT_PAD_PKCS1
		padInfo := C.BCRYPT_PKCS1_PADDING_INFO{}
		padPtr = unsafe.Pointer(&padInfo)

		switch hash {
		case crypto.SHA1:
			padInfo.pszAlgId = BCRYPT_SHA1_ALGORITHM
		case crypto.SHA256:
			padInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM
		case crypto.SHA384:
			padInfo.pszAlgId = BCRYPT_SHA384_ALGORITHM
		case crypto.SHA512:
			padInfo.pszAlgId = BCRYPT_SHA512_ALGORITHM
		default:
			return nil, errors.New("unsupported hash algorithm")
		}
	}

	// get signature length
	if err := checkStatus(C.NCryptSignHash(wpk.cngHandle, padPtr, digestPtr, digestLen, nil, 0, &sigLen, flags)); err != nil {
		return nil, errors.Wrap(err, "failed to get signature length")
	}

	// get signature
	sig := make([]byte, sigLen)
	sigPtr := (*C.BYTE)(&sig[0])
	if err := checkStatus(C.NCryptSignHash(wpk.cngHandle, padPtr, digestPtr, digestLen, sigPtr, sigLen, &sigLen, flags)); err != nil {
		return nil, errors.Wrap(err, "failed to sign digest")
	}

	// CNG returns a raw ECDSA signature, but we wan't ASN.1 DER encoding.
	if _, isEC := wpk.publicKey.(*ecdsa.PublicKey); isEC {
		if len(sig)%2 != 0 {
			return nil, errors.New("bad ecdsa signature from CNG")
		}

		type ecdsaSignature struct {
			R, S *big.Int
		}

		r := new(big.Int).SetBytes(sig[:len(sig)/2])
		s := new(big.Int).SetBytes(sig[len(sig)/2:])

		encoded, err := asn1.Marshal(ecdsaSignature{r, s})
		if err != nil {
			return nil, errors.Wrap(err, "failed to ASN.1 encode EC signature")
		}

		return encoded, nil
	}

	return sig, nil
}

// capiSignHash signs a digest using the CryptoAPI APIs.
func (wpk *winPrivateKey) capiSignHash(hash crypto.Hash, digest []byte) ([]byte, error) {
	if len(digest) != hash.Size() {
		return nil, errors.New("bad digest for hash")
	}

	// Figure out which CryptoAPI hash algorithm we're using.
	var hash_alg C.ALG_ID

	switch hash {
	case crypto.SHA1:
		hash_alg = C.CALG_SHA1
	case crypto.SHA256:
		hash_alg = C.CALG_SHA_256
	case crypto.SHA384:
		hash_alg = C.CALG_SHA_384
	case crypto.SHA512:
		hash_alg = C.CALG_SHA_512
	default:
		return nil, errors.New("unsupported hash algorithm")
	}

	// Instantiate a CryptoAPI hash object.
	var chash C.HCRYPTHASH

	if ok := C.CryptCreateHash(C.HCRYPTPROV(wpk.capiProv), hash_alg, 0, 0, &chash); ok == winFalse {
		return nil, lastError("failed to create hash")
	}
	defer C.CryptDestroyHash(chash)

	// Make sure the hash size matches.
	var (
		hashSize    C.DWORD
		hashSizePtr = (*C.BYTE)(unsafe.Pointer(&hashSize))
		hashSizeLen = C.DWORD(unsafe.Sizeof(hashSize))
	)

	if ok := C.CryptGetHashParam(chash, C.HP_HASHSIZE, hashSizePtr, &hashSizeLen, 0); ok == winFalse {
		return nil, lastError("failed to get hash size")
	}

	if hash.Size() != int(hashSize) {
		return nil, errors.New("invalid CryptoAPI hash")
	}

	// Put our digest into the hash object.
	digestPtr := (*C.BYTE)(unsafe.Pointer(&digest[0]))
	if ok := C.CryptSetHashParam(chash, C.HP_HASHVAL, digestPtr, 0); ok == winFalse {
		return nil, lastError("failed to set hash digest")
	}

	// Get signature length.
	var sigLen C.DWORD

	if ok := C.CryptSignHash(chash, wpk.keySpec, nil, 0, nil, &sigLen); ok == winFalse {
		return nil, lastError("failed to get signature length")
	}

	// Get signature
	var (
		sig    = make([]byte, int(sigLen))
		sigPtr = (*C.BYTE)(unsafe.Pointer(&sig[0]))
	)

	if ok := C.CryptSignHash(chash, wpk.keySpec, nil, 0, sigPtr, &sigLen); ok == winFalse {
		return nil, lastError("failed to sign digest")
	}

	// Signature is little endian, but we want big endian. Reverse it.
	for i := len(sig)/2 - 1; i >= 0; i-- {
		opp := len(sig) - 1 - i
		sig[i], sig[opp] = sig[opp], sig[i]
	}

	return sig, nil
}

func (wpk *winPrivateKey) Delete() error {
	if wpk.cngHandle != 0 {
		// Delete CNG key
		if err := checkStatus(C.NCryptDeleteKey(wpk.cngHandle, 0)); err != nil {
			return err
		}
	} else if wpk.capiProv != 0 {
		// Delete CryptoAPI key
		var (
			param unsafe.Pointer
			err   error

			containerName C.LPCTSTR
			providerName  C.LPCTSTR
			providerType  *C.DWORD
		)

		if param, err = wpk.getProviderParam(C.PP_CONTAINER); err != nil {
			return errors.Wrap(err, "failed to get PP_CONTAINER")
		} else {
			containerName = C.LPCTSTR(param)
		}

		if param, err = wpk.getProviderParam(C.PP_NAME); err != nil {
			return errors.Wrap(err, "failed to get PP_NAME")
		} else {
			providerName = C.LPCTSTR(param)
		}

		if param, err = wpk.getProviderParam(C.PP_PROVTYPE); err != nil {
			return errors.Wrap(err, "failed to get PP_PROVTYPE")
		} else {
			providerType = (*C.DWORD)(param)
		}

		// use CRYPT_SILENT too?
		var prov C.HCRYPTPROV
		if ok := C.CryptAcquireContext(&prov, containerName, providerName, *providerType, C.CRYPT_DELETEKEYSET); ok == winFalse {
			return lastError("failed to delete key set")
		}
	} else {
		return errors.New("bad private key")
	}

	return nil
}

// getProviderParam gets a parameter about a provider.
func (wpk *winPrivateKey) getProviderParam(param C.DWORD) (unsafe.Pointer, error) {
	var dataLen C.DWORD
	if ok := C.CryptGetProvParam(wpk.capiProv, param, nil, &dataLen, 0); ok == winFalse {
		return nil, lastError("failed to get provider parameter size")
	}

	data := make([]byte, dataLen)
	dataPtr := (*C.BYTE)(unsafe.Pointer(&data[0]))
	if ok := C.CryptGetProvParam(wpk.capiProv, param, dataPtr, &dataLen, 0); ok == winFalse {
		return nil, lastError("failed to get provider parameter")
	}

	// TODO leaking memory here
	return C.CBytes(data), nil
}

// Close closes this winPrivateKey.
func (wpk *winPrivateKey) Close() {
	if wpk.cngHandle != 0 {
		C.NCryptFreeObject(C.NCRYPT_HANDLE(wpk.cngHandle))
	}

	if wpk.capiProv != 0 {
		C.CryptReleaseContext(wpk.capiProv, 0)
	}
}

// winStore is a wrapper around a C.HCERTSTORE.
type winStore struct {
	store  C.HCERTSTORE
	prev   C.PCCERT_CONTEXT
	err    error
	closed bool
}

// openMyCertStore open the current user's personal cert store. Call Close()
// when finished.
func openMyCertStore() (*winStore, error) {
	storeName := unsafe.Pointer(C.CString("MY"))
	defer C.free(storeName)

	store := C.CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, C.CERT_SYSTEM_STORE_CURRENT_USER, storeName)
	if store == nil {
		return nil, lastError("failed to open system cert store")
	}

	return &winStore{store: store}, nil
}

func (s *winStore) importPFX(data []byte, password string) ([]Identity, error) {
	cdata := C.CBytes(data)
	defer C.free(cdata)

	cpw := stringToUTF16(password)
	defer C.free(unsafe.Pointer(cpw))

	pfx := &C.CRYPT_DATA_BLOB{
		cbData: C.DWORD(len(data)),
		pbData: (*C.BYTE)(cdata),
	}

	flags := C.CRYPT_USER_KEYSET

	// import into preferred KSP
	if winAPIFlag&C.CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG > 0 {
		flags |= C.PKCS12_PREFER_CNG_KSP
	} else if winAPIFlag&C.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG > 0 {
		flags |= C.PKCS12_ALWAYS_CNG_KSP
	}

	store := C.PFXImportCertStore(pfx, cpw, C.DWORD(flags))
	if store == nil {
		return nil, lastError("failed to import PFX cert store")
	}

	wstore := &winStore{store: store}
	defer wstore.Close()

	idents := []Identity{}

	for ctx := wstore.nextCert(); ctx != nil; ctx = wstore.nextCert() {
		// Copy the cert context from the PFX store to the system store.
		var newCtx C.PCCERT_CONTEXT
		if ok := C.CertAddEncodedCertificateToStore(s.store, ctx.dwCertEncodingType, ctx.pbCertEncoded, ctx.cbCertEncoded, C.CERT_STORE_ADD_REPLACE_EXISTING, &newCtx); ok == winFalse {
			for _, ident := range idents {
				ident.Close()
			}
			return nil, lastError("failed to add imported certificate to MY store")
		}

		idents = append(idents, newWinIdentity(newCtx))
	}

	if err := wstore.getError(); err != nil {
		for _, ident := range idents {
			ident.Close()
		}
		return nil, err
	}

	return idents, nil
}

// nextCert starts or continues an iteration through this store's certificates.
// Nil is returned once all certs have been retrieved or an error is
// encountered. Check getError() to see why iteration stopped. Iteration can be
// started over by calling reset().
func (s *winStore) nextCert() C.PCCERT_CONTEXT {
	if err := s._check(); err != nil {
		s.err = err
	}

	if s.err != nil {
		return nil
	}

	s.prev = C.CertFindCertificateInStore(
		s.store,
		C.X509_ASN_ENCODING|C.PKCS_7_ASN_ENCODING,
		0,
		C.CERT_FIND_ANY,
		nil,
		s.prev,
	)

	if s.prev == nil {
		s.err = lastError("CertFindCertificateInStore failed")

		return nil
	}

	return s.prev
}

// getError returns any error encountered while iterating through store's certs
// with nextCert().
func (s *winStore) getError() error {
	if err := s._check(); err != nil {
		return err
	}

	// cryptENotFound is encountered at the end of iteration or if the store
	// doesn't have any certs.
	if errors.Cause(s.err) == cryptENotFound {
		return nil
	}

	return s.err
}

// reset clears nextCert() iteration state.
func (s *winStore) reset() error {
	if err := s._check(); err != nil {
		return err
	}

	if s.prev != nil {
		C.CertFreeCertificateContext(s.prev)
	}

	s.prev = nil
	s.err = nil

	return nil
}

// Close closes this store.
func (s *winStore) Close() {
	if err := s._check(); err != nil {
		return
	}

	if s.prev != nil {
		C.CertFreeCertificateContext(s.prev)
	}

	C.CertCloseStore(s.store, 0)

	s.closed = true
}

func (s *winStore) _check() error {
	if s == nil {
		return errors.New("nil winStore pointer")
	}

	if s.store == nil {
		return errors.New("nil winStore pointer")
	}

	if s.closed {
		return errors.New("store closed")
	}

	return nil
}

type errCode C.DWORD

const (
	// cryptENotFound — Cannot find object or property.
	cryptENotFound errCode = C.CRYPT_E_NOT_FOUND & (1<<32 - 1)
)

// lastError gets the last error from the current thread.
func lastError(msg string) error {
	return errors.Wrap(errCode(C.GetLastError()), msg)
}

func (c errCode) Error() string {
	cmsg := C.errMsg(C.DWORD(c))
	if cmsg == nil {
		return fmt.Sprintf("Error %X", int(c))
	}
	defer C.LocalFree(C.HLOCAL(cmsg))

	gomsg := C.GoString(cmsg)

	return fmt.Sprintf("Error: %X %s", int(c), gomsg)
}

type securityStatus C.SECURITY_STATUS

func checkStatus(s C.SECURITY_STATUS) error {
	if s == C.ERROR_SUCCESS {
		return nil
	}

	return securityStatus(s)
}

func (s securityStatus) Error() string {
	return fmt.Sprintf("SECURITY_STATUS %d", int(s))
}

func stringToUTF16(s string) C.LPCWSTR {
	wstr := utf16.Encode([]rune(s))

	p := C.calloc(C.size_t(len(wstr)+1), C.size_t(unsafe.Sizeof(uint16(0))))
	pp := (*[1 << 30]uint16)(p)
	copy(pp[:], wstr)

	return (C.LPCWSTR)(p)
}