package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"github.com/ThalesIgnite/crypto11"
	"github.com/miekg/pkcs11"
	"github.com/spiffe/spire/proto/server/keymanager"
	"math/big"
	"reflect"
)

func (m *KeyManager) deleteKey(keyId string, keyType keymanager.KeyType) error {
	var keyPair []pkcs11.ObjectHandle
	var err error

	switch keyType {
	case keymanager.KeyType_RSA_1024 | keymanager.KeyType_RSA_2048 | keymanager.KeyType_RSA_4096:
		keyPair, err = m.findObjHandle([]byte(keyId), pkcs11.CKK_RSA)
		if err != nil {
			return err
		}
	case keymanager.KeyType_EC_P256 | keymanager.KeyType_EC_P384:
		keyPair, err = m.findObjHandle([]byte(keyId), pkcs11.CKK_RSA)
		if err != nil {
			return err
		}
	}

	if len(keyPair) != 0 {
		err = m.ctx.DestroyObject(m.session, keyPair[0])
		if err != nil {
			return err
		}
		err = m.ctx.DestroyObject(m.session, keyPair[1])
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *KeyManager) findObjHandle(keyId []byte, keyTypeInPKCS11 int) (obj []pkcs11.ObjectHandle, err error) {
	publKeyTemp := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyTypeInPKCS11),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyId),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyId),
	}
	privKeyTemp := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyTypeInPKCS11),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyId),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyId),
	}

	err = m.ctx.FindObjectsInit(m.session, publKeyTemp)
	if err != nil {
		return nil, err
	}
	defer func() {
		errNew := m.ctx.FindObjectsFinal(m.session)
		if err != nil {
			err = errNew
		}
	}()

	key, _, err := m.ctx.FindObjects(m.session, 1)
	if err != nil {
		return nil, err
	}

	obj = append(obj, key[0])

	err = m.ctx.FindObjectsInit(m.session, privKeyTemp)
	if err != nil {
		return nil, err
	}
	defer func() {
		errNew := m.ctx.FindObjectsFinal(m.session)
		if err != nil {
			err = errNew
		}
	}()

	key, _, err = m.ctx.FindObjects(m.session, 1)
	if err != nil {
		return nil, err
	}

	obj = append(obj, key[0])

	return obj, nil
}

func (m *KeyManager) IsKeyOnHsm(keyId string) bool {
	_, err := crypto11.FindKeyPairOnSlot(0, []byte(keyId), []byte(keyId))

	if err != nil {
		return false
	}
	return true
}

func (m *KeyManager) generateRSAKey(slot uint, keyId []byte, bits int) (*crypto11.PKCS11PrivateKey, error) {
	rsaKeyPair, err := crypto11.GenerateRSAKeyPairOnSlot(m.slotID, keyId, keyId, bits)
	if err != nil {
		return nil, err
	}
	return &rsaKeyPair.PKCS11PrivateKey, nil
}

func (m *KeyManager) generateECKey(slot uint, keyId []byte, curve elliptic.Curve) (*crypto11.PKCS11PrivateKey, error) {
	ecdsaKeyPair, err := crypto11.GenerateECDSAKeyPairOnSlot(m.slotID, keyId, keyId, curve)
	if err != nil {
		return nil, err
	}
	return &ecdsaKeyPair.PKCS11PrivateKey, nil
}

func (m *KeyManager) generateKey(keyId string, keyType keymanager.KeyType) (k *keymanager.PublicKey, err error) {
	var pkcs11PrivateKey *crypto11.PKCS11PrivateKey

	switch keyType {
	case keymanager.KeyType_EC_P256:
		pkcs11PrivateKey, err = m.generateECKey(m.slotID, []byte(keyId), elliptic.P256())
	case keymanager.KeyType_EC_P384:
		pkcs11PrivateKey, err = m.generateECKey(m.slotID, []byte(keyId), elliptic.P384())
	case keymanager.KeyType_RSA_1024:
		pkcs11PrivateKey, err = m.generateRSAKey(m.slotID, []byte(keyId), 1024)
	case keymanager.KeyType_RSA_2048:
		pkcs11PrivateKey, err = m.generateRSAKey(m.slotID, []byte(keyId), 2048)
	case keymanager.KeyType_RSA_4096:
		pkcs11PrivateKey, err = m.generateRSAKey(m.slotID, []byte(keyId), 4096)
	default:
		return nil, crypto11.ErrUnsupportedKeyType
	}

	if err != nil {
		return nil, err
	}

	pubKey, err := makePublicKey(keyId, keyType, pkcs11PrivateKey)
	if err != nil {
		return nil, errors.New("unable to make keymanager.PublicKey")
	}

	return pubKey, nil
}

func (m *KeyManager) signByHsmKey(req *keymanager.SignDataRequest, signerOpts crypto.SignerOpts) (*keymanager.SignDataResponse, error) {
	privateKey := m.getPrivateKey(req.KeyId)
	if privateKey == nil {
		return nil, crypto11.ErrKeyNotFound
	}
	_, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("keypair is not usable for signing")
	}

	var signature []byte
	var err error

	switch reflect.TypeOf(privateKey) {
	case reflect.TypeOf(&crypto11.PKCS11PrivateKeyRSA{}):
		signature, err = privateKey.(*crypto11.PKCS11PrivateKeyRSA).Sign(rand.Reader, req.Data, signerOpts)
	case reflect.TypeOf(&crypto11.PKCS11PrivateKeyECDSA{}):
		signature, err = privateKey.(*crypto11.PKCS11PrivateKeyECDSA).Sign(rand.Reader, req.Data, signerOpts)
	default:
		return nil, crypto11.ErrUnsupportedKeyType
	}

	if err != nil {
		return nil, errors.New("keypair signing operation failed")
	}

	return &keymanager.SignDataResponse{
		Signature: signature,
	}, nil
}

func (m *KeyManager) getPrivateKey(id string) crypto.PrivateKey {
	privateKey, err := crypto11.FindKeyPairOnSlot(m.slotID, []byte(id), []byte(id))
	if err != nil {
		return nil
	}
	return privateKey
}

func (m *KeyManager) findKeyOnHSM(keyId string) (*keymanager.PublicKey, error) {
	key, err := crypto11.FindKeyPairOnSlot(m.slotID, []byte(keyId), []byte(keyId))

	switch reflect.TypeOf(key) {
	case reflect.TypeOf(&crypto11.PKCS11PrivateKeyRSA{}):
		rsaKeyPair, err := m.findObjHandle([]byte(keyId), pkcs11.CKK_RSA)
		if err != nil {
			return nil, err
		}
		if len(rsaKeyPair) != 0 {
			return m.makeRSAPubKey(rsaKeyPair[0])
		}
	case reflect.TypeOf(&crypto11.PKCS11PrivateKeyECDSA{}):
		ecdsaKeyPair, err := m.findObjHandle([]byte(keyId), pkcs11.CKK_ECDSA)
		if err != nil {
			return nil, err
		}
		if len(ecdsaKeyPair) != 0 {
			return m.makeECDSAPubKey(ecdsaKeyPair[0])
		}
	default:
		return nil, err
	}

	return nil, err
}

func (m *KeyManager) makeRSAPubKey(pubHandle pkcs11.ObjectHandle) (*keymanager.PublicKey, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
	}
	attributes, err := m.ctx.GetAttributeValue(m.session, pubHandle, template)
	if err != nil {
		return nil, err
	}

	var modulus = new(big.Int)
	modulus.SetBytes(attributes[0].Value)

	var bigExponent = new(big.Int)
	bigExponent.SetBytes(attributes[1].Value)

	if bigExponent.BitLen() > 32 {
		return nil, crypto11.ErrMalformedRSAKey
	}
	if bigExponent.Sign() < 1 {
		return nil, crypto11.ErrMalformedRSAKey
	}
	exponent := int(bigExponent.Uint64())
	if exponent < 2 {
		return nil, crypto11.ErrMalformedRSAKey
	}
	key := rsa.PublicKey{
		N: modulus,
		E: exponent,
	}

	pkixData, err := x509.MarshalPKIXPublicKey(&key)
	keyId := string(attributes[2].Value)

	var keyType keymanager.KeyType
	switch modulus.BitLen() {
	case 1024:
		keyType = keymanager.KeyType_RSA_1024
	case 2048:
		keyType = keymanager.KeyType_RSA_2048
	case 4096:
		keyType = keymanager.KeyType_RSA_4096
	default:
		return nil, crypto11.ErrUnsupportedKeyType
	}

	return &keymanager.PublicKey{
		Id:       keyId,
		Type:     keyType,
		PkixData: pkixData,
	}, nil
}

func (m *KeyManager) makeECDSAPubKey(pubHandle pkcs11.ObjectHandle) (*keymanager.PublicKey, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ECDSA_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
	}
	attributes, err := m.ctx.GetAttributeValue(m.session, pubHandle, template)
	if err != nil {
		return nil, err
	}

	var pub ecdsa.PublicKey
	var keyType keymanager.KeyType

	b256, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	b384, err := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 34})

	if bytes.Compare(b256, attributes[0].Value) == 0 {
		pub.Curve = elliptic.P256()
		keyType = keymanager.KeyType_EC_P256
	} else {
		if bytes.Compare(b384, attributes[0].Value) == 0 {
			pub.Curve = elliptic.P384()
			keyType = keymanager.KeyType_EC_P384
		} else {
			return nil, crypto11.ErrUnsupportedEllipticCurve
		}
	}

	if pub.X, pub.Y, err = unmarshalEcPoint(attributes[1].Value, pub.Curve); err != nil {
		return nil, err
	}

	pkixData, err := x509.MarshalPKIXPublicKey(&pub)
	if err != nil {
		return nil, err
	}

	keyId := string(attributes[2].Value)

	return &keymanager.PublicKey{
		Id:       keyId,
		Type:     keyType,
		PkixData: pkixData,
	}, nil
}

func (m *KeyManager) findAllRSAPubKeys() ([]*keymanager.PublicKey, error) {

	var rsaPubKeys []*keymanager.PublicKey
	rsaKeyTemp := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
	}
	err := m.ctx.FindObjectsInit(m.session, rsaKeyTemp)

	if err != nil {
		return nil, err
	}

	for {
		obj, _, err := m.ctx.FindObjects(m.session, 1)
		if err != nil {
			return nil, err
		}

		if len(obj) == 0 {
			err = m.ctx.FindObjectsFinal(m.session)
			if err != nil {
				return nil, err
			}
			return rsaPubKeys, nil
		}
		entry, err := m.makeRSAPubKey(obj[0])
		if err != nil {
			return nil, err
		}
		rsaPubKeys = append(rsaPubKeys, entry)

	}
}

func (m *KeyManager) findAllECDSAPubKeys() ([]*keymanager.PublicKey, error) {
	var ecdsaPubKeys []*keymanager.PublicKey
	ECDSAKeyTemp := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ECDSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
	}
	err := m.ctx.FindObjectsInit(m.session, ECDSAKeyTemp)
	if err != nil {
		return nil, err
	}

	for {
		obj, _, err := m.ctx.FindObjects(m.session, 1)
		if err != nil {
			return nil, err
		}

		if len(obj) == 0 {

			err = m.ctx.FindObjectsFinal(m.session)
			if err != nil {
				return nil, err
			}
			return ecdsaPubKeys, nil
		}

		pubKey, err := m.makeECDSAPubKey(obj[0])
		if err != nil {
			return nil, err
		}
		ecdsaPubKeys = append(ecdsaPubKeys, pubKey)
	}
}

func (m *KeyManager) getPublicKeys() ([]*keymanager.PublicKey, error) {
	var pubKeys []*keymanager.PublicKey
	rsaKeys, err := m.findAllRSAPubKeys()
	if err != nil {
		return nil, err
	}
	pubKeys = append(pubKeys, rsaKeys...)

	ecdsaKeys, err := m.findAllECDSAPubKeys()
	if err != nil {
		return nil, err
	}
	pubKeys = append(pubKeys, ecdsaKeys...)

	return pubKeys, nil
}

func makePublicKey(keyId string, keyType keymanager.KeyType, key *crypto11.PKCS11PrivateKey) (*keymanager.PublicKey, error) {
	pkixData, err := x509.MarshalPKIXPublicKey(key.PubKey)
	if err != nil {
		return nil, err
	}
	return &keymanager.PublicKey{
		Id:       keyId,
		Type:     keyType,
		PkixData: pkixData,
	}, nil
}

func unmarshalEcPoint(b []byte, c elliptic.Curve) (x *big.Int, y *big.Int, err error) {
	// Decoding an octet string in isolation seems to be too hard
	// with encoding.asn1, so we do it manually. Look away now.
	if b[0] != 4 {
		return nil, nil, crypto11.ErrMalformedDER
	}
	var l, r int
	if b[1] < 128 {
		l = int(b[1])
		r = 2
	} else {
		ll := int(b[1] & 127)
		if ll > 2 { // unreasonably long
			return nil, nil, crypto11.ErrMalformedDER
		}
		l = 0
		for i := int(0); i < ll; i++ {
			l = 256*l + int(b[2+i])
		}
		r = ll + 2
	}
	if r+l > len(b) {
		return nil, nil, crypto11.ErrMalformedDER
	}
	pointBytes := b[r:]
	x, y = elliptic.Unmarshal(c, pointBytes)
	if x == nil || y == nil {
		err = crypto11.ErrMalformedPoint
	}
	return
}
