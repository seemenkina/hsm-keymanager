package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/ThalesIgnite/crypto11"
	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/hcl"
	"github.com/miekg/pkcs11"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/keymanager"
)

type configuration struct {
	HSMPath    string `hcl:"hsm_path"`
	TokenLabel string `hcl:"token_label"`
	UserPin    string `hcl:"user_pin"`
}

type KeyManager struct {
	config  *configuration
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
	slotID  uint
}

func New() *KeyManager {
	return &KeyManager{}
}

func (m *KeyManager) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {

	resp := &spi.ConfigureResponse{}
	config := &configuration{}
	hclTree, err := hcl.Parse(req.Configuration)
	if err != nil {
		err := fmt.Errorf("Error parsing custom keymanager configuration: %s", err)
		return resp, err
	}

	err = hcl.DecodeObject(&config, hclTree)
	if err != nil {
		err := fmt.Errorf("Error decoding custom keymanager configuration: %v", err)
		return resp, err
	}
	if err := m.configure(config); err != nil {
		return nil, err
	}

	return &spi.ConfigureResponse{}, nil
}

func (m *KeyManager) configure(config *configuration) error {
	cfg := crypto11.PKCS11Config{
		Path:       config.HSMPath,
		TokenLabel: config.TokenLabel,
		Pin:        config.UserPin,
	}

	ctx, err := crypto11.Configure(&cfg)
	if err != nil {
		return err
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return err
	}

	if len(slots) == 1 {
		return errors.New("slots aren't presented on module")
	}

	session, err := ctx.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return err
	}

	m.ctx = ctx
	m.config = config
	m.session = session
	m.slotID = slots[0]

	return nil
}

func (m *KeyManager) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (m *KeyManager) GenerateKey(ctx context.Context, req *keymanager.GenerateKeyRequest) (*keymanager.GenerateKeyResponse, error) {
	if req.KeyId == "" {
		return nil, errors.New("key id is required")
	}
	if req.KeyType == keymanager.KeyType_UNSPECIFIED_KEY_TYPE {
		return nil, errors.New("key type is required")
	}

	if m.IsKeyOnHsm(req.KeyId) {
		err := m.deleteKey(req.KeyId, req.KeyType)
		if err != nil {
			return nil, err
		}
	}

	pubKey, err := m.generateKey(req.KeyId, req.KeyType)
	if err != nil {
		return nil, err
	}
	return &keymanager.GenerateKeyResponse{
		PublicKey: pubKey,
	}, nil
}

func (m *KeyManager) GetPublicKey(ctx context.Context, req *keymanager.GetPublicKeyRequest) (*keymanager.GetPublicKeyResponse, error) {
	if req.KeyId == "" {
		return nil, errors.New("key id is required")
	}

	pubKey, err := m.findKeyOnHSM(req.KeyId)
	if err != nil {
		return nil, err
	}

	return &keymanager.GetPublicKeyResponse{
		PublicKey: pubKey,
	}, nil
}

func (m *KeyManager) GetPublicKeys(ctx context.Context, req *keymanager.GetPublicKeysRequest) (*keymanager.GetPublicKeysResponse, error) {
	pubKeys, err := m.getPublicKeys()
	if err != nil {
		return nil, err
	}
	return &keymanager.GetPublicKeysResponse{
		PublicKeys: pubKeys,
	}, nil
}

func (m *KeyManager) SignData(ctx context.Context, req *keymanager.SignDataRequest) (*keymanager.SignDataResponse, error) {
	if req.KeyId == "" {
		return nil, errors.New("key id is required")
	}
	if req.SignerOpts == nil {
		return nil, errors.New("signer opts is required")
	}

	var signerOpts crypto.SignerOpts
	switch opts := req.SignerOpts.(type) {
	case *keymanager.SignDataRequest_HashAlgorithm:
		if opts.HashAlgorithm == keymanager.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM {
			return nil, errors.New("hash algorithm is required")
		}
		signerOpts = crypto.Hash(opts.HashAlgorithm)
	case *keymanager.SignDataRequest_PssOptions:
		if opts.PssOptions == nil {
			return nil, errors.New("PSS options are nil")
		}
		if opts.PssOptions.HashAlgorithm == keymanager.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM {
			return nil, errors.New("hash algorithm is required")
		}
		signerOpts = &rsa.PSSOptions{
			SaltLength: int(opts.PssOptions.SaltLength),
			Hash:       crypto.Hash(opts.PssOptions.HashAlgorithm),
		}
	default:
		return nil, errors.New("unsupported signer opts type")
	}

	return m.signByHsmKey(req, signerOpts)
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		Plugins: map[string]plugin.Plugin{
			"hsmkeymanager": &keymanager.GRPCPlugin{ServerImpl: New()},
		},
		HandshakeConfig: keymanager.Handshake,
		GRPCServer:      plugin.DefaultGRPCServer,
	})
}
