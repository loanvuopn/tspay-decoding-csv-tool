package gpg

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptAndDecrypt(t *testing.T) {
	t.Run("encrypt and decrypt with different private keys", func(t *testing.T) {
		message := bytes.NewBuffer([]byte("Hello"))

		aliceGPGPrivKeyPath, err := filepath.Abs("../test/fixtures/keys/gpg_alice/private_key.asc")
		require.NoError(t, err)

		bobGPGPubKeyPath, err := filepath.Abs("../test/fixtures/keys/gpg_bob/public_key.asc")
		require.NoError(t, err)

		gpg1 := &GPG{
			PrivateKeyPath: aliceGPGPrivKeyPath,
			PublicKeyPath:  bobGPGPubKeyPath,
		}

		encodedMessage, err := gpg1.Encrypt(message)
		assert.NoError(t, err)

		bobGPGPrivKeyPath, err := filepath.Abs("../test/fixtures/keys/gpg_bob/private_key.asc")
		require.NoError(t, err)

		gpg2 := &GPG{
			PrivateKeyPath: bobGPGPrivKeyPath,
			Passphrase:     []byte("passphrase"),
		}

		decodedMessage, err := gpg2.Decrypt(encodedMessage)
		require.NoError(t, err)

		assert.Equal(t, "Hello", decodedMessage.String())
	})
}
