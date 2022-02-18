package gpg

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/openpgp"
)

// GPG ...
type GPG struct {
	PrivateKeyPath string
	PublicKeyPath  string
	Passphrase     []byte
}

// Encrypt ...
func (gpg *GPG) Encrypt(reader io.Reader) (*bytes.Buffer, error) {
	publicKeyFile, err := os.Open(gpg.PublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error opening public key: %s", err)
	}
	defer publicKeyFile.Close()

	publicKey, err := openpgp.ReadArmoredKeyRing(publicKeyFile)
	if err != nil {
		return nil, err
	}

	privateKeyFile, err := os.Open(gpg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error opening private key: %s", err)
	}
	defer privateKeyFile.Close()

	privateKey, err := openpgp.ReadArmoredKeyRing(privateKeyFile)
	if err != nil {
		return nil, err
	}

	entity := append(publicKey, privateKey...)

	buf := new(bytes.Buffer)
	encrypter, err := openpgp.Encrypt(buf, entity, nil, nil, nil)
	if err != nil {
		return nil, err
	}

	_, err = io.Copy(encrypter, reader)
	if err != nil {
		return nil, err
	}

	err = encrypter.Close()
	if err != nil {
		return nil, err
	}

	w := new(bytes.Buffer)
	_, err = io.Copy(w, buf)
	if err != nil {
		return nil, err
	}

	return w, nil
}

// Decrypt ...
func (gpg *GPG) Decrypt(reader io.Reader) (*bytes.Buffer, error) {
	privateKeyFile, err := os.Open(gpg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error opening private key: %s", err)
	}
	defer privateKeyFile.Close()

	privateKey, err := openpgp.ReadArmoredKeyRing(privateKeyFile)
	if err != nil {
		return nil, err
	}

	entity := privateKey[0]

	if entity.PrivateKey != nil && entity.PrivateKey.Encrypted {
		if len(gpg.Passphrase) == 0 {
			return nil, errors.New("private key is encrypted but you did not provide a passphrase")
		}
		err := entity.PrivateKey.Decrypt(gpg.Passphrase)
		if err != nil {
			return nil, errors.New("failed to decrypt private key. Did you use the wrong passphrase? (" + err.Error() + ")")
		}
	}
	for _, subkey := range entity.Subkeys {
		if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
			err := subkey.PrivateKey.Decrypt(gpg.Passphrase)
			if err != nil {
				return nil, errors.New("failed to decrypt subkey. Did you use the wrong passphrase? (" + err.Error() + ")")
			}
		}
	}

	var entityList openpgp.EntityList
	entityList = append(entityList, entity)

	message, err := openpgp.ReadMessage(reader, entityList, nil, nil)
	if err != nil {
		return nil, err
	}

	writer := new(bytes.Buffer)
	_, err = io.Copy(writer, message.LiteralData.Body)

	return writer, err
}
