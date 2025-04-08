// Author github.com/Goodies365/YandexDecrypt
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/objx"
	"golang.org/x/crypto/pbkdf2"
)

var (
	yandexSignature           = []byte{0x08, 0x01, 0x12, 0x20}
	errInvalidYandexSignature = errors.New("main: inavalidYandexSignature")
)

type yandexDecrypt struct {
	path     string
	key      []byte
	profiles []string
}

type sealedKey struct {
	encryptedEncryptionKey           []byte
	encryptedPrivateKey              []byte
	unlockKeySalt                    []byte
	encryptionKeyAlgorithm           int
	encryptionKeyEncryptionAlgorithm int
	keyId                            string
	privateKeyEncryptionAlgorithm    int
	unlockKeyDerivationAlgorithm     int
	unlockKeyIterations              int
}

type invalidMasterPasswordTypeError struct {
	message string
}

func (e *invalidMasterPasswordTypeError) Error() string {
	return fmt.Sprintf("main: %s", e.message)
}

func getSealedKey(db *sql.DB) (*sealedKey, error) {
	var sealedKeyJson string
	err := db.QueryRow("SELECT sealed_key FROM active_keys").Scan(&sealedKeyJson)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	sealedKeyObjx, err := objx.FromJSON(sealedKeyJson)
	if err != nil {
		return nil, err
	}

	encryptedEncryptionKey, err := base64.StdEncoding.DecodeString(sealedKeyObjx.Get("encrypted_encryption_key").Str())
	if err != nil {
		return nil, err
	}
	encryptedPrivateKey, err := base64.StdEncoding.DecodeString(sealedKeyObjx.Get("encrypted_private_key").Str())
	if err != nil {
		return nil, err
	}
	unlockKeySalt, err := base64.StdEncoding.DecodeString(sealedKeyObjx.Get("unlock_key_salt").Str())
	if err != nil {
		return nil, err
	}

	return &sealedKey{
		encryptedEncryptionKey,
		encryptedPrivateKey,
		unlockKeySalt,
		sealedKeyObjx.Get("encryption_key_algorithm").Int(),
		sealedKeyObjx.Get("encryption_key_encryption_algorithm").Int(),
		sealedKeyObjx.Get("key_id").Str(),
		sealedKeyObjx.Get("private_key_encryption_algorithm").Int(),
		sealedKeyObjx.Get("unlock_key_derivation_algorithm").Int(),
		sealedKeyObjx.Get("unlock_key_iterations").Int(),
	}, nil
}

func getLocalEncryptorDataKey(db *sql.DB, key []byte) ([]byte, error) {
	var blob []byte
	err := db.QueryRow("SELECT value FROM meta WHERE key = 'local_encryptor_data'").Scan(&blob)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	ind := bytes.Index(blob, []byte("v10"))

	if ind == -1 {
		return nil, errors.New("main: couldn't find encrypted key from local_encryptor_data")
	}

	encryptedKey, _ := bytes.CutPrefix(blob[ind:], []byte("v10"))

	if len(encryptedKey) < 96 {
		return nil, errors.New("main: invalid encrypted key from local_encryptor_data")
	}

	encryptedKey = encryptedKey[:96]

	decryptedKey, err := decryptAesGcm256(encryptedKey[12:], key, encryptedKey[:12], nil)
	if err != nil {
		return nil, err
	}

	var found bool
	decryptedKey, found = bytes.CutPrefix(decryptedKey, yandexSignature)
	if !found {
		return nil, errInvalidYandexSignature
	}
	if len(decryptedKey) < 32 {
		return nil, errors.New("main: invalid decrypted key from local_encryptor_data")
	}

	return decryptedKey[:32], nil
}

func decryptKeyRsaOaep(passwrod, salt []byte, iterations int, encryptedPrivateKey, encryptedEncryptionKey []byte) ([]byte, error) {
	derivedKey := pbkdf2.Key(passwrod, salt, iterations, 32, sha256.New)

	decryptedPrivateKey, err := decryptAesGcm256(encryptedPrivateKey[12:], derivedKey, encryptedPrivateKey[:12], salt)

	if err != nil {
		return nil, &invalidMasterPasswordTypeError{message: "incorrect master password"}
	}

	if len(decryptedPrivateKey) < 5 {
		return nil, errors.New("main: invalid rsa oaep key")
	}
	decryptedPrivateKey = decryptedPrivateKey[5:]

	privateKey, err := x509.ParsePKCS8PrivateKey(decryptedPrivateKey)
	if err != nil {
		return nil, err
	}

	rsaPrivateKey := privateKey.(*rsa.PrivateKey)

	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPrivateKey, encryptedEncryptionKey, nil)
	if err != nil {
		return nil, err
	}

	decryptKey, found := bytes.CutPrefix(decrypted, yandexSignature)
	if !found {
		return nil, errInvalidYandexSignature
	}

	return decryptKey, nil
}

func (y *yandexDecrypt) printCreditCards(profilePath string, key []byte, masterPassword bool, keyId []byte) error {
	creditCardsPath := filepath.Join(profilePath, "Ya Credit Cards")

	db, err := sql.Open("sqlite3", creditCardsPath)
	if err != nil {
		return err
	}
	defer db.Close()

	fmt.Printf("Found credit cards database: %s\n", creditCardsPath)

	if key == nil {
		key, err = getLocalEncryptorDataKey(db, y.key)
		if err != nil {
			return err
		}
	}

	rows, err := db.Query("SELECT guid, public_data, private_data FROM records")
	if err != nil {
		return err
	}
	for rows.Next() {
		var guid string
		var publicData string
		var privateData []byte

		err = rows.Scan(&guid, &publicData, &privateData)
		if err != nil {
			continue
		}

		aadResult := []byte(guid)
		if masterPassword {
			aadResult = append(aadResult, keyId...)
		}

		if len(privateData) < 12 {
			continue
		}

		decrypted, err := decryptAesGcm256(privateData[12:], key, privateData[:12], aadResult)
		if err != nil {
			continue
		}

		decryptedObjx, err := objx.FromJSON(string(decrypted))
		if err != nil {
			continue
		}

		publicDataObjx, err := objx.FromJSON(publicData)
		if err != nil {
			continue
		}

		fmt.Println("======================================CREDIT CARD====================================")
		fmt.Println("Card number:", decryptedObjx.Get("full_card_number").Str())
		fmt.Println("CVC:", decryptedObjx.Get("pin_code").Str())
		fmt.Println("Comment:", decryptedObjx.Get("secret_comment").Str())
		fmt.Println("Card holder:", publicDataObjx.Get("card_holder").Str())
		fmt.Println("Card title:", publicDataObjx.Get("card_title").Str())
		fmt.Println("Expiration date:", publicDataObjx.Get("expire_date_year").Str()+"/"+publicDataObjx.Get("expire_date_month").Str())
	}
	fmt.Println("====================================================================================\n\n")
	rows.Close()

	return nil
}

func (y *yandexDecrypt) PrintCredentials() error {
	for _, profileName := range y.profiles {
		profilePath := filepath.Join(y.path, profileName)

		loginsPath := filepath.Join(profilePath, "Ya Passman Data")

		db, err := sql.Open("sqlite3", loginsPath)
		if err != nil {
			continue
		}

		fmt.Printf("Found logins database: %s\n", loginsPath)

		sealedKey, err := getSealedKey(db)
		if err != nil {
			continue
		}

		var decryptKey []byte
		masterPassword := false
		if sealedKey != nil {
			masterPassword = true
			if len(sealedKey.encryptedPrivateKey) < 12 {
				continue
			}

			for {
				var password string
				fmt.Print("Enter master password: ")
				fmt.Scan(&password)

				decryptKey, err = decryptKeyRsaOaep([]byte(password), sealedKey.unlockKeySalt, sealedKey.unlockKeyIterations, sealedKey.encryptedPrivateKey, sealedKey.encryptedEncryptionKey)
				imperr := &invalidMasterPasswordTypeError{}
				if errors.As(err, &imperr) {
					fmt.Println("Incorrect master password")
					continue
				}
				if err != nil {
					fmt.Println(err)
					break
				}

				fmt.Println("Correct master password")
				break
			}
		} else {
			decryptKey, err = getLocalEncryptorDataKey(db, y.key)
			if err != nil {
				continue
			}
		}

		if len(decryptKey) == 0 {
			fmt.Println("Failed to decrypt key to decrypt encrypted data")
			continue
		}

		rows, err := db.Query("SELECT origin_url, username_element, username_value, password_element, password_value, signon_realm FROM logins")
		if err != nil {
			continue
		}

		for rows.Next() {
			var originUrl string
			var usernameElement string
			var usernameValue string
			var passwordElement string
			var passwordValue []byte
			var signonRealm string

			err = rows.Scan(&originUrl, &usernameElement, &usernameValue, &passwordElement, &passwordValue, &signonRealm)
			if err != nil {
				continue
			}

			var strToHash = originUrl + "\x00" + usernameElement + "\x00" + usernameValue + "\x00" + passwordElement + "\x00" + signonRealm

			hash := sha1.New()
			hash.Write([]byte(strToHash))

			if err != nil {
				continue
			}

			hashResult := hash.Sum(nil)
			if masterPassword {
				hashResult = append(hashResult, sealedKey.keyId...)
				passwordValue, err = base64.StdEncoding.DecodeString(string(passwordValue))
				if err != nil {
					continue
				}
			}

			if len(passwordValue) < 12 {
				continue
			}

			decrypted, err := decryptAesGcm256(passwordValue[12:], decryptKey, passwordValue[:12], hashResult)
			if err != nil {
				continue
			}

			fmt.Println("======================================PASSWORD======================================")
			fmt.Println("Url:", originUrl)
			fmt.Println("Login:", usernameValue)
			fmt.Println("Password:", string(decrypted))
		}
		fmt.Println("====================================================================================\n\n")

		rows.Close()

		if sealedKey != nil {
			y.printCreditCards(profilePath, decryptKey, masterPassword, []byte(sealedKey.keyId))
		} else {
			y.printCreditCards(profilePath, nil, false, nil)
		}

		db.Close()
	}

	return nil
}

func newYandexDecrypt(path string) (*yandexDecrypt, error) {
	localStateJson, err := os.ReadFile(filepath.Join(path, "Local State"))
	if err != nil {
		return nil, err
	}
	localStateObjx, err := objx.FromJSON(string(localStateJson))
	if err != nil {
		return nil, err
	}
	var profiles []string
	for _, profileNameAny := range localStateObjx.Get("profile.profiles_order").InterSlice() {
		if profileName, ok := profileNameAny.(string); ok {
			profiles = append(profiles, profileName)
		}
	}

	if len(profiles) == 0 {
		return nil, errors.New("main: there is no profiles")
	}

	key, err := base64.StdEncoding.DecodeString(localStateObjx.Get("os_crypt.encrypted_key").Str())
	if err != nil {
		return nil, err
	}

	var ok bool

	key, ok = bytes.CutPrefix(key, []byte("DPAPI"))
	if !ok {
		return nil, errors.New("main: dpapi prefix does not exist")
	}

	decryptedKey, err := decryptDpapi(key)
	if err != nil {
		return nil, err
	}

	return &yandexDecrypt{
		path,
		decryptedKey,
		profiles,
	}, nil
}
