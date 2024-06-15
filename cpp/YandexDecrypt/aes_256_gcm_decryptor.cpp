#include <windows.h>

#include "aes_256_gcm_decryptor.h"

Aes256GcmDecryptor::Aes256GcmDecryptor()
{
}

Aes256GcmDecryptor::~Aes256GcmDecryptor()
{
  BCryptCloseAlgorithmProvider(_alg_handle, 0);
  BCryptDestroyKey(_key_handle);
}

void Aes256GcmDecryptor::init(const uint8_t *key, size_t key_size)
{
  if (BCryptOpenAlgorithmProvider(&_alg_handle, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) {
    throw std::exception("Cannot initialize cryptoprovider");
  }

  if (BCryptSetProperty(_alg_handle, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0) {
    throw std::exception("Cannot set chaining mode");
  }

  if (BCryptGenerateSymmetricKey(_alg_handle, &_key_handle, NULL, 0, (PUCHAR)key, key_size, 0) != 0) {
    throw std::exception("Cannot initialize symmetric key");
  }
}

void Aes256GcmDecryptor::decrypt(uint8_t *out, size_t *out_len, size_t max_out_len, const uint8_t *nonce,
                                 size_t nonce_len, const uint8_t *in, size_t in_len, const uint8_t *ad, size_t ad_len)
{
  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO bacmi;

  BCRYPT_INIT_AUTH_MODE_INFO(bacmi);

  bacmi.pbNonce = (PUCHAR)nonce;
  bacmi.cbNonce = nonce_len;

  bacmi.pbTag = (PUCHAR)(in + in_len) - 16;
  bacmi.cbTag = 16;

  if (ad) {
    bacmi.pbAuthData = (PUCHAR)ad;
    bacmi.cbAuthData = ad_len;
  }

  *out_len = 0;

  NTSTATUS status = 0;
  if (!BCRYPT_SUCCESS(status = BCryptDecrypt(_key_handle, (PUCHAR)in, in_len - 16, &bacmi, NULL, 0,
                     (PUCHAR)out, max_out_len, (ULONG *)out_len, 0))) {
    throw std::exception("Cannot decrypt ciphertext");
  }
}