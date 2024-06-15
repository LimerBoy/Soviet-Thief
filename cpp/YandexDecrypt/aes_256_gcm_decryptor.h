#pragma once

#include <string>

#include <Bcrypt.h>

class Aes256GcmDecryptor
{
public:
  Aes256GcmDecryptor();
  ~Aes256GcmDecryptor();

  void init(const uint8_t *key, size_t key_size);
  void decrypt(uint8_t *out, size_t *out_len, size_t max_out_len, const uint8_t *nonce,
               size_t nonce_len, const uint8_t *in, size_t in_len, const uint8_t *ad, size_t ad_len);

private:

  BCRYPT_ALG_HANDLE _alg_handle;
  BCRYPT_KEY_HANDLE _key_handle;
};