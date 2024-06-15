#pragma once

#include <string>
#include "sqlite/sqlite3.h"
#include "json.hpp"

struct decrypted_password_t
{
  std::string url;
  std::string username;
  std::string password;
};

struct decrypted_cc_t
{
  std::string card_number;
  std::string pin_code;
  std::string secret_comment;
  std::string card_holder;
  std::string card_title;
  std::string expire_date_year;
  std::string expire_date_month;
};

class YaDecryptor
{
public:
  YaDecryptor(const char *user_data_path, const char *profile_name = "Default");
  ~YaDecryptor();

  void init();

  std::vector<decrypted_password_t> get_passwords();
  std::vector<decrypted_cc_t> get_credit_cards();

private:
  std::string decrypt_ls_key(std::string &key_base64);
  std::string get_le_key(sqlite3 *db_ctx);

  std::string _user_data_path;
  std::string _profile_name;

  std::string _local_state_path;

  std::string _profile_path;
  std::string _passwords_path;
  std::string _cards_path;
  std::string _cookies_path;

  std::string _ls_key;
  std::string _le_key;
};