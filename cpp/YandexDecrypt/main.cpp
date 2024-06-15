#include <iostream>
#include <filesystem>

#include <Shlwapi.h>
#include <Shlobj.h>

#include "yadecryptor.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")

namespace fs = std::filesystem;

int main()
{
  /*
  * Алгоритм шифрования данных в яндекс браузере использует шифрование aes-256-gcm с использованием данными-аутентификации AAD
  * в bcrypt winapi библиотеке это необязательный параметр pbAuthData. В случае шифровании паролей данные аутентификации всегда
  * равны 20 байтам, эти данные берутся вычисляя хеш sha1 от значений origin_url, username_value, signon_realm, то есть для
  * каждой записи пароля в основном эти данные-аутентификации получаются разные. Между этими тремя значениями используется
  * разделитель двух нулевых байт 0x00, 0x00. То есть в sha1 подается буфер origin_url + 0x0000 + username_value + 0x0000 + signon_realm
  * Для кредитных карт в виде данныъ аутентификации берется guid значение, которое есть у каждой записи кредитной карты в таблице
  * records в файле Ya Credit Cards. Сам зашифрованный блоб пароля, кредитной карты начинается с 12 байт вектора инициализации
  * iv(nonce), потом идут зашифрованный данные, а в самом конце 16 байт находится tag, вообщем все как обычно.
  * Сам ключ для расшифровки паролей 32-ух байтный хранится в таблице meta в строке со значением local_encryptor_data, этот значение есть как у паролей, так и
  * у кредитных карт. Здесь в коде я назвал его le_key. Начинается этот зашифрованный блоб с v10. Размер зашифрованного блоба 96 байт.
  * Опять таки здесь 12 байт в начале это iv, потом идут зашифрованные данные (68 байт) и в конце 16 байт tag.
  * Расшифровав ключ получается 68 байт, первые четыре байта это сигнатура, а дальше лежит 32-ух байтный ключ который используется
  * чтобы расшифровать пароли или кредитные карты. Для расшифровки блоба используется все тот же aes-256-gcm, но уже без AAD.
  * Ключ для расшифровки блоба хранится в localstate, в коде я его назвал ls_key. Шифрование ключа используется такое же как в хроме.
  * ["os_crypt"]["encrypted_key"]. Хранится он там в base64, декодируем base64, удаляем dpapi префикс и дальше расшифроваваем
  * dpapi. Получается 32 байтный ключ для расшифровки блобов local_encryptor_data.
  * Кстати в local_encryptor_data после 96 байт лежит еще один блоб, который можно расшифровать ключом из WinCred Yandex.Browser.
  * Там хранится 36 байт значение, первые 4 байта это префикс, а дальше 32 байта сам ключ. Используется скорее всего чтобы 
  * восстанавливать данные. В случае если localstate удален.
  */


  try {
    char path[MAX_PATH];

    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path) != S_OK) {
      std::cout << "Cannot get path to localappdata";

      return -1;
    }

    fs::path user_data_path = path;
    user_data_path /= "Yandex\\YandexBrowser\\User Data";

    YaDecryptor decryptor(user_data_path.string().c_str());

    decryptor.init();

    auto passwords = decryptor.get_passwords();

    std::cout << "==================================PASSWORDS==================================";

    for (auto &password : passwords) {
      std::cout << "\n" << "Url: " << password.url << "\n";
      std::cout << "Username: " << password.username << "\n";
      std::cout << "Password: " << password.password << "\n";
    }
    std::cout << "=============================================================================" << "\n";
    std::cout << std::endl;

    auto credit_cards = decryptor.get_credit_cards();

    std::cout << "==================================CREDIT_CARDS==================================";

    for (auto &credit_card : credit_cards) {
      std::cout << "\n" << "Card number: " << credit_card.card_number << "\n";
      std::cout << "CVC: " << credit_card.pin_code << "\n";
      std::cout << "Comment: " << credit_card.secret_comment << "\n";
      std::cout << "Card holder: " << credit_card.card_holder << "\n";
      std::cout << "Card title: " << credit_card.card_title << "\n";
      std::cout << "Expiration date: " << credit_card.expire_date_year << "/" << credit_card.expire_date_month << "\n";
    }
    std::cout << "=============================================================================" << "\n";
    std::cout << std::endl;
  }
  catch (std::exception &ex) {
    std::cout << ex.what() << std::endl;
  }

  int a;
  std::cin >> a;
}