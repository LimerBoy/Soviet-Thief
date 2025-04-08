using System;
using System.IO;
using System.Text;
using System.Diagnostics;

namespace YandexDecryptor.Helpers
{
    internal static class IOUtils
    {
        public static readonly string
            LocalAppdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            RoamingAppdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);


        public static string ToUtf8(string s)
        {
            return Encoding.UTF8.GetString(Encoding.Default.GetBytes(s));
        }


        public static string CombinePaths(params string[] paths)
        {
            if (paths == null || paths.Length == 0)
                throw new ArgumentException("No paths provided.");

            string combinedPath = paths[0];

            for (int i = 1; i < paths.Length; i++)
            {
                combinedPath = Path.Combine(combinedPath, paths[i]);
            }

            return combinedPath;
        }


        /// <summary>
        /// Read file bytes from disk; Copy if busy
        /// </summary>
        /// <param name="f">FileInfo object</param>
        /// <returns>File bytes</returns>
        public static byte[] ReadFileBytes(FileInfo f)
        {
            try
            {

                return File.ReadAllBytes(f.FullName);
            }
            catch 
            {
                string tmp = Path.GetTempFileName();

                try
                {
                    File.Copy(f.FullName, tmp, overwrite: true);
                }
                catch 
                {
                    return new byte[] { };
                }


                byte[] data = File.ReadAllBytes(tmp);
                try
                {
                    File.Delete(tmp);
                }
                catch { }


                return data;
            }
        }

        public static byte[] ReadFileBytes(string f) => ReadFileBytes(new FileInfo(f));
        public static string ReadFileText(FileInfo f) => Encoding.UTF8.GetString(ReadFileBytes(f));
        public static string ReadFileText(string f) => ReadFileText(new FileInfo(f));



        public static int FindByteSequence(byte[] src, byte[] pattern)
        {
            int maxFirstCharSlot = src.Length - pattern.Length + 1;
            for (int i = 0; i < maxFirstCharSlot; i++)
            {
                if (src[i] != pattern[0]) // compare only first byte
                    continue;

                // found a match on first byte, now try to match rest of the pattern
                for (int j = pattern.Length - 1; j >= 1; j--)
                {
                    if (src[i + j] != pattern[j]) break;
                    if (j == 1) return i;
                }
            }
            return -1;
        }



    }
}
