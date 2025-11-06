/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace NativeProcesses.Core
{
    public static class SignatureVerifier
    {
        #region Structs & Enums
        private enum WinTrustDataUIChoice : uint
        {
            All = 1,
            None = 2,
            NoBad = 3,
            NoGood = 4
        }

        private enum WinTrustDataRevocationChecks : uint
        {
            None = 0,
            WholeChain = 1
        }

        private enum WinTrustDataChoice : uint
        {
            File = 1,
            Catalog = 2,
            Blob = 3,
            Signer = 4,
            Certificate = 5
        }

        private enum WinTrustDataStateAction : uint
        {
            Ignore = 0,
            Verify = 1,
            Close = 2,
            AutoVerify = 3,
            AutoVerifyClose = 4
        }

        [Flags]
        private enum WinTrustDataFlags : uint
        {
            None = 0,
            UseIE4Trust = 1,
            NoIE4Chain = 2,
            NoPolicyUsage = 4,
            RevocationCheckNone = 16,
            RevocationCheckEndCert = 32,
            RevocationCheckChain = 64,
            RevocationCheckChainExcludeRoot = 128,
            Safer = 256,
            HashOnly = 512,
            UseDefaultOSVerCheck = 1024,
            LifetimeSigning = 2048,
            CacheOnlyURLRetrieval = 4096,
            DisableMD2andMD4 = 8192
        }

        private enum WinVerifyTrustResult : uint
        {
            Success = 0,
            ProviderUnknown = 0x800b0001,
            ActionUnknown = 0x800b0002,
            SubjectFormUnknown = 0x800b0003,
            SubjectNotTrusted = 0x800b0004,
            FileNotSigned = 0x800B0100,
            UntrustedRoot = 0x800B0109,
            CertExpired = 0x800B0101
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private class WINTRUST_FILE_INFO
        {
            public uint cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
            public IntPtr pcwszFilePath;
            public IntPtr hFile = IntPtr.Zero;
            public IntPtr pgKnownSubject = IntPtr.Zero;

            public WINTRUST_FILE_INFO(string filePath)
            {
                pcwszFilePath = Marshal.StringToCoTaskMemAuto(filePath);
            }

            ~WINTRUST_FILE_INFO()
            {
                if (pcwszFilePath != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(pcwszFilePath);
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private class WINTRUST_DATA
        {
            public uint cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
            public IntPtr pPolicyCallbackData = IntPtr.Zero;
            public IntPtr pSIPClientData = IntPtr.Zero;
            public WinTrustDataUIChoice dwUIChoice = WinTrustDataUIChoice.None;
            public WinTrustDataRevocationChecks fdwRevocationChecks = WinTrustDataRevocationChecks.None;
            public WinTrustDataChoice dwUnionChoice = WinTrustDataChoice.File;
            public IntPtr pFile;
            public WinTrustDataStateAction dwStateAction = WinTrustDataStateAction.Ignore;
            public IntPtr hWVTStateData = IntPtr.Zero;
            public IntPtr pwszURLReference = IntPtr.Zero;
            public WinTrustDataFlags dwFlags = WinTrustDataFlags.None;
            public uint dwProvFlags = 0;
            public uint dwUIContext = 0;

            ~WINTRUST_DATA()
            {
                if (pFile != IntPtr.Zero)
                {
                    Marshal.DestroyStructure(pFile, typeof(WINTRUST_FILE_INFO));
                    Marshal.FreeCoTaskMem(pFile);
                }
            }
        }

        private const string WINTRUST_ACTION_GENERIC_VERIFY_V2 = "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}";

        #endregion

        #region P/Invoke
        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
        private static extern uint WinVerifyTrust(
            IntPtr hwnd,
            [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
            IntPtr pWVTData);

        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool CryptQueryObject(
            int dwObjectType,
            IntPtr pvObject,
            int dwExpectedContentTypeFlags,
            int dwExpectedFormatTypeFlags,
            int dwFlags,
            out int pdwMsgAndCertEncodingType,
            out int pdwContentType,
            out int pdwFormatType,
            out IntPtr phCertStore,
            out IntPtr phMsg,
            out IntPtr ppvContext);

        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool CryptMsgGetParam(
            IntPtr hCryptMsg,
            int dwParamType,
            int dwIndex,
            IntPtr pvData,
            ref int pcbData);

        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool CryptMsgClose(IntPtr hCryptMsg);

        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool CertCloseStore(IntPtr hCertStore, int dwFlags);

        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CertFindCertificateInStore(
            IntPtr hCertStore,
            int dwCertEncodingType,
            int dwFindFlags,
            int dwFindType,
            IntPtr pvFindPara,
            IntPtr pPrevCertContext);

        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool CertFreeCertificateContext(IntPtr pCertContext);

        #endregion

        public static ProcessSignatureInfo Verify(string filePath)
        {
            var info = new ProcessSignatureInfo();
            var guidAction = new Guid(WINTRUST_ACTION_GENERIC_VERIFY_V2);
            var fileInfo = new WINTRUST_FILE_INFO(filePath);
            var wvtData = new WINTRUST_DATA();
            IntPtr pInfo = Marshal.AllocCoTaskMem(Marshal.SizeOf(fileInfo));
            Marshal.StructureToPtr(fileInfo, pInfo, false);
            wvtData.pFile = pInfo;

            IntPtr pData = Marshal.AllocCoTaskMem(Marshal.SizeOf(wvtData));
            Marshal.StructureToPtr(wvtData, pData, false);

            try
            {
                uint result = WinVerifyTrust(IntPtr.Zero, guidAction, pData);

                if (result == (uint)WinVerifyTrustResult.Success)
                {
                    info.IsSigned = true;
                    info.SignerName = GetSignerName(filePath);
                }
                else
                {
                    info.IsSigned = false;
                    if (result == (uint)WinVerifyTrustResult.FileNotSigned)
                    {
                        info.ErrorMessage = "Unsigned";
                    }
                    else
                    {
                        info.ErrorMessage = $"Untrusted (0x{result:X})";
                    }
                }
            }
            catch (Exception ex)
            {
                info.IsSigned = false;
                info.ErrorMessage = ex.Message;
            }
            finally
            {
                Marshal.FreeCoTaskMem(pData);
            }

            return info;
        }

        private static string GetSignerName(string filePath)
        {
            IntPtr pFilePath = Marshal.StringToCoTaskMemUni(filePath);
            try
            {
                bool result = CryptQueryObject(
                    1,
                    pFilePath,
                    0x40 | 0x8 | 0x1,
                    0 | 0,
                    0,
                    out int encodingType,
                    out int contentType,
                    out int formatType,
                    out IntPtr hCertStore,
                    out IntPtr hMsg,
                    out IntPtr ppvContext);

                if (!result)
                {
                    return "N/A (Query failed)";
                }

                try
                {
                    int pcbData = 0;
                    if (!CryptMsgGetParam(hMsg, 29, 0, IntPtr.Zero, ref pcbData))
                    {
                        return "N/A (MsgParam failed)";
                    }

                    IntPtr pvData = Marshal.AllocHGlobal(pcbData);
                    try
                    {
                        if (!CryptMsgGetParam(hMsg, 29, 0, pvData, ref pcbData))
                        {
                            return "N/A (MsgParam 2 failed)";
                        }

                        IntPtr pCertContext = CertFindCertificateInStore(
                            hCertStore,
                            encodingType,
                            0,
                            0x30000,
                            pvData,
                            IntPtr.Zero);

                        if (pCertContext != IntPtr.Zero)
                        {
                            try
                            {
                                var cert = new X509Certificate2(pCertContext);
                                return cert.GetNameInfo(X509NameType.SimpleName, false);
                            }
                            finally
                            {
                                CertFreeCertificateContext(pCertContext);
                            }
                        }
                        return "N/A (Cert not found)";
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(pvData);
                    }
                }
                finally
                {
                    CryptMsgClose(hMsg);
                    CertCloseStore(hCertStore, 0);
                }
            }
            catch
            {
                return "N/A (Exception)";
            }
            finally
            {
                Marshal.FreeCoTaskMem(pFilePath);
            }
        }

        #region Helper Structs for GetSignerName
        [StructLayout(LayoutKind.Sequential)]
        private struct CMSG_SIGNER_INFO
        {
            public int dwVersion;
            public CERT_NAME_BLOB Issuer;
            public CRYPT_INTEGER_BLOB SerialNumber;
            public CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
            public CRYPT_ALGORITHM_IDENTIFIER HashEncryptionAlgorithm;
            public CRYPT_DATA_BLOB EncryptedHash;
            public CRYPT_ATTRIBUTES AuthAttrs;
            public CRYPT_ATTRIBUTES UnauthAttrs;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CERT_NAME_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CRYPT_INTEGER_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CRYPT_ALGORITHM_IDENTIFIER
        {
            public IntPtr pszObjId;
            public CRYPT_DATA_BLOB Parameters;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CRYPT_DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CRYPT_ATTRIBUTES
        {
            public int cAttr;
            public IntPtr rgAttr;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CRYPT_ATTRIBUTE
        {
            public IntPtr pszObjId;
            public int cValue;
            public IntPtr rgValue;
        }
        #endregion
    }
}