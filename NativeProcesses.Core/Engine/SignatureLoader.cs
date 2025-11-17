/*
   NativeProcesses Framework  |
   © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace NativeProcesses.Core.Inspection
{
    public static class SignatureLoader
    {
        // Hardcoded Key für die Datenbank (Sollte in Production obfuskiert sein)
        private static readonly byte[] Key = Encoding.UTF8.GetBytes("NativeProcesses_Secure_Sig_Key_!"); // 32 Bytes
        private static readonly byte[] IV = Encoding.UTF8.GetBytes("NativeProcess_IV"); // 16 Bytes

        public static List<SignatureModel> LoadEncryptedSignatures(string filePath)
        {
            if (!File.Exists(filePath)) return new List<SignatureModel>();

            try
            {
                byte[] encryptedBytes = File.ReadAllBytes(filePath);
                string json = DecryptStringFromBytes_Aes(encryptedBytes, Key, IV);
                return JsonConvert.DeserializeObject<List<SignatureModel>>(json);
            }
            catch (Exception)
            {
                // Fallback: Leere Liste oder Logging
                return new List<SignatureModel>();
            }
        }

        // Hilfsmethode zum Erstellen der Datei (für dich als Entwickler)
        public static void SaveSignaturesEncrypted(string filePath, List<SignatureModel> signatures)
        {
            string json = JsonConvert.SerializeObject(signatures, Formatting.Indented);
            byte[] encrypted = EncryptStringToBytes_Aes(json, Key, IV);
            File.WriteAllBytes(filePath, encrypted);
        }

        private static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            if (plainText == null || plainText.Length <= 0) throw new ArgumentNullException("plainText");
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                    return msEncrypt.ToArray();
                }
            }
        }

        private static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            if (cipherText == null || cipherText.Length <= 0) return null;
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                {
                    return srDecrypt.ReadToEnd();
                }
            }
        }
    }
}