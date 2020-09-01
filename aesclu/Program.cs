using Scrypt;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AESCommandLineUtil
{
    internal static class Program
    {
        private const string VERSION_STRING = "v2.9-1.20";
        private const string DATE_STRING = "2020-09-01";
        private static bool isLegacy = false;

        private static long BufferSize = 16777216;

        private static void Main(string[] args)
        {
            string inputFile = string.Empty;
            if (args.Length >= 1)
            {
                if (new string[] { "-h", "--help", "/?" }.Contains(args[0].ToLower()))
                {
                    Help();
                    return;
                }
                else if (args[0].Equals("-v"))
                {
                    PrintVersion();
                    return;
                }
                inputFile = args[0];
            }
            if (!File.Exists(inputFile) && args.Length != 0)
            {
                Console.WriteLine("Error: no such file.");
                return;
            }
            string password = string.Empty;
            string mode = string.Empty;
            switch (args.Length)
            {
                case 1:
                    if (!InteractiveSetup(ref password, ref mode))
                    {
                        return;
                    }
                    break;

                case 2:
                    if (args[1].Equals("--legacy", StringComparison.OrdinalIgnoreCase))
                    {
                        isLegacy = true;
                        if (!InteractiveSetup(ref password, ref mode))
                        {
                            return;
                        }
                    }
                    else
                    {
                        Help();
                        return;
                    }
                    break;

                case 3:
                case 4:
                case 5:
                    password = args[1];
                    mode = args[2];
                    break;

                default:
                    Help();
                    return;
            }
            if (args.Length >= 4)
            {
                try
                {
                    BufferSize = Convert.ToInt32(args[3]);
                }
                catch (FormatException)
                {
                    Console.WriteLine("Error: invalid buffer size.");
                }
                if (args.Length == 5 && args[4].Equals("--legacy", StringComparison.OrdinalIgnoreCase))
                {
                    isLegacy = true;
                }
                else if (args.Length > 4)
                {
                    Help();
                    return;
                }
            }
            if (mode.Equals("-e", StringComparison.OrdinalIgnoreCase))
            {
                AesCbcEncrypt(inputFile, password);
            }
            else if (mode.Equals("-d", StringComparison.OrdinalIgnoreCase))
            {
                AesCbcDecrypt(inputFile, password);
            }
            else
            {
                Console.WriteLine("Third argument has to be -(e)ncrypt or -(d)ecrypt");
            }
        }

        private static bool InteractiveSetup(ref string password, ref string mode)
        {
            // Interactive mode
            PrintVersion();
            Console.Write("Enter password: ");
            password = ReadPassword("Enter password: ");
            while (true)
            {
                Console.WriteLine("\nWhat to do?");
                Console.WriteLine("[1] encrypt file");
                Console.WriteLine("[2] decrypt file");
                Console.Write(" > ");
                ConsoleKeyInfo keyInfo = Console.ReadKey(false);
                Console.WriteLine("");
                if (keyInfo.Key == ConsoleKey.D1 || keyInfo.Key == ConsoleKey.NumPad1)
                {
                    Console.Write("Repeat password: ");
                    if (!password.Equals(ReadPassword("Repeat password: ")))
                    {
                        Console.WriteLine("Error: These passwords don't match!");
                        Console.WriteLine("Bye ...");
                        return false;
                    }
                    mode = "-e";
                    return true;
                }
                else if (keyInfo.Key == ConsoleKey.D2 || keyInfo.Key == ConsoleKey.NumPad2)
                {
                    mode = "-d";
                    return true;
                }
                else
                {
                    Console.WriteLine("Error: Invalid option!");
                }
            }
        }

        private static string ReadPassword(string prompt)
        {
            StringBuilder passwordBuilder = new StringBuilder();
            StringBuilder currentLine = new StringBuilder(prompt);
            ConsoleKeyInfo keyInfo;
            while (true)
            {
                keyInfo = Console.ReadKey(true);
                if (keyInfo.Key == ConsoleKey.Enter)
                {
                    break;
                }
                if (keyInfo.Key == ConsoleKey.Backspace)
                {
                    if (passwordBuilder.Length > 0)
                    {
                        passwordBuilder.Remove(passwordBuilder.Length - 1, 1);
                        currentLine.Remove(currentLine.Length - 1, 1);
                        Console.Write("\r" + new string(' ', currentLine.Length + 1));
                        Console.Write("\r" + currentLine.ToString());
                    }
                }
                else
                {
                    passwordBuilder.Append(keyInfo.KeyChar);
                    currentLine.Append('*');
                    Console.Write("\r" + currentLine.ToString());
                }
            }
            Console.WriteLine("");
            return passwordBuilder.ToString();
        }

        private static void Help()
        {
            PrintVersion();
            Console.WriteLine("USAGE:");
            Console.WriteLine("Parameters in <> are required, [] are optional.");
            Console.WriteLine("aesclu <filename> [<password> <mode> [buffer size in bytes]] [--legacy]\n");
            Console.WriteLine("Additional Options:");
            Console.WriteLine("   -h shows this usage information.");
            Console.WriteLine("   --help shows this usage information.");
            Console.WriteLine("   /? shows this usage information.");
            Console.WriteLine("   -v print version number.\n");
            Console.WriteLine("   Where --legacy will enable support for the .aes2 file format.");
        }

        private static void PrintVersion()
        {
            Console.WriteLine("----------------------------------------------------------");
            Console.WriteLine("AES Command Line Util " + VERSION_STRING + " - " + DATE_STRING);
            Console.WriteLine("Copyright (c) " + DATE_STRING.Split('-')[0] + " Frederik Hoeft\n");
        }

        public static void AesCbcEncrypt(string inputFile, string password)
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            using SHA256 sha = SHA256.Create();
            byte[] hashedPasswordBytes = sha.ComputeHash(passwordBytes);
            FileInfo info = new FileInfo(inputFile);
            long size = info.Length;
            long encryptedSize = 0;
            string outputFile = inputFile + (isLegacy ? ".aes2" : ".lsec");
            PrintStats(info, outputFile, false);
            Console.WriteLine("Starting Encryption ...");
            using FileStream fsin = new FileStream(inputFile, FileMode.Open);
            using FileStream fsout = new FileStream(outputFile, FileMode.Create);
            using AesCng AES = new AesCng
            {
                KeySize = 256,
                Key = hashedPasswordBytes
            };
            AES.IV = GetRandomBytes(AES.BlockSize / 8);
            AES.Mode = CipherMode.CBC;
            if (!isLegacy)
            {
                ScryptProvider scryptProvider = new ScryptProvider(password);
                passwordBytes = Encoding.UTF8.GetBytes(scryptProvider.ComputeHash());
                fsout.Write(passwordBytes, 0, passwordBytes.Length);
            }
            fsout.Write(AES.IV, 0, AES.IV.Length);
            using ICryptoTransform encryptor = AES.CreateEncryptor();
            using CryptoStream cs = new CryptoStream(fsout, encryptor, CryptoStreamMode.Write);
            byte[] buffer = new byte[BufferSize];
            int read;
            try
            {
                while ((read = fsin.Read(buffer, 0, buffer.Length)) > 0)
                {
                    cs.Write(buffer, 0, read);
                    encryptedSize += buffer.Length;
                    ShowProgress(encryptedSize, size, false);
                }
                cs.FlushFinalBlock();
                fsout.Flush();
            }
            catch (CryptographicException e)
            {
                Console.WriteLine("\nFatal error: " + e.Message);
                try
                {
                    File.Delete(outputFile);
                }
                catch (Exception)
                {
                }
            }
        }

        public static void AesCbcDecrypt(string inputFile, string password)
        {
            string[] directoryParts = inputFile.Split(Path.DirectorySeparatorChar);
            string dir = string.Join(Path.DirectorySeparatorChar, directoryParts[..^1]);
            string[]? filenameParts = directoryParts.LastOrDefault()?.Split('.');
            if (filenameParts == null)
            {
                Console.WriteLine("The provided file is invalid!");
                return;
            }
            string fileExtension = filenameParts.LastOrDefault();
            string outputFile = dir;
            if (string.IsNullOrEmpty(fileExtension) || !new string[] { "aes2", "lsec" }.Contains(fileExtension.ToLower()))
            {
                outputFile += Path.DirectorySeparatorChar + string.Join('.', filenameParts) + ".decrypted";
            }
            else
            {
                if (!isLegacy && fileExtension.Equals("aes2", StringComparison.OrdinalIgnoreCase))
                {
                    isLegacy = true;
                }
                outputFile += Path.DirectorySeparatorChar + string.Join('.', filenameParts[..^1]);
            }
            byte[] buffer = new byte[BufferSize];
            int read;

            FileInfo info = new FileInfo(inputFile);
            long size = info.Length;
            long decryptedSize = 0;
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            using SHA256 sha = SHA256.Create();
            byte[] hashedPasswordBytes = sha.ComputeHash(passwordBytes);
            using FileStream fsin = new FileStream(inputFile, FileMode.Open);
            FileStream fsout = new FileStream(outputFile, FileMode.Create);
            using AesCng AES = new AesCng();
            if (!isLegacy)
            {
                ScryptProvider scryptProvider = new ScryptProvider(password);
                byte[] scryptHashBytes = new byte[103];
                fsin.Read(scryptHashBytes, 0, scryptHashBytes.Length);
                string scryptHash = Encoding.UTF8.GetString(scryptHashBytes);
                if (!scryptProvider.IsValid(scryptHash))
                {
                    Console.WriteLine("Invalid file format! You may try using the --legacy option.");
                    return;
                }
                if (!scryptProvider.Compare(scryptHash))
                {
                    Console.WriteLine("Invalid password!");
                    return;
                }
            }
            PrintStats(info, outputFile, true);
            Console.WriteLine("Starting Decryption ...");
            byte[] iv = new byte[16];
            fsin.Read(iv, 0, iv.Length);
            AES.IV = iv;
            AES.KeySize = 256;
            AES.Mode = CipherMode.CBC;
            AES.Key = hashedPasswordBytes;

            using ICryptoTransform decryptor = AES.CreateDecryptor();
            using CryptoStream cs = new CryptoStream(fsin, decryptor, CryptoStreamMode.Read);
            try
            {
                while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    fsout.Write(buffer, 0, read);
                    decryptedSize += buffer.Length;
                    ShowProgress(decryptedSize, size, true);
                }
                fsout.Flush();
            }
            catch (CryptographicException e)
            {
                Console.WriteLine("\nFatal error: " + e.Message);
                Console.WriteLine("   This might be due to an incorrect password or the file being corrupted.");
                try
                {
                    fsout.Close();
                    File.Delete(outputFile);
                }
                catch (Exception ex)
                {
                }
            }
        }

        private static RandomNumberGenerator? randomNumberGenerator;

        /// <summary>
        /// Generates cryptographically secure random bytes.
        /// </summary>
        /// <param name="saltLength">The number of bytes to be generated.</param>
        /// <returns>Cryptographically secure random bytes.</returns>
        public static byte[] GetRandomBytes(int saltLength)
        {
            if (randomNumberGenerator == null)
            {
                randomNumberGenerator = RandomNumberGenerator.Create();
            }
            byte[] randomBytes = new byte[saltLength];
            randomNumberGenerator.GetBytes(randomBytes);
            return randomBytes;
        }

        private static void PrintStats(FileInfo info, string outputFile, bool isDecrypt)
        {
            Console.WriteLine("----------------------------------------------------------");
            Console.WriteLine("--- FILE STATS");
            Console.WriteLine("------ File Name IN: " + info.Name);
            Console.WriteLine("------ File Name OUT: " + outputFile);
            Console.WriteLine("------ Size: " + info.Length.ToHumanReadableFileSize(2));
            Console.WriteLine("--- ENCRYPTION");
            Console.WriteLine("------ Algorithm: AES");
            Console.WriteLine("------ Key Size: 256 Bit");
            Console.WriteLine("------ Block Size: 128 Bit");
            Console.WriteLine("------ Cipher Mode: CBC");
            Console.WriteLine("--- PROGRAM SETTINGS");
            Console.WriteLine("------ Mode: " + (isDecrypt ? "Decrypt" : "Encrypt"));
            Console.WriteLine("------ Buffer Size: " + BufferSize.ToHumanReadableFileSize(2));
            Console.WriteLine("----------------------------------------------------------");
        }

        private static void ShowProgress(long processedSize, long size, bool isDecrypt)
        {
            double percentage = processedSize / (double)size * 100;
            string finalPercentage = string.Format("{0:0.00}", percentage);
            if (processedSize > size)
            {
                Console.Write("\r" + (isDecrypt ? "Decrypting" : "Encrypting") + ": 100.00 % (" + size.ToHumanReadableFileSize(2) + " of " + size.ToHumanReadableFileSize(2) + ") ...");
            }
            else
            {
                Console.Write("\r" + (isDecrypt ? "Decrypting" : "Encrypting") + ": " + finalPercentage + " % (" + processedSize.ToHumanReadableFileSize(2) + " of " + size.ToHumanReadableFileSize(2) + ") ...");
            }
        }

        /// <summary>
        /// Represents an interface to apply the Scrypt hash function to a provided input string.
        /// </summary>
        private class ScryptProvider : HashFunction, ISecureRandomProvider
        {
            /// <summary>
            /// Creates a new instance of the <see cref="ScryptProvider"/> and specifies a string to be digested.
            /// </summary>
            /// <param name="input"><inheritdoc/></param>
            public ScryptProvider(string input) : base(input) { }

            /// <summary>
            /// Computes the digest of the specified input string using the Scrypt hash function as implemented by the <see cref="ScryptEncoder"/> and a random salt.
            /// </summary>
            /// <returns>The hex encoded, salted scrypt hash of the input string.</returns>
            public override string ComputeHash()
            {
                if (digest == null)
                {
                    ScryptEncoder scrypt = new ScryptEncoder(65536, 8, 1, ISecureRandomProvider.rngCryptoService);
                    digest = scrypt.Encode(input);
                }
                return digest;
            }

            /// <inheritdoc/>
            public override bool Compare(string hash)
            {
                if (digest != null)
                {
                    return digest.Equals(hash);
                }
                ScryptEncoder scrypt = new ScryptEncoder(65536, 8, 1, ISecureRandomProvider.rngCryptoService);
                return scrypt.Compare(input, hash);
            }

            public bool IsValid(string hash)
            {
                ScryptEncoder scrypt = new ScryptEncoder(65536, 8, 1, ISecureRandomProvider.rngCryptoService);
                return scrypt.IsValid(hash);
            }
        }

        /// <summary>
        /// Defines generalized methods that should be implemented by any hash function.
        /// </summary>
        private abstract class HashFunction
        {
            /// <summary>
            /// The string to be digested.
            /// </summary>
            private protected readonly string input;

            /// <summary>
            /// Used to cache the result of the last call to <see cref="ComputeHash"/>.
            /// </summary>
            private protected string? digest;

            /// <summary>
            /// Creates a new instance of this <see cref="HashFunction"/> and specifies a string to be digested.
            /// </summary>
            /// <param name="input">The string to be digested.</param>
            protected HashFunction(string input)
            {
                this.input = input;
            }

            /// <summary>
            /// Computes the digest using the implemented hash function.
            /// </summary>
            /// <returns>A string representation of the computed hash.</returns>
            public abstract string ComputeHash();

            /// <summary>
            /// Compares the provided hash value with the digested string.
            /// </summary>
            /// <param name="hash">The hash value to be checked against.</param>
            /// <returns><c>true</c> if the provided hash matches the digest of the input this <see cref="HashFunction"/> was initialized with. <c>false</c> otherwise.</returns>
            public abstract bool Compare(string hash);
        }

        /// <summary>
        /// Provides a single shared instance of a <see cref="RNGCryptoServiceProvider"/> to be used by all cryptographic classes.
        /// </summary>
        private interface ISecureRandomProvider
        {
            /// <summary>
            /// The single shared instance of a <see cref="RNGCryptoServiceProvider"/>.
            /// </summary>
            private protected static readonly RNGCryptoServiceProvider rngCryptoService = new RNGCryptoServiceProvider();
        }
    }
}