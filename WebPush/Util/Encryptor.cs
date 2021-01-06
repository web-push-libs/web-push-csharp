using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Security.Cryptography;

namespace WebPush.Util
{
    // @LogicSoftware
    // Originally from https://github.com/LogicSoftware/WebPushEncryption/blob/master/src/Encryptor.cs
    public static class Encryptor
    {
        public static EncryptionResult Encrypt(string userKey, string userSecret, string payload)
        {
            byte[] userKeyBytes = UrlBase64.Decode(userKey);
            byte[] userSecretBytes = UrlBase64.Decode(userSecret);
            byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);

            return Encrypt(userKeyBytes, userSecretBytes, payloadBytes);
        }

        public static EncryptionResult Encrypt(byte[] userKey, byte[] userSecret, byte[] payload)
        {
            var salt = GenerateSalt(16);

            byte[] serverPublicKey = null;
            byte[] key = null;

            var cgnKey = ImportCngKeyFromPublicKey(userKey);
            using (ECDiffieHellmanCng alice = new ECDiffieHellmanCng(256))
            {
                alice.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hmac;
                alice.HashAlgorithm = CngAlgorithm.Sha256;
                alice.HmacKey = userSecret;

                serverPublicKey = ImportPublicKeyFromCngKey(alice.PublicKey.ToByteArray());
                key = alice.DeriveKeyMaterial(cgnKey);
            }

            var prk = HKDFSecondStep(key, Encoding.UTF8.GetBytes("Content-Encoding: auth\0"), 32);
            byte[] cek = HKDF(salt, prk, CreateInfoChunk("aesgcm", userKey, serverPublicKey), 16);
            byte[] nonce = HKDF(salt, prk, CreateInfoChunk("nonce", userKey, serverPublicKey), 12);

            var input = AddPaddingToInput(payload);

            var encryptedMessage = EncryptAes(nonce, cek, input);

            return new EncryptionResult
            {
                Salt = salt,
                Payload = encryptedMessage,
                PublicKey = serverPublicKey
            };
        }

        private static CngKey ImportCngKeyFromPublicKey(byte[] userKey)
        {
            var keyType = new byte[] { 0x45, 0x43, 0x4B, 0x31 };
            var keyLength = new byte[] { 0x20, 0x00, 0x00, 0x00 };

            var keyImport = keyType.Concat(keyLength).Concat(userKey.Skip(1)).ToArray();

            return CngKey.Import(keyImport, CngKeyBlobFormat.EccPublicBlob);
        }

        private static byte[] ImportPublicKeyFromCngKey(byte[] cngKey)
        {
            var keyImport = (new byte[] { 0x04 }).Concat(cngKey.Skip(8)).ToArray();

            return keyImport;
        }

        private static byte[] GenerateSalt(int length)
        {
            var salt = new byte[length];
            var random = new Random();
            random.NextBytes(salt);
            return salt;
        }

        private static byte[] AddPaddingToInput(byte[] data)
        {
            var input = new byte[0 + 2 + data.Length];
            Buffer.BlockCopy(ConvertInt(0), 0, input, 0, 2);
            Buffer.BlockCopy(data, 0, input, 0 + 2, data.Length);
            return input;
        }


        private static byte[] EncryptAes(byte[] nonce, byte[] cek, byte[] message)
        {
            using (AuthenticatedAesCng aes = new AuthenticatedAesCng())
            {
                aes.CngMode = CngChainingMode.Gcm;

                aes.Key = cek;

                aes.IV = nonce;

                using (MemoryStream ms = new MemoryStream())
                using (var encryptor = aes.CreateAuthenticatedEncryptor())
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    // Encrypt the secret message
                    cs.Write(message, 0, message.Length);

                    // Finish the encryption and get the output authentication tag and ciphertext
                    cs.FlushFinalBlock();
                    var ciphertext = ms.ToArray();

                    var tag = encryptor.GetTag();

                    return ciphertext.Concat(tag).ToArray();
                }
            }
        }

        public static byte[] HKDFSecondStep(byte[] key, byte[] info, int length)
        {
            var hmac = new HMACSHA256(key);
            var infoAndOne = info.Concat(new byte[] { 0x01 }).ToArray();
            var result = hmac.ComputeHash(infoAndOne);

            if (result.Length > length)
            {
                Array.Resize(ref result, length);
            }

            return result;
        }

        public static byte[] HKDF(byte[] salt, byte[] prk, byte[] info, int length)
        {
            var hmac = new HMACSHA256(salt);
            var key = hmac.ComputeHash(prk);

            return HKDFSecondStep(key, info, length);
        }

        public static byte[] ConvertInt(int number)
        {
            var output = BitConverter.GetBytes(Convert.ToUInt16(number));
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(output);
            }

            return output;
        }

        public static byte[] CreateInfoChunk(string type, byte[] recipientPublicKey, byte[] senderPublicKey)
        {
            var output = new List<byte>();
            output.AddRange(Encoding.UTF8.GetBytes($"Content-Encoding: {type}\0P-256\0"));
            output.AddRange(ConvertInt(recipientPublicKey.Length));
            output.AddRange(recipientPublicKey);
            output.AddRange(ConvertInt(senderPublicKey.Length));
            output.AddRange(senderPublicKey);
            return output.ToArray();
        }
    }
}