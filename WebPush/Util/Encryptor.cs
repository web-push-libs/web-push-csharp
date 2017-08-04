using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

// @LogicSoftware
// Originally from https://github.com/LogicSoftware/WebPushEncryption/blob/master/src/Encryptor.cs
namespace WebPush.Util
{
    public static class Encryptor
    {
        private static readonly RandomNumberGenerator RandomNumberProvider = RandomNumberGenerator.Create();

        public static EncryptionResult Encrypt(string userKey, string userSecret, string payload)
        {
            byte[] userKeyBytes = UrlBase64.Decode(userKey);
            byte[] userSecretBytes = UrlBase64.Decode(userSecret);
            byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);

            return Encrypt(userKeyBytes, userSecretBytes, payloadBytes);
        }

        public static EncryptionResult Encrypt(byte[] userKey, byte[] userSecret, byte[] payload)
        {
            byte[] salt = GenerateSalt(16);
            AsymmetricCipherKeyPair serverKeyPair = ECKeyHelper.GenerateKeys();

            IBasicAgreement ecdhAgreement = AgreementUtilities.GetBasicAgreement("ECDH");
            ecdhAgreement.Init(serverKeyPair.Private);

            ECPublicKeyParameters userPublicKey = ECKeyHelper.GetPublicKey(userKey);

            byte[] key = ecdhAgreement.CalculateAgreement(userPublicKey).ToByteArrayUnsigned();
            byte[] serverPublicKey = ((ECPublicKeyParameters)serverKeyPair.Public).Q.GetEncoded(false);

            byte[] prk = HKDF(userSecret, key, Encoding.UTF8.GetBytes("Content-Encoding: auth\0"), 32);
            byte[] cek = HKDF(salt, prk, CreateInfoChunk("aesgcm", userKey, serverPublicKey), 16);
            byte[] nonce = HKDF(salt, prk, CreateInfoChunk("nonce", userKey, serverPublicKey), 12);

            byte[] input = AddPaddingToInput(payload);
            byte[] encryptedMessage = EncryptAes(nonce, cek, input);

            return new EncryptionResult
            {
                Salt = salt,
                Payload = encryptedMessage,
                PublicKey = serverPublicKey
            };
        }

        private static byte[] GenerateSalt(int length)
        {
            byte[] salt = new byte[length];
            RandomNumberProvider.GetBytes(salt);
            return salt;
        }

        private static byte[] AddPaddingToInput(byte[] data)
        {
            byte[] input = new byte[0 + 2 + data.Length];
            Buffer.BlockCopy(ConvertInt(0), 0, input, 0, 2);
            Buffer.BlockCopy(data, 0, input, 0 + 2, data.Length);
            return input;
        }

        private static byte[] EncryptAes(byte[] nonce, byte[] cek, byte[] message)
        {
            GcmBlockCipher cipher = new GcmBlockCipher(new AesFastEngine());
            AeadParameters parameters = new AeadParameters(new KeyParameter(cek), 128, nonce);
            cipher.Init(true, parameters);

            //Generate Cipher Text With Auth Tag
            byte[] cipherText = new byte[cipher.GetOutputSize(message.Length)];
            int len = cipher.ProcessBytes(message, 0, message.Length, cipherText, 0);
            cipher.DoFinal(cipherText, len);

            //byte[] tag = cipher.GetMac();
            return cipherText;
        }

        public static byte[] HKDFSecondStep(byte[] key, byte[] info, int length)
        {
            HMACSHA256 hmac = new HMACSHA256(key);
            byte[] infoAndOne = info.Concat(new byte[] { 0x01 }).ToArray();
            byte[] result = hmac.ComputeHash(infoAndOne);

            if (result.Length > length) Array.Resize(ref result, length);
            return result;
        }

        public static byte[] HKDF(byte[] salt, byte[] prk, byte[] info, int length)
        {
            HMACSHA256 hmac = new HMACSHA256(salt);
            byte[] key = hmac.ComputeHash(prk);

            return HKDFSecondStep(key, info, length);
        }

        public static byte[] ConvertInt(int number)
        {
            byte[] output = BitConverter.GetBytes(Convert.ToUInt16(number));
            if (BitConverter.IsLittleEndian) Array.Reverse(output);
            return output;
        }

        public static byte[] CreateInfoChunk(string type, byte[] recipientPublicKey, byte[] senderPublicKey)
        {
            List<byte> output = new List<byte>();
            output.AddRange(Encoding.UTF8.GetBytes($"Content-Encoding: {type}\0P-256\0"));
            output.AddRange(ConvertInt(recipientPublicKey.Length));
            output.AddRange(recipientPublicKey);
            output.AddRange(ConvertInt(senderPublicKey.Length));
            output.AddRange(senderPublicKey);
            return output.ToArray();
        }
    }
}