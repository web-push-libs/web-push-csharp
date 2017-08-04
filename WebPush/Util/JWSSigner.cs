using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace WebPush.Util
{
    public class JWSSigner
    {
        private readonly ECPrivateKeyParameters _privateKey;

        public JWSSigner(ECPrivateKeyParameters privateKey)
        {
            _privateKey = privateKey;
        }

        /// <summary>
        /// Generates a Jws Signature.
        /// </summary>
        /// <param name="header"></param>
        /// <param name="payload"></param>
        /// <returns></returns>
        public string GenerateSignature(Dictionary<string, object> header, Dictionary<string, object> payload)
        {

            string securedInput = SecureInput(header, payload);
            byte[] message = Encoding.UTF8.GetBytes(securedInput);

            byte[] hashedMessage;
            using (var sha256Hasher = SHA256.Create())
            {
                hashedMessage = sha256Hasher.ComputeHash(message);
            }

            ECDsaSigner signer = new ECDsaSigner();
            signer.Init(true, _privateKey);
            BigInteger[] results = signer.GenerateSignature(hashedMessage);

            // Concated to create signature
            var a = results[0].ToByteArrayUnsigned();
            var b = results[1].ToByteArrayUnsigned();

            // a,b are required to be exactly the same length of bytes
            if (a.Length != b.Length)
            {
                int largestLength = Math.Max(a.Length, b.Length);
                a = ByteArrayPadLeft(a, largestLength);
                b = ByteArrayPadLeft(b, largestLength);
            }

            string signature = UrlBase64.Encode(a.Concat(b).ToArray());
            return String.Format("{0}.{1}", securedInput, signature);
        }

        private static string SecureInput(Dictionary<string, object> header, Dictionary<string, object> payload)
        {
            string encodeHeader = UrlBase64.Encode(Encoding.UTF8.GetBytes(Newtonsoft.Json.JsonConvert.SerializeObject(header)));
            string encodePayload = UrlBase64.Encode(Encoding.UTF8.GetBytes(Newtonsoft.Json.JsonConvert.SerializeObject(payload)));

            return String.Format("{0}.{1}", encodeHeader, encodePayload);
        }

        private static byte[] ByteArrayPadLeft(byte[] src, int size)
        {
            byte[] dst = new byte[size];
            var startAt = dst.Length - src.Length;
            Array.Copy(src, 0, dst, startAt, src.Length);
            return dst;
        }
    }
}