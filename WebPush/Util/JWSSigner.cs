using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace WebPush.Util
{
    internal class JWSSigner
    {
        private readonly ECPrivateKeyParameters _privateKey;

        public JWSSigner(ECPrivateKeyParameters privateKey)
        {
            _privateKey = privateKey;
        }

        /// <summary>
        ///     Generates a Jws Signature.
        /// </summary>
        /// <param name="header"></param>
        /// <param name="payload"></param>
        /// <returns></returns>
        public string GenerateSignature(Dictionary<string, object> header, Dictionary<string, object> payload)
        {
            var securedInput = SecureInput(header, payload);
            var message = Encoding.UTF8.GetBytes(securedInput);

            byte[] hashedMessage =sha256Hash(message);

            var signer = new ECDsaSigner();
            signer.Init(true, _privateKey);
            var results = signer.GenerateSignature(hashedMessage);

            // Concated to create signature
            var a = results[0].ToByteArrayUnsigned();
            var b = results[1].ToByteArrayUnsigned();

            // a,b are required to be exactly the same length of bytes
            if (a.Length != b.Length)
            {
                var largestLength = Math.Max(a.Length, b.Length);
                a = ByteArrayPadLeft(a, largestLength);
                b = ByteArrayPadLeft(b, largestLength);
            }

            var signature = UrlBase64.Encode(a.Concat(b).ToArray());
            return string.Format("{0}.{1}", securedInput, signature);
        }

        private static string SecureInput(Dictionary<string, object> header, Dictionary<string, object> payload)
        {
            var encodeHeader = UrlBase64.Encode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(header)));
            var encodePayload = UrlBase64.Encode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(payload)));

            return string.Format("{0}.{1}", encodeHeader, encodePayload);
        }

        private static byte[] ByteArrayPadLeft(byte[] src, int size)
        {
            var dst = new byte[size];
            var startAt = dst.Length - src.Length;
            Array.Copy(src, 0, dst, startAt, src.Length);
            return dst;
        }

        private static byte[] sha256Hash(byte[] message)
        {
            Sha256Digest sha256Digest = new Sha256Digest();
            sha256Digest.BlockUpdate(message, 0, message.Length);
            byte[] hash = new byte[sha256Digest.GetDigestSize()];
            sha256Digest.DoFinal(hash, 0);
            return hash;
        }
    }
}