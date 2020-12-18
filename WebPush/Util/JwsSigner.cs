using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;
using System.Security.Cryptography;

namespace WebPush.Util
{
	internal class JwsSigner
    {
        private readonly AsymmetricAlgorithm _privateKey;

        public JwsSigner(AsymmetricAlgorithm privateKey)
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

            var hashedMessage = Sha256Hash(message);
			byte[] results = null;

			if (_privateKey is ECDsaCng)
			{
				(_privateKey as ECDsaCng).HashAlgorithm = CngAlgorithm.Sha256;
				results = (_privateKey as ECDsaCng).SignHash(hashedMessage);
			}
			else
				throw new Exception($"Algorithm {_privateKey?.GetType()} not supported");

			var signature = UrlBase64.Encode(results);
			return $"{securedInput}.{signature}";
        }

        private static string SecureInput(Dictionary<string, object> header, Dictionary<string, object> payload)
        {
            var encodeHeader = UrlBase64.Encode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(header)));
            var encodePayload = UrlBase64.Encode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(payload)));

            return $"{encodeHeader}.{encodePayload}";
        }

        private static byte[] ByteArrayPadLeft(byte[] src, int size)
        {
            var dst = new byte[size];
            var startAt = dst.Length - src.Length;
            Array.Copy(src, 0, dst, startAt, src.Length);
            return dst;
        }

		private static byte[] Sha256Hash(byte[] message)
		{
			using (SHA256 sha256Hash = SHA256.Create())
			{
				return sha256Hash.ComputeHash(message);
			}
		}		
	}
}
