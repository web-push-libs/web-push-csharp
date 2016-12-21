using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace WebPush.Util
{
    public class JWSSigner
    {
        private readonly CngKey _signingKey;

        // If changed, also look at changing CngAlgorithm.Sga256
        private const int KEY_SIZE = 256;

        public JWSSigner(CngKey signingKey)
        {
            if (signingKey.KeySize != KEY_SIZE)
            {
                throw new ArgumentException("Signing key is not of size " + KEY_SIZE);
            }

            _signingKey = signingKey;
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
            using (ECDsaCng signer = new ECDsaCng(_signingKey))
            {
                signer.HashAlgorithm = CngAlgorithm.Sha256;

                byte[] signatureBytes = signer.SignData(Encoding.UTF8.GetBytes(securedInput));
                string signature = UrlBase64.Encode(signatureBytes);
                return String.Format("{0}.{1}", securedInput, signature);
            }
        }

        private static string SecureInput(Dictionary<string, object> header, Dictionary<string, object> payload)
        {
            string encodeHeader = UrlBase64.Encode(Encoding.UTF8.GetBytes(Newtonsoft.Json.JsonConvert.SerializeObject(header)));
            string encodePayload = UrlBase64.Encode(Encoding.UTF8.GetBytes(Newtonsoft.Json.JsonConvert.SerializeObject(payload)));

            return String.Format("{0}.{1}", encodeHeader, encodePayload);
        }
    }
}
