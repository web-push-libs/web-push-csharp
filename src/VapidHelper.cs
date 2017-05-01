using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using WebPush.Util;

namespace WebPush
{
    public static class VapidHelper
    {
        /// <summary>
        /// Generate vapid keys
        /// </summary>
        /// <returns></returns>
        public static VapidDetails GenerateVapidKeys()
        {
            VapidDetails results = new VapidDetails();

            AsymmetricCipherKeyPair keys = ECKeyHelper.GenerateKeys();
            byte[] publicKey = ((ECPublicKeyParameters)keys.Public).Q.GetEncoded(false);
            byte[] privateKey = ((ECPrivateKeyParameters)keys.Private).D.ToByteArrayUnsigned();

            results.PublicKey = UrlBase64.Encode(publicKey);
            results.PrivateKey = UrlBase64.Encode(privateKey);

            return results;
        }

        /// <summary>
        /// This method takes the required VAPID parameters and returns the required
        /// header to be added to a Web Push Protocol Request. 
        /// </summary>
        /// <param name="audience">This must be the origin of the push service.</param>
        /// <param name="subject">This should be a URL or a 'mailto:' email address</param>
        /// <param name="publicKey">The VAPID public key as a base64 encoded string</param>
        /// <param name="privateKey">The VAPID private key as a base64 encoded string</param>
        /// <param name="expiration">The expiration of the VAPID JWT.</param>
        /// <returns>A dictionary of header key/value pairs.</returns>
        public static Dictionary<string, string> GetVapidHeaders(string audience, string subject, string publicKey, string privateKey, long expiration = -1)
        {
            ValidateAudience(audience);
            ValidateSubject(subject);
            ValidatePublicKey(publicKey);
            ValidatePrivateKey(privateKey);

            byte[] decodedPrivateKey = UrlBase64.Decode(privateKey);

            if (expiration == -1)
            {
                expiration = UnixTimeNow() + 43200;
            }

            Dictionary<string, object> header = new Dictionary<string, object>();
            header.Add("typ", "JWT");
            header.Add("alg", "ES256");

            Dictionary<string, object> jwtPayload = new Dictionary<string, object>();
            jwtPayload.Add("aud", audience);
            jwtPayload.Add("exp", expiration);
            jwtPayload.Add("sub", subject);

            ECPrivateKeyParameters signingKey = ECKeyHelper.GetPrivateKey(decodedPrivateKey);

            JWSSigner signer = new JWSSigner(signingKey);
            string token = signer.GenerateSignature(header, jwtPayload);

            Dictionary<string, string> results = new Dictionary<string, string>();
            results.Add("Authorization", "WebPush " + token);
            results.Add("Crypto-Key", "p256ecdsa=" + publicKey);

            return results;
        }

        public static void ValidateAudience(string audience)
        {
            if (String.IsNullOrEmpty(audience))
            {
                throw new ArgumentException(@"No audience could be generated for VAPID.");
            }

            if (audience.Length == 0)
            {
                throw new ArgumentException(@"The audience value must be a string containing the origin of a push service. " + audience);
            }

            if (!Uri.IsWellFormedUriString(audience, UriKind.Absolute))
            {
                throw new ArgumentException(@"VAPID audience is not a url.");
            }

        }

        public static void ValidateSubject(string subject)
        {
            if (String.IsNullOrEmpty(subject))
            {
                throw new ArgumentException(@"A subject is required");
            }

            if (subject.Length == 0)
            {
                throw new ArgumentException(@"The subject value must be a string containing a url or mailto: address.");
            }

            if (!subject.StartsWith("mailto:"))
            {
                if (!Uri.IsWellFormedUriString(subject, UriKind.Absolute))
                {
                    throw new ArgumentException(@"Subject is not a valid URL or mailto address");
                }
            }
        }

        public static void ValidatePublicKey(string publicKey)
        {
            if (String.IsNullOrEmpty(publicKey))
            {
                throw new ArgumentException(@"Valid public key not set");
            }

            byte[] decodedPublicKey = UrlBase64.Decode(publicKey);

            if (decodedPublicKey.Length != 65)
            {
                throw new ArgumentException(@"Vapid public key must be 65 characters long when decoded");
            }
        }


        public static void ValidatePrivateKey(string privateKey)
        {
            if (String.IsNullOrEmpty(privateKey))
            {
                throw new ArgumentException(@"Valid private key not set");
            }

            byte[] decodedPrivateKey = UrlBase64.Decode(privateKey);


            if (decodedPrivateKey.Length != 32)
            {
                throw new ArgumentException(@"Vapid private key should be 32 bytes long when decoded.");
            }
        }

        private static long UnixTimeNow()
        {
            TimeSpan timeSpan = (DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0));
            return (long)timeSpan.TotalSeconds;
        }
    }
}
