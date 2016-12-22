using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace WebPush.Util
{
    public static class CngKeyHelper
    {
        public static CngKey ImportCngKeyFromPublicKey(byte[] userKey)
        {
            byte[] keyType = new byte[] { 0x45, 0x43, 0x4B, 0x31 };
            byte[] keyLength = new byte[] { 0x20, 0x00, 0x00, 0x00 };

            byte[] keyImport = keyType.Concat(keyLength).Concat(userKey.Skip(1)).ToArray();

            return CngKey.Import(keyImport, CngKeyBlobFormat.EccPublicBlob);
        }

        public static byte[] ImportPublicKeyFromCngKey(byte[] cngKey)
        {
            return (new byte[] { 0x04 }).Concat(cngKey.Skip(8)).ToArray();
            
        }

        public static ECPrivateKeyParameters GetPrivateKey(byte[] privateKey)
        {
            Asn1Object version = new DerInteger(1);
            Asn1Object derEncodedKey = new DerOctetString(privateKey);
            Asn1Object keyTypeParameters = new DerTaggedObject(0, new DerObjectIdentifier(@"1.2.840.10045.3.1.7"));

            Asn1Object derSequence = new DerSequence(version,derEncodedKey,keyTypeParameters);

            var base64EncodedDerSequence = Convert.ToBase64String(derSequence.GetDerEncoded());
            var pemKey = "-----BEGIN EC PRIVATE KEY-----\n";
            pemKey += base64EncodedDerSequence;
            pemKey += "\n-----END EC PRIVATE KEY----";

            StringReader reader = new StringReader(pemKey); 
            PemReader pemReader = new PemReader(reader);
            AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();

            return (ECPrivateKeyParameters)keyPair.Private;
        }

        //TODO: Fix to produce valid keys.
        // Currently producing keys that are 33 bytes in length, 32 required
        public static AsymmetricCipherKeyPair GenerateKeys()
        {
            ECKeyPairGenerator gen = new ECKeyPairGenerator();
            SecureRandom secureRandom = new SecureRandom();
            DerObjectIdentifier curveName = X962NamedCurves.GetOid("prime256v1");
            ECKeyGenerationParameters genParam = new ECKeyGenerationParameters(curveName, secureRandom);
            gen.Init(genParam);
            return gen.GenerateKeyPair();
        }
    }
}
