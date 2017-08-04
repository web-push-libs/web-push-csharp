using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using WebPush.Util;
using Xunit;

namespace WebPush.Test
{
    public class ECKeyHelperTest
    {
        private const string TEST_PUBLIC_KEY =
            @"BCvKwB2lbVUYMFAaBUygooKheqcEU-GDrVRnu8k33yJCZkNBNqjZj0VdxQ2QIZa4kV5kpX9aAqyBKZHURm6eG1A";

        private const string TEST_PRIVATE_KEY = @"on6X5KmLEFIVvPP3cNX9kE0OF6PV9TJQXVbnKU2xEHI";

        [Fact]
        public void TestGetPublicKey()
        {
            byte[] publicKey = UrlBase64.Decode(TEST_PUBLIC_KEY);
            ECPublicKeyParameters publicKeyParams = ECKeyHelper.GetPublicKey(publicKey);

            string importedPublicKey = UrlBase64.Encode(publicKeyParams.Q.GetEncoded(false));

            Assert.Equal(TEST_PUBLIC_KEY, importedPublicKey);
        }

        [Fact]
        public void TestGetPrivateKey()
        {
            byte[] privateKey = UrlBase64.Decode(TEST_PRIVATE_KEY);
            ECPrivateKeyParameters privateKeyParams = ECKeyHelper.GetPrivateKey(privateKey);

            string importedPrivateKey = UrlBase64.Encode(privateKeyParams.D.ToByteArrayUnsigned());

            Assert.Equal(TEST_PRIVATE_KEY, importedPrivateKey);
        }

        [Fact]
        public void TestGenerateKeys()
        {
            AsymmetricCipherKeyPair keys = ECKeyHelper.GenerateKeys();

            byte[] publicKey = ((ECPublicKeyParameters) keys.Public).Q.GetEncoded(false);
            byte[] privateKey = ((ECPrivateKeyParameters) keys.Private).D.ToByteArrayUnsigned();

            int publicKeyLength = publicKey.Length;
            int privateKeyLength = privateKey.Length;

            Assert.Equal(65, publicKeyLength);
            Assert.Equal(32, privateKeyLength);

;        }

        [Fact]
        public void TestGenerateKeysNoCache()
        {
            AsymmetricCipherKeyPair keys1 = ECKeyHelper.GenerateKeys();
            AsymmetricCipherKeyPair keys2 = ECKeyHelper.GenerateKeys();

            byte[] publicKey1 = ((ECPublicKeyParameters)keys1.Public).Q.GetEncoded(false);
            byte[] privateKey1 = ((ECPrivateKeyParameters)keys1.Private).D.ToByteArrayUnsigned();

            byte[] publicKey2 = ((ECPublicKeyParameters)keys2.Public).Q.GetEncoded(false);
            byte[] privateKey2 = ((ECPrivateKeyParameters)keys2.Private).D.ToByteArrayUnsigned();
            
            Assert.False(publicKey1.SequenceEqual(publicKey2));
            Assert.False(privateKey1.SequenceEqual(privateKey2));
        }
    }
}