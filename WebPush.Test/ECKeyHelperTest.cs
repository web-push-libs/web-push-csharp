using System.Linq;
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
        public void TestGenerateKeys()
        {
            var keys = ECKeyHelper.GenerateKeys();

            var publicKey = ((ECPublicKeyParameters) keys.Public).Q.GetEncoded(false);
            var privateKey = ((ECPrivateKeyParameters) keys.Private).D.ToByteArrayUnsigned();

            var publicKeyLength = publicKey.Length;
            var privateKeyLength = privateKey.Length;

            Assert.Equal(65, publicKeyLength);
            Assert.Equal(32, privateKeyLength);

            ;
        }

        [Fact]
        public void TestGenerateKeysNoCache()
        {
            var keys1 = ECKeyHelper.GenerateKeys();
            var keys2 = ECKeyHelper.GenerateKeys();

            var publicKey1 = ((ECPublicKeyParameters) keys1.Public).Q.GetEncoded(false);
            var privateKey1 = ((ECPrivateKeyParameters) keys1.Private).D.ToByteArrayUnsigned();

            var publicKey2 = ((ECPublicKeyParameters) keys2.Public).Q.GetEncoded(false);
            var privateKey2 = ((ECPrivateKeyParameters) keys2.Private).D.ToByteArrayUnsigned();

            Assert.False(publicKey1.SequenceEqual(publicKey2));
            Assert.False(privateKey1.SequenceEqual(privateKey2));
        }

        [Fact]
        public void TestGetPrivateKey()
        {
            var privateKey = UrlBase64.Decode(TEST_PRIVATE_KEY);
            var privateKeyParams = ECKeyHelper.GetPrivateKey(privateKey);

            var importedPrivateKey = UrlBase64.Encode(privateKeyParams.D.ToByteArrayUnsigned());

            Assert.Equal(TEST_PRIVATE_KEY, importedPrivateKey);
        }

        [Fact]
        public void TestGetPublicKey()
        {
            var publicKey = UrlBase64.Decode(TEST_PUBLIC_KEY);
            var publicKeyParams = ECKeyHelper.GetPublicKey(publicKey);

            var importedPublicKey = UrlBase64.Encode(publicKeyParams.Q.GetEncoded(false));

            Assert.Equal(TEST_PUBLIC_KEY, importedPublicKey);
        }
    }
}