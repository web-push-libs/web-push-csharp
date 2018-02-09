using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Crypto.Parameters;
using WebPush.Util;

namespace WebPush.Test
{
    [TestClass]
    public class ECKeyHelperTest
    {
        private const string TestPublicKey =
            @"BCvKwB2lbVUYMFAaBUygooKheqcEU-GDrVRnu8k33yJCZkNBNqjZj0VdxQ2QIZa4kV5kpX9aAqyBKZHURm6eG1A";

        private const string TestPrivateKey = @"on6X5KmLEFIVvPP3cNX9kE0OF6PV9TJQXVbnKU2xEHI";

        [TestMethod]
        public void TestGenerateKeys()
        {
            var keys = ECKeyHelper.GenerateKeys();

            var publicKey = ((ECPublicKeyParameters) keys.Public).Q.GetEncoded(false);
            var privateKey = ((ECPrivateKeyParameters) keys.Private).D.ToByteArrayUnsigned();

            var publicKeyLength = publicKey.Length;
            var privateKeyLength = privateKey.Length;

            Assert.AreEqual(65, publicKeyLength);
            Assert.AreEqual(32, privateKeyLength);
        }

        [TestMethod]
        public void TestGenerateKeysNoCache()
        {
            var keys1 = ECKeyHelper.GenerateKeys();
            var keys2 = ECKeyHelper.GenerateKeys();

            var publicKey1 = ((ECPublicKeyParameters) keys1.Public).Q.GetEncoded(false);
            var privateKey1 = ((ECPrivateKeyParameters) keys1.Private).D.ToByteArrayUnsigned();

            var publicKey2 = ((ECPublicKeyParameters) keys2.Public).Q.GetEncoded(false);
            var privateKey2 = ((ECPrivateKeyParameters) keys2.Private).D.ToByteArrayUnsigned();

            Assert.IsFalse(publicKey1.SequenceEqual(publicKey2));
            Assert.IsFalse(privateKey1.SequenceEqual(privateKey2));
        }

        [TestMethod]
        public void TestGetPrivateKey()
        {
            var privateKey = UrlBase64.Decode(TestPrivateKey);
            var privateKeyParams = ECKeyHelper.GetPrivateKey(privateKey);

            var importedPrivateKey = UrlBase64.Encode(privateKeyParams.D.ToByteArrayUnsigned());

            Assert.AreEqual(TestPrivateKey, importedPrivateKey);
        }

        [TestMethod]
        public void TestGetPublicKey()
        {
            var publicKey = UrlBase64.Decode(TestPublicKey);
            var publicKeyParams = ECKeyHelper.GetPublicKey(publicKey);

            var importedPublicKey = UrlBase64.Encode(publicKeyParams.Q.GetEncoded(false));

            Assert.AreEqual(TestPublicKey, importedPublicKey);
        }
    }
}