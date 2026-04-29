using System.Linq;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WebPush.Util;

namespace WebPush.Test;

[TestClass]
public class ECKeyHelperTest
{
    private const string TestPublicKey =
        @"BCvKwB2lbVUYMFAaBUygooKheqcEU-GDrVRnu8k33yJCZkNBNqjZj0VdxQ2QIZa4kV5kpX9aAqyBKZHURm6eG1A";

    private const string TestPrivateKey = @"on6X5KmLEFIVvPP3cNX9kE0OF6PV9TJQXVbnKU2xEHI";

    [TestMethod]
    public void TestGenerateKeys()
    {
        var keypair = ECKeyHelper.GenerateKeys();
        var publicKey = keypair.GetPublicKey();
        var privateKey = keypair.GetPrivateKey();

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

        var publicKey1 = keys1.GetPublicKey();
        var privateKey1 = keys1.GetPrivateKey();

        var publicKey2 = keys2.GetPublicKey();
        var privateKey2 = keys2.GetPrivateKey();

        Assert.IsFalse(publicKey1.SequenceEqual(publicKey2));
        Assert.IsFalse(privateKey1.SequenceEqual(privateKey2));
    }

    [TestMethod]
    public void TestGetPrivateKey()
    {
        var privateKey = Base64UrlEncoder.DecodeBytes(TestPrivateKey);
        var publicKey = Base64UrlEncoder.DecodeBytes(TestPublicKey);
        var keypair = ECKeyHelper.GetKeyPair(privateKey, publicKey);

        var importedPrivateKey = keypair.GetEncodedPrivateKey();
        Assert.AreEqual(TestPrivateKey, importedPrivateKey);

        var rawPrivateKey = keypair.GetPrivateKey();
        Assert.IsTrue(privateKey.SequenceEqual(rawPrivateKey));
    }

    [TestMethod]
    public void TestGetPublicKey()
    {
        var privateKey = Base64UrlEncoder.DecodeBytes(TestPrivateKey);
        var publicKey = Base64UrlEncoder.DecodeBytes(TestPublicKey);
        var keypair = ECKeyHelper.GetKeyPair(privateKey, publicKey);

        var importedPublicKey = keypair.GetEncodedPublicKey();
        Assert.AreEqual(TestPublicKey, importedPublicKey);

        var rawPublicKey = keypair.GetPublicKey();
        Assert.IsTrue(publicKey.SequenceEqual(rawPublicKey));
    }

    [TestMethod]
    public void TestGetKeyPairNet()
    {
        var privateKey = Base64UrlEncoder.DecodeBytes(TestPrivateKey);
        var publicKey = Base64UrlEncoder.DecodeBytes(TestPublicKey);

        var keypair = ECKeyHelper.GetKeyPair(privateKey, publicKey);

        var importedPublicKey = keypair.GetEncodedPublicKey();
        Assert.AreEqual(TestPublicKey, importedPublicKey);

        var importedPrivateKey = keypair.GetEncodedPrivateKey();
        Assert.AreEqual(TestPrivateKey, importedPrivateKey);
    }
}
