using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WebPush.Model;

namespace WebPush.Test;

[TestClass]
public class VapidHelperTest
{
    private const string ValidAudience = @"http://example.com";
    private const string ValidSubject = @"http://example.com/example";
    private const string ValidSubjectMailto = @"mailto:example@example.com";

    private const string TestPublicKey =
        @"BCvKwB2lbVUYMFAaBUygooKheqcEU-GDrVRnu8k33yJCZkNBNqjZj0VdxQ2QIZa4kV5kpX9aAqyBKZHURm6eG1A";

    private const string TestPrivateKey = @"on6X5KmLEFIVvPP3cNX9kE0OF6PV9TJQXVbnKU2xEHI";

    [TestMethod]
    public void TestGenerateVapidKeys()
    {
        var keys = VapidHelper.GenerateVapidKeys();
        var publicKey = Base64UrlEncoder.DecodeBytes(keys.PublicKey);
        var privateKey = Base64UrlEncoder.DecodeBytes(keys.PrivateKey);

        Assert.HasCount(32, privateKey);
        Assert.HasCount(65, publicKey);
    }

    [TestMethod]
    public void TestGenerateVapidKeysNoCache()
    {
        var keys1 = VapidHelper.GenerateVapidKeys();
        var keys2 = VapidHelper.GenerateVapidKeys();

        Assert.AreNotEqual(keys1.PublicKey, keys2.PublicKey);
        Assert.AreNotEqual(keys1.PrivateKey, keys2.PrivateKey);
    }

    [TestMethod]
    public void TestGetVapidHeaders()
    {
        var publicKey = TestPublicKey;
        var privateKey = TestPrivateKey;
        var headers = VapidHelper.GetVapidHeaders(ValidAudience, ValidSubject, publicKey, privateKey);

        Assert.IsTrue(headers.ContainsKey(@"Authorization"));
    }

    [TestMethod]
    public void TestGetVapidHeadersAudienceNotAUrl()
    {
        var publicKey = TestPublicKey;
        var privateKey = TestPrivateKey;
        Assert.ThrowsExactly<ArgumentException>(
            delegate
            {
                VapidHelper.GetVapidHeaders("invalid audience", ValidSubjectMailto, publicKey, privateKey);
            });
    }

    [TestMethod]
    public void TestGetVapidHeadersAudienceMissing()
    {
        var publicKey = TestPublicKey;
        var privateKey = TestPrivateKey;
        Assert.ThrowsExactly<ArgumentException>(
            delegate
            {
                VapidHelper.GetVapidHeaders("", ValidSubjectMailto, publicKey, privateKey);
            });
    }


    [TestMethod]
    public void TestGetVapidHeadersInvalidPrivateKey()
    {
        var publicKey = Base64UrlEncoder.Encode(new byte[65]);
        var privateKey = Base64UrlEncoder.Encode(new byte[1]);

        Assert.ThrowsExactly<ArgumentException>(
            delegate { VapidHelper.GetVapidHeaders(ValidAudience, ValidSubject, publicKey, privateKey); });
    }

    [TestMethod]
    public void TestGetVapidHeadersInvalidPublicKey()
    {
        var publicKey = Base64UrlEncoder.Encode(new byte[1]);
        var privateKey = Base64UrlEncoder.Encode(new byte[32]);

        Assert.ThrowsExactly<ArgumentException>(
            delegate { VapidHelper.GetVapidHeaders(ValidAudience, ValidSubject, publicKey, privateKey); });
    }

    [TestMethod]
    public void TestGetVapidHeadersPublicKeyMissing()
    {
        Assert.ThrowsExactly<ArgumentException>(
            delegate { VapidHelper.GetVapidHeaders(ValidAudience, ValidSubject, "", TestPrivateKey); });
    }

    [TestMethod]
    public void TestGetVapidHeadersPublicKeyInvalidBase64()
    {
        Assert.Throws<CryptographicException>(
            delegate { VapidHelper.GetVapidHeaders(ValidAudience, ValidSubject, @"BCvKwB2lbVUYMFAaBUygooKheqcEU-GDrVRnu8k33zJCZkNBNqjZj0VdxQ2QIZa4kV5kpX9aAqyBKZHURm6eG1A", TestPrivateKey); });
    }

    [TestMethod]
    public void TestGetVapidHeadersPrivateKeyMissing()
    {
        Assert.ThrowsExactly<ArgumentException>(
            delegate { VapidHelper.GetVapidHeaders(ValidAudience, ValidSubject, TestPublicKey, ""); });
    }

    [TestMethod]
    public void TestGetVapidHeadersPrivateKeyInvalidBase64()
    {
        Assert.Throws<CryptographicException>(
            delegate { VapidHelper.GetVapidHeaders(ValidAudience, ValidSubject, TestPublicKey, @"WRONGKmLEFIVvPP3cNX9kE0OF6PV9TJQXVbnKU2xEHI"); });
    }

    [TestMethod]
    public void TestGetVapidHeadersSubjectNotAUrlOrMailTo()
    {
        var publicKey = TestPublicKey;
        var privateKey = TestPrivateKey;

        Assert.ThrowsExactly<ArgumentException>(
            delegate { VapidHelper.GetVapidHeaders(ValidAudience, @"invalid subject", publicKey, privateKey); });
    }

    [TestMethod]
    public void TestGetVapidHeadersSubjectMissing()
    {
        var publicKey = TestPublicKey;
        var privateKey = TestPrivateKey;

        Assert.ThrowsExactly<ArgumentException>(
            delegate { VapidHelper.GetVapidHeaders(ValidAudience, "   ", publicKey, privateKey); });
    }

    [TestMethod]
    public void TestGetVapidHeadersWithMailToSubject()
    {
        var publicKey = TestPublicKey;
        var privateKey = TestPrivateKey;
        var headers = VapidHelper.GetVapidHeaders(ValidAudience, ValidSubjectMailto, publicKey,
            privateKey);

        Assert.IsTrue(headers.ContainsKey(@"Authorization"));
    }

    [TestMethod]
    public void TestExpirationInPastExceptions()
    {
        var publicKey = TestPublicKey;
        var privateKey = TestPrivateKey;

        Assert.ThrowsExactly<ArgumentException>(
            delegate
            {
                VapidHelper.GetVapidHeaders(ValidAudience, ValidSubjectMailto, publicKey,
                    privateKey, DateTimeOffset.FromUnixTimeSeconds(1552715607).UtcDateTime);
            });
    }


    [TestMethod]
    public void TestVapidHeaders()
    {
        var vapidHeaders = VapidHelper.GetVapidHeaders(ValidAudience, ValidSubjectMailto, TestPublicKey, TestPrivateKey, new DateTime(2128, 08, 08, 08, 08, 08), ContentEncoding.Aes128gcm);

        vapidHeaders.TryGetValue("Authorization", out var authHeader);
        Assert.IsNotNull(vapidHeaders);

        var partsSpace = authHeader.Split(' ');
        Assert.IsGreaterThanOrEqualTo(3, partsSpace.Length);

        var authType = partsSpace[0];
        Assert.AreEqual("vapid", authType);

        var jwkPart = partsSpace[1][0..^1]; // remove delimiter ','
        Assert.StartsWith("t=", jwkPart);
        var token = jwkPart["t=".Length..];
        var tokenParts = token.Split('.');

        Assert.HasCount(3, tokenParts);

        var encodedHeader = tokenParts[0];
        var encodedPayload = tokenParts[1];
        var signature = tokenParts[2];

        var decodedHeader = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(encodedHeader));
        var decodedPayload = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(encodedPayload));

        Assert.AreEqual(@"{""alg"":""ES256"",""typ"":""JWT""}", decodedHeader);
        Assert.Contains(@"""typ"":""JWT""", decodedHeader);
        Assert.Contains(@"""alg"":""ES256""", decodedHeader);
        Assert.Contains(@$"""aud"":""{ValidAudience}""", decodedPayload);
        Assert.Contains(@$"""sub"":""{ValidSubjectMailto}""", decodedPayload);
        Assert.MatchesRegex(@"""exp"":\d+", decodedPayload);

        var decodedSignature = Base64UrlEncoder.DecodeBytes(signature);
        var decodedSignatureLength = decodedSignature.Length;

        var isSignatureLengthValid = decodedSignatureLength == 66 || decodedSignatureLength == 64;
        Assert.IsTrue(isSignatureLengthValid);

        var keyPart = partsSpace[2];
        Assert.StartsWith("k=", keyPart);
        Assert.AreEqual(TestPublicKey, keyPart["k-".Length..]);
    }
}
