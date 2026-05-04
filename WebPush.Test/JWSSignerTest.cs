using System;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WebPush.Util;

namespace WebPush.Test;

[TestClass]
public class JWSSignerTest
{
    private const string TestPublicKey =
        @"BCvKwB2lbVUYMFAaBUygooKheqcEU-GDrVRnu8k33yJCZkNBNqjZj0VdxQ2QIZa4kV5kpX9aAqyBKZHURm6eG1A";

    private const string TestPrivateKey = @"on6X5KmLEFIVvPP3cNX9kE0OF6PV9TJQXVbnKU2xEHI";


    [TestMethod]
    public void TestGenerateSignature()
    {
        var key = ECKeyHelper.GetKeyPair(Base64UrlEncoder.DecodeBytes(TestPrivateKey), Base64UrlEncoder.DecodeBytes(TestPublicKey));
        var handler = new JsonWebTokenHandler
        {
            SetDefaultTimesOnTokenCreation = false
        };
        var now = DateTime.UtcNow;
        var epoch = new DateTime(1970, 1, 1, 0, 0, 1, DateTimeKind.Utc);
        var subject = new ClaimsIdentity([new Claim(JwtRegisteredClaimNames.Sub, "subject")]);

        string token = handler.CreateToken(new SecurityTokenDescriptor
        {
            Audience = "aud",
            // Expires = now.AddMinutes(1),
            Expires = epoch,
            // IssuedAt = now,
            Subject = subject,
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
        });
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
        Assert.AreEqual(@"{""aud"":""aud"",""exp"":1,""sub"":""subject""}", decodedPayload);

        var decodedSignature = Base64UrlEncoder.DecodeBytes(signature);
        var decodedSignatureLength = decodedSignature.Length;

        var isSignatureLengthValid = decodedSignatureLength == 66 || decodedSignatureLength == 64;
        Assert.IsTrue(isSignatureLengthValid);
    }
}
