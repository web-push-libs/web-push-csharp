using System.Collections.Generic;
using System.Text;
using WebPush.Util;
using Xunit;

namespace WebPush.Test
{
    public class JWSSignerTest
    {
        [Fact]
        public void TestGenerateSignature()
        {
            var privateKey = ECKeyHelper.GetPrivateKey(new byte[32]);

            var header = new Dictionary<string, object>();
            header.Add("typ", "JWT");
            header.Add("alg", "ES256");

            var jwtPayload = new Dictionary<string, object>();
            jwtPayload.Add("aud", "aud");
            jwtPayload.Add("exp", 1);
            jwtPayload.Add("sub", "subject");

            var signer = new JWSSigner(privateKey);
            var token = signer.GenerateSignature(header, jwtPayload);

            var tokenParts = token.Split('.');

            Assert.Equal(3, tokenParts.Length);

            var encodedHeader = tokenParts[0];
            var encodedPayload = tokenParts[1];
            var signature = tokenParts[2];

            var decodedHeader = Encoding.UTF8.GetString(UrlBase64.Decode(encodedHeader));
            var decodedPayload = Encoding.UTF8.GetString(UrlBase64.Decode(encodedPayload));

            Assert.Equal(@"{""typ"":""JWT"",""alg"":""ES256""}", decodedHeader);
            Assert.Equal(@"{""aud"":""aud"",""exp"":1,""sub"":""subject""}", decodedPayload);

            var decodedSignature = UrlBase64.Decode(signature);
            var decodedSignatureLength = decodedSignature.Length;

            var isSignatureLengthValid = decodedSignatureLength == 66 || decodedSignatureLength == 64;
            Assert.Equal(true, isSignatureLengthValid);
        }
    }
}