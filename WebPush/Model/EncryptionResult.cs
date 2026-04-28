using Microsoft.IdentityModel.Tokens;

namespace WebPush.Model;

// @LogicSoftware
// Originally From: https://github.com/LogicSoftware/WebPushEncryption/blob/master/src/EncryptionResult.cs
public class EncryptionResult
{
    public required byte[] PublicKey { get; set; }
    public required byte[] Payload { get; set; }
    public required byte[] Salt { get; set; }

    public string Base64EncodePublicKey()
    {
        return Base64UrlEncoder.Encode(PublicKey);
    }

    public string Base64EncodeSalt()
    {
        return Base64UrlEncoder.Encode(Salt);
    }
}
