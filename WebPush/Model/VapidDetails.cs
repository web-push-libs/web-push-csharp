using System;
using System.Diagnostics.CodeAnalysis;

namespace WebPush;

public class VapidDetails
{
    /// <param name="subject">This should be a URL or a 'mailto:' email address</param>
    /// <param name="publicKey">The VAPID public key as a base64 encoded string</param>
    /// <param name="privateKey">The VAPID private key as a base64 encoded string</param>
    [SetsRequiredMembers]
    public VapidDetails(string subject, string publicKey, string privateKey)
    {
        Subject = subject;
        PublicKey = publicKey;
        PrivateKey = privateKey;
    }

    public required string Subject { get; set; }
    public required string PublicKey { get; set; }
    public required string PrivateKey { get; set; }
    public DateTime? Expiration { get; set; } = null;
}
