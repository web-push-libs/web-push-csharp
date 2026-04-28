using System;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using WebPush.Util;

namespace WebPush;

public static class VapidHelper
{
    /// <summary>
    ///     Generate vapid keys
    /// </summary>
    public static VapidDetails GenerateVapidKeys()
    {
        var keys = ECKeyHelper.GenerateKeys();
        return new VapidDetails("", keys.GetEncodedPublicKey(), keys.GetEncodedPrivateKey());
    }

    /// <summary>
    ///     This method takes the required VAPID parameters and returns the required
    ///     header to be added to a Web Push Protocol Request.
    /// </summary>
    /// <param name="audience">This must be the origin of the push service.</param>
    /// <param name="subject">This should be a URL or a 'mailto:' email address</param>
    /// <param name="publicKey">The VAPID public key as a base64 encoded string</param>
    /// <param name="privateKey">The VAPID private key as a base64 encoded string</param>
    /// <param name="expiration">The expiration of the VAPID JWT.</param>
    /// <returns>A dictionary of header key/value pairs.</returns>
    public static Dictionary<string, string> GetVapidHeaders(string audience, string subject, string publicKey, string privateKey, DateTime? expiration = null, ContentEncoding contentEncoding = ContentEncoding.Aes128gcm)
    {
        ValidateAudience(audience);
        ValidateSubject(subject);
        ValidatePublicKey(publicKey);
        ValidatePrivateKey(privateKey);
        var now = DateTime.UtcNow;
        if (expiration is null)
        {
            expiration = now.AddHours(12);
        }
        else
        {
            ValidateExpiration(expiration);
        }

        var key = ECKeyHelper.GetKeyPair(Base64UrlEncoder.DecodeBytes(privateKey), Base64UrlEncoder.DecodeBytes(publicKey));
        var identity = new ClaimsIdentity([new Claim(JwtRegisteredClaimNames.Sub, subject)]);
        var handler = new JsonWebTokenHandler
        {
            SetDefaultTimesOnTokenCreation = false,
        };
        string token = handler.CreateToken(new SecurityTokenDescriptor
        {
            Audience = audience,
            Expires = expiration,
            // IssuedAt = now,
            Subject = identity,
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
        });
        return contentEncoding switch
        {
            ContentEncoding.Aesgcm => new Dictionary<string, string>(StringComparer.Ordinal)
            {
                { "Authorization", $"WebPush {token}"},
                { "Crypto-Key", $"p256ecdsa={publicKey}"},
            },
            ContentEncoding.Aes128gcm => new Dictionary<string, string>(StringComparer.Ordinal)
            {
                { "Authorization", $"vapid t={token}, k={publicKey}"},
            },
            _ => throw new Exception("This content encoding is not supported"),
        };
    }

    public static void ValidateAudience(string audience)
    {
        if (string.IsNullOrWhiteSpace(audience))
        {
            throw new ArgumentException(
                @$"The audience value must be a string containing the origin of a push service: {audience}", nameof(audience));
        }

        if (!Uri.IsWellFormedUriString(audience, UriKind.Absolute))
        {
            throw new ArgumentException(@$"VAPID audience is not a url: {audience}", nameof(audience));
        }
    }

    public static void ValidateSubject(string subject)
    {
        if (string.IsNullOrWhiteSpace(subject))
        {
            throw new ArgumentException(@"The subject value must be a string containing a url or mailto: address.", nameof(subject));
        }

        if (!subject.StartsWith("mailto:", StringComparison.Ordinal))
        {
            if (!Uri.IsWellFormedUriString(subject, UriKind.Absolute))
            {
                throw new ArgumentException(@"Subject is not a valid URL or mailto address", nameof(subject));
            }
        }
    }

    public static void ValidatePublicKey(string publicKey)
    {
        if (string.IsNullOrWhiteSpace(publicKey))
        {
            throw new ArgumentException(@"Valid public key not set", nameof(publicKey));
        }

        var decodedPublicKey = Base64UrlEncoder.DecodeBytes(publicKey);

        if (decodedPublicKey.Length != 65)
        {
            throw new ArgumentException(@"Vapid public key must be 65 characters long when decoded", nameof(publicKey));
        }
    }

    public static void ValidatePrivateKey(string privateKey)
    {
        if (string.IsNullOrWhiteSpace(privateKey))
        {
            throw new ArgumentException(@"Valid private key not set", nameof(privateKey));
        }

        var decodedPrivateKey = Base64UrlEncoder.DecodeBytes(privateKey);

        if (decodedPrivateKey.Length != 32)
        {
            throw new ArgumentException(@"Vapid private key should be 32 bytes long when decoded.", nameof(privateKey));
        }
    }

    private static void ValidateExpiration(DateTime? expiration)
    {
        if (expiration is null || expiration <= DateTime.UtcNow)
        {
            throw new ArgumentException(@"Vapid expiration must be in the future", nameof(expiration));
        }
    }
}
