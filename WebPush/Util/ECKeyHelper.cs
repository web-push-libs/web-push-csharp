using System;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace WebPush.Util;

internal static class ECKeyHelper
{
    public static ECDsa GetKeyPair(byte[] privateKey, byte[] publicKey)
    {
        return ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = privateKey,
            Q = new ECPoint
            {
                X = [.. publicKey.Skip(1).Take(32)],
                Y = [.. publicKey.Skip(33)],
            }
        });
    }

    public static byte[] GetPublicKey(this ECDsa keypair)
    {
        var ep = keypair.ExportParameters(includePrivateParameters: true);
        if (ep.Q.X is null || ep.Q.Y is null) throw new InvalidOperationException();
        return [4, .. ep.Q.X, .. ep.Q.Y];
    }


    public static byte[] GetPrivateKey(this ECDsa keypair)
    {
        var ep = keypair.ExportParameters(includePrivateParameters: true);
        if (ep.D is null) throw new InvalidOperationException();
        return [.. ep.D];
    }

    public static string GetEncodedPublicKey(this ECDsa keypair) => Base64UrlEncoder.Encode(keypair.GetPublicKey());
    public static string GetEncodedPrivateKey(this ECDsa keypair) => Base64UrlEncoder.Encode(keypair.GetPrivateKey());

    public static ECDsa GenerateKeys()
    {
        return ECDsa.Create(ECCurve.NamedCurves.nistP256);
    }

    public static byte[] GetECDiffieHellmanSharedKey(byte[] privateKey, byte[] publicKey)
    {
        var myKey = CreateWithPrivateKey(privateKey);
        var otherKey = CreateWithPublicKey(publicKey);
        return myKey.DeriveRawSecretAgreement(otherKey.PublicKey);
    }

    internal static ECDiffieHellman CreateWithPrivateKey(byte[] privateKey)
    {
        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = privateKey,
        };
        return ECDiffieHellman.Create(parameters);
    }

    internal static ECDiffieHellman CreateWithPublicKey(byte[] publicKey)
    {
        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = [.. publicKey.Skip(1).Take(32)],
                Y = [.. publicKey.Skip(33)],
            },
        };
        return ECDiffieHellman.Create(parameters);
    }

}
