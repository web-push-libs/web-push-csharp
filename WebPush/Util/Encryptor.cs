using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using WebPush.Model;

[assembly: InternalsVisibleTo("WebPush.Test")]

namespace WebPush.Util;

internal static class Encryptor
{
    public static EncryptionResult Encrypt(string subscriptionPublicKeyBase64, string authSecretBase64, string payload)
    {
        var subscriptionPublicKey = Base64UrlEncoder.DecodeBytes(subscriptionPublicKeyBase64);
        var authenticationSecret = Base64UrlEncoder.DecodeBytes(authSecretBase64);

        // see https://datatracker.ietf.org/doc/html/rfc8291

        using var ephemeralEcdh = ECKeyHelper.GenerateKeys();
        var uncompressedEphemeralPublicKey = ephemeralEcdh.GetPublicKey();
        var sharedSecret = ECKeyHelper.GetECDiffieHellmanSharedKey(ephemeralEcdh.GetPrivateKey(), subscriptionPublicKey);

        Span<byte> salt = stackalloc byte[16];
        RandomNumberGenerator.Fill(salt);

        // Step 0 PRK_key
        Span<byte> prkkey = stackalloc byte[32]; // SHA256 output is 32 bytes
        HKDF.Extract(HashAlgorithmName.SHA256, sharedSecret, authenticationSecret, prkkey);

        // Step 1 IKM
        byte[] keyInfo = [.. Encoding.UTF8.GetBytes("WebPush: info"), 0x00, .. subscriptionPublicKey, .. uncompressedEphemeralPublicKey];
        Span<byte> ikm = stackalloc byte[32];
        HKDF.Expand(HashAlgorithmName.SHA256, prkkey, ikm, keyInfo);

        // Step 2 PRK
        Span<byte> prk = stackalloc byte[32];
        HKDF.Extract(HashAlgorithmName.SHA256, ikm, salt, prk);

        // Step 3 CEK
        byte[] cekInfo = [.. Encoding.UTF8.GetBytes("Content-Encoding: aes128gcm"), 0x00];
        Span<byte> cek = stackalloc byte[16];
        HKDF.Expand(HashAlgorithmName.SHA256, prk, cek, cekInfo);

        // Step 4 NONCE
        byte[] nonceInfo = [.. Encoding.UTF8.GetBytes("Content-Encoding: nonce"), 0x00];
        Span<byte> nonce = stackalloc byte[12];
        HKDF.Expand(HashAlgorithmName.SHA256, prk, nonce, nonceInfo);

        // Step 5 Header
        var maxContentLength = BitConverter.GetBytes(Convert.ToInt32(4096));
        if (BitConverter.IsLittleEndian) { Array.Reverse(maxContentLength); }
        var asPublicLength = Convert.ToByte(uncompressedEphemeralPublicKey.Length);
        byte[] header = [.. salt, .. maxContentLength, asPublicLength, .. uncompressedEphemeralPublicKey];

        // Step 6 Payload padding
        byte[] paddedPayload = [.. Encoding.UTF8.GetBytes(payload), 0x02];

        // Step 7 Content Encryption
        var cipherText = EncryptMessage(paddedPayload, [.. cek], [.. nonce]);
        byte[] encryptedContent = [.. header, .. cipherText];

        return new EncryptionResult
        {
            Salt = [.. salt],
            Payload = encryptedContent,
            PublicKey = uncompressedEphemeralPublicKey
        };
    }

    /// <summary>
    /// Encrypts a byte array using AES with a given key and a new random IV.
    ///
    /// The Web Push protocol specifies a 16-byte authentication tag.
    /// </summary>
    public static byte[] EncryptMessage(byte[] payload, byte[] key, byte[] iv)
    {
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];
        var encryptedBytes = new byte[payload.Length];

        using (var aesGcm = new AesGcm(key, AesGcm.TagByteSizes.MaxSize))
        {
            aesGcm.Encrypt(iv, payload, encryptedBytes, tag);
        }

        return [.. encryptedBytes, .. tag];
    }

    /// <summary>
    /// Decrypts a byte array using AES with a given key and IV.
    ///
    /// ciphertext must contain the tag as the end (last 16 bytes).
    /// </summary>
    public static string DecryptMessage(byte[] payload, byte[] key, byte[] nonce)
    {
        ReadOnlySpan<byte> readOnlySpan = payload;
        var tag = readOnlySpan.Slice(payload.Length - AesGcm.TagByteSizes.MaxSize, length: AesGcm.TagByteSizes.MaxSize);
        var ciphertext = readOnlySpan.Slice(0, payload.Length - AesGcm.TagByteSizes.MaxSize);
        using var aes = new AesGcm(key, tag.Length);
        var plaintextBytes = new byte[ciphertext.Length];
        aes.Decrypt(nonce, ciphertext, tag, plaintextBytes);
        return Encoding.UTF8.GetString(plaintextBytes);
    }
}
