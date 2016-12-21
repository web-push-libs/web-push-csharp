using System.Linq;
using System.Security.Cryptography;
namespace WebPush.Util
{
    public static class CngKeyHelper
    {
        public static CngKey ImportCngKeyFromPrivateKey(byte[] publicKey, byte[] privateKey)
        {
            byte[] keyType = new byte[] { 0x45, 0x43, 0x4B, 0x32 };
            byte[] keyLength = new byte[] { 0x20, 0x00, 0x00, 0x00 };

            byte[] keyImport = keyType.Concat(keyLength).Concat(publicKey.Skip(1)).Concat(privateKey).ToArray();

            return CngKey.Import(keyImport, CngKeyBlobFormat.GenericPrivateBlob);
        }

        public static CngKey ImportCngKeyFromPublicKey(byte[] userKey)
        {
            byte[] keyType = new byte[] { 0x45, 0x43, 0x4B, 0x31 };
            byte[] keyLength = new byte[] { 0x20, 0x00, 0x00, 0x00 };

            byte[] keyImport = keyType.Concat(keyLength).Concat(userKey.Skip(1)).ToArray();

            return CngKey.Import(keyImport, CngKeyBlobFormat.EccPublicBlob);
        }

        public static byte[] ImportPublicKeyFromCngKey(byte[] cngKey)
        {
            byte[] keyImport = (new byte[] { 0x04 }).Concat(cngKey.Skip(8)).ToArray();

            return keyImport;
        }
    }
}
