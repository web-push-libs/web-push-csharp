using System.Security.Cryptography;
using System.Linq;

namespace WebPush.Util
{
    internal static class ECKeyHelper
    {
        public static byte[] GetECPublicKey(this CngKey key)
        {
            var cngKey = key.Export(CngKeyBlobFormat.EccPublicBlob);
            return new byte[] { 0x04 }.Concat(cngKey.Skip(8)).ToArray();
        }

        public static byte[] GetECPrivateKey(this CngKey key)
        {
            var cngKey = key.Export(CngKeyBlobFormat.EccPrivateBlob);
            return cngKey.Skip(8 + 32 + 32).Take(32).ToArray();
        }

        public static CngKey GetPublicKey(byte[] key)
        {
            var keyType = new byte[] { 0x45, 0x43, 0x4B, 0x31 };
            var keyLength = new byte[] { 0x20, 0x00, 0x00, 0x00 };

            var keyImport = keyType.Concat(keyLength).Concat(key.Skip(1)).ToArray();

            return CngKey.Import(keyImport, CngKeyBlobFormat.EccPublicBlob);
        }
#if NET48
	public static AsymmetricAlgorithm GetPrivateKey(byte[] privateKey)
	{
		return ECDsaCng.Create(new ECParameters
		{
			Curve = ECCurve.NamedCurves.nistP256,
			D = privateKey,
			Q = new ECPoint(){ X = new byte[32],Y = new byte[32]}
		});
	}
	public static AsymmetricKeyPair GenerateKeys()
		{

			using (var cng = new ECDiffieHellmanCng(ECCurve.NamedCurves.nistP256))
			{
				cng.GenerateKey(ECCurve.NamedCurves.nistP256);
				var parameters = cng.ExportParameters(true);
				var pr = parameters.D.ToArray();
				var pub = new byte[] { 0x04 }.Concat(parameters.Q.X).Concat(parameters.Q.Y).ToArray();
				return new AsymmetricKeyPair() { PublicKey = pub,PrivateKey = pr };
			}
		}
#else
        private static CngKey ImportPrivCngKey(byte[] pubKey, byte[] privKey)
        {
            // to import keys to CngKey in ECCPublicKeyBlob and ECCPrivateKeyBlob format, keys should be form in specific formats as noted here :
            // https://stackoverflow.com/a/24255090
            // magic prefixes : https://referencesource.microsoft.com/#system.core/System/Security/Cryptography/BCryptNative.cs,fde0749a0a5f70d8,references
            var keyType = new byte[] { 0x45, 0x43, 0x53, 0x32 };
            var keyLength = new byte[] { 0x20, 0x00, 0x00, 0x00 };

            var key = pubKey.Skip(1);

            var keyImport = keyType.Concat(keyLength).Concat(key).Concat(privKey).ToArray();

            var cngKey = CngKey.Import(keyImport, CngKeyBlobFormat.EccPrivateBlob);
            return cngKey;
        }
        public static ECDsaCng GetPrivateKey(byte[] privateKey)
        {
            var fakePubKey = new byte[64];
            var publicKey = (new byte[] { 0x04 }).Concat(fakePubKey).ToArray();

            var cngKey = ImportPrivCngKey(publicKey, privateKey);
            var ecDsaCng = new ECDsaCng(cngKey);
            ecDsaCng.HashAlgorithm = CngAlgorithm.ECDsaP256;
            return ecDsaCng;
        }

        public static AsymmetricKeyPair GenerateKeys()
        {
            CngProvider cp = CngProvider.MicrosoftSoftwareKeyStorageProvider;
            string keyName = "tempvapidkey";
            if (CngKey.Exists(keyName, cp))
            {
                using (CngKey cngKey = CngKey.Open(keyName, cp))
                    cngKey.Delete();
            }
            CngKeyCreationParameters kcp = new CngKeyCreationParameters
            {
                Provider = cp,
                ExportPolicy = CngExportPolicies.AllowPlaintextExport
            };
            try
            {
                using (CngKey myKey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256, keyName, kcp))
                {
                    return new AsymmetricKeyPair()
                    {
                        PublicKey = myKey.GetECPublicKey(),
                        PrivateKey = myKey.GetECPrivateKey()
                    };
                }
            }
            finally
            {
                if (CngKey.Exists(keyName, cp))
                {
                    using (CngKey cngKey = CngKey.Open(keyName, cp))
                        cngKey.Delete();
                }
            }
        }
#endif
    }
}