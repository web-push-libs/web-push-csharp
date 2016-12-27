using System;
using System.Linq;
using NUnit.Framework;
using WebPush;
using WebPush.Util;

namespace WebPush.Test
{
    [TestFixture]
    public class VapidHelperTest
    {
        [Test]
        public void TestGenerateVapidKeys()
        {
            VapidDetails keys = VapidHelper.GenerateVapidKeys();
            byte[] publicKey = UrlBase64.Decode(keys.PublicKey);
            byte[] privateKey = UrlBase64.Decode(keys.PrivateKey);

            Assert.AreEqual(32, privateKey.Length);
            Assert.AreEqual(65, publicKey.Length);
        }

        [Test]
        public void TestGenerateVapidKeysNoCache()
        {
            VapidDetails keys1 = VapidHelper.GenerateVapidKeys();
            VapidDetails keys2 = VapidHelper.GenerateVapidKeys();

            Assert.AreNotEqual(keys1.PublicKey, keys2.PublicKey);
            Assert.AreNotEqual(keys1.PrivateKey, keys2.PrivateKey);
        }
    }
}
