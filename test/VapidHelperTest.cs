using System;
using System.Collections.Generic;
using System.Linq;
using NUnit.Framework;
using WebPush.Util;

namespace WebPush.Test
{
    [TestFixture]
    public class VapidHelperTest
    {
        private const string VALID_AUDIENCE = "http://example.com";
        private const string VALID_SUBJECT = "http://example.com/example";
        private const string VALID_SUBJECT_MAILTO = "mailto:example@example.com";
        
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

        [Test]
        public void TestGetVapidHeaders()
        {
            string publicKey = UrlBase64.Encode(new byte[65]);
            string privatekey = UrlBase64.Encode(new byte[32]);
            Dictionary<string, string> headers = VapidHelper.GetVapidHeaders(VALID_AUDIENCE, VALID_SUBJECT, publicKey, privatekey);
            
            Assert.IsTrue(headers.ContainsKey("Authorization"));
            Assert.IsTrue(headers.ContainsKey("Crypto-Key"));
        }

        [Test]
        public void TestGetVapidHeadersWithMailToSubject()
        {
            string publicKey = UrlBase64.Encode(new byte[65]);
            string privatekey = UrlBase64.Encode(new byte[32]);
            Dictionary<string, string> headers = VapidHelper.GetVapidHeaders(VALID_AUDIENCE, VALID_SUBJECT_MAILTO, publicKey,
                privatekey);

            Assert.IsTrue(headers.ContainsKey("Authorization"));
            Assert.IsTrue(headers.ContainsKey("Crypto-Key"));
        }

        [Test]
        public void TestGetVapidHeadersAudienceNotAUrl()
        {
            string publicKey = UrlBase64.Encode(new byte[65]);
            string privatekey = UrlBase64.Encode(new byte[32]);

            Assert.Throws(typeof(ArgumentException),
                delegate
                {
                    VapidHelper.GetVapidHeaders("invalid audience", VALID_SUBJECT, publicKey, privatekey);
                });
        }

        [Test]
        public void TestGetVapidHeadersSubjectNotAUrlOrMailTo()
        {
            string publicKey = UrlBase64.Encode(new byte[65]);
            string privatekey = UrlBase64.Encode(new byte[32]);

            Assert.Throws(typeof(ArgumentException),
                delegate
                {
                    VapidHelper.GetVapidHeaders(VALID_AUDIENCE, "invalid subject", publicKey, privatekey);
                });
        }

        [Test]
        public void TestGetVapidHeadersInvalidPublicKey()
        {
            string publicKey = UrlBase64.Encode(new byte[1]);
            string privatekey = UrlBase64.Encode(new byte[32]);

            Assert.Throws(typeof(ArgumentException),
                delegate
                {
                    VapidHelper.GetVapidHeaders(VALID_AUDIENCE, VALID_SUBJECT, publicKey, privatekey);
                });
        }

        [Test]
        public void TestGetVapidHeadersInvalidPrivateKey()
        {
            string publicKey = UrlBase64.Encode(new byte[65]);
            string privatekey = UrlBase64.Encode(new byte[1]);

            Assert.Throws(typeof(ArgumentException),
                delegate
                {
                    VapidHelper.GetVapidHeaders(VALID_AUDIENCE, VALID_SUBJECT, publicKey, privatekey);
                });
        }
    }
}
