using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace WebPush.Test
{
    [TestClass]
    public class WebPushClientTest
    {
        private const string TestPublicKey =
            @"BCvKwB2lbVUYMFAaBUygooKheqcEU-GDrVRnu8k33yJCZkNBNqjZj0VdxQ2QIZa4kV5kpX9aAqyBKZHURm6eG1A";

        private const string TestPrivateKey = @"on6X5KmLEFIVvPP3cNX9kE0OF6PV9TJQXVbnKU2xEHI";

        private const string TestGcmEndpoint = @"https://android.googleapis.com/gcm/send/";

        private const string TestFcmEndpoint =
            @"https://fcm.googleapis.com/fcm/send/efz_TLX_rLU:APA91bE6U0iybLYvv0F3mf6";

        [TestMethod]
        public void TestGcmApiKeyInOptions()
        {
            var client = new WebPushClient();

            var gcmAPIKey = @"teststring";
            var subscription = new PushSubscription(TestGcmEndpoint, TestPublicKey, TestPrivateKey);

            var options = new Dictionary<string, object>();
            options[@"gcmAPIKey"] = gcmAPIKey;
            var message = client.GenerateRequestDetails(subscription, @"test payload", options);
            var authorizationHeader = message.Headers.GetValues(@"Authorization").First();

            Assert.AreEqual("key=" + gcmAPIKey, authorizationHeader);

            // Test previous incorrect casing of gcmAPIKey
            var options2 = new Dictionary<string, object>();
            options2[@"gcmApiKey"] = gcmAPIKey;
            Assert.ThrowsException<ArgumentException>(delegate
            {
                client.GenerateRequestDetails(subscription, "test payload", options2);
            });
        }

        [TestMethod]
        public void TestSetGcmApiKey()
        {
            var client = new WebPushClient();

            var gcmAPIKey = @"teststring";
            client.SetGcmApiKey(gcmAPIKey);
            var subscription = new PushSubscription(TestGcmEndpoint, TestPublicKey, TestPrivateKey);
            var message = client.GenerateRequestDetails(subscription, @"test payload");
            var authorizationHeader = message.Headers.GetValues(@"Authorization").First();

            Assert.AreEqual(@"key=" + gcmAPIKey, authorizationHeader);
        }

        [TestMethod]
        public void TestSetGCMAPIKeyEmptyString()
        {
            WebPushClient client = new WebPushClient();

            Assert.ThrowsException<ArgumentException>(delegate
            {
                client.SetGcmApiKey("");
            });
        }

        [TestMethod]
        public void TestSetGcmApiKeyNonGcmPushService()
        {
            // Ensure that the API key doesn't get added on a service that doesn't accept it.
            var client = new WebPushClient();

            var gcmAPIKey = @"teststring";
            client.SetGcmApiKey(gcmAPIKey);
            var subscription = new PushSubscription(TestFcmEndpoint, TestPublicKey, TestPrivateKey);
            var message = client.GenerateRequestDetails(subscription, @"test payload");

            IEnumerable<string> values;
            Assert.IsFalse(message.Headers.TryGetValues(@"Authorization", out values));
        }

        [TestMethod]
        public void TestSetGcmApiKeyNull()
        {
            var client = new WebPushClient();

            client.SetGcmApiKey(@"somestring");
            client.SetGcmApiKey(null);

            var subscription = new PushSubscription(TestGcmEndpoint, TestPublicKey, TestPrivateKey);
            var message = client.GenerateRequestDetails(subscription, @"test payload");

            IEnumerable<string> values;
            Assert.IsFalse(message.Headers.TryGetValues("Authorization", out values));
        }

        [TestMethod]
        public void TestSetVapidDetails()
        {
            var client = new WebPushClient();

            client.SetVapidDetails("mailto:example@example.com", TestPublicKey, TestPrivateKey);

            var subscription = new PushSubscription(TestFcmEndpoint, TestPublicKey, TestPrivateKey);
            var message = client.GenerateRequestDetails(subscription, @"test payload");
            var authorizationHeader = message.Headers.GetValues(@"Authorization").First();
            var cryptoHeader = message.Headers.GetValues(@"Crypto-Key").First();

            Assert.IsTrue(authorizationHeader.StartsWith(@"WebPush "));
            Assert.IsTrue(cryptoHeader.Contains(@"p256ecdsa"));
        }
    }
}