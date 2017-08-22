using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace WebPush.Test
{
    public class WebPushClientTest
    {
        private const string TEST_PUBLIC_KEY =
            @"BCvKwB2lbVUYMFAaBUygooKheqcEU-GDrVRnu8k33yJCZkNBNqjZj0VdxQ2QIZa4kV5kpX9aAqyBKZHURm6eG1A";

        private const string TEST_PRIVATE_KEY = @"on6X5KmLEFIVvPP3cNX9kE0OF6PV9TJQXVbnKU2xEHI";

        private const string TEST_GCM_ENDPOINT = @"https://android.googleapis.com/gcm/send/";

        private const string TEST_FCM_ENDPOINT =
            @"https://fcm.googleapis.com/fcm/send/efz_TLX_rLU:APA91bE6U0iybLYvv0F3mf6";

        [Fact]
        public void TestGCMAPIKeyInOptions()
        {
            var client = new WebPushClient();

            var gcmAPIKey = @"teststring";
            var subscription = new PushSubscription(TEST_GCM_ENDPOINT, TEST_PUBLIC_KEY, TEST_PRIVATE_KEY);

            var options = new Dictionary<string, object>();
            options["gcmAPIKey"] = gcmAPIKey;
            var message = client.GenerateRequestDetails(subscription, "test payload", options);
            var authorizationHeader = message.Headers.GetValues("Authorization").First();

            Assert.Equal("key=" + gcmAPIKey, authorizationHeader);

            // Test previous incorrect casing of gcmAPIKey
            var options2 = new Dictionary<string, object>();
            options2["gcmApiKey"] = gcmAPIKey;
            Assert.Throws<ArgumentException>(delegate
            {
                client.GenerateRequestDetails(subscription, "test payload", options2);
            });
        }

        [Fact]
        public void TestSetGCMAPIKey()
        {
            var client = new WebPushClient();

            var gcmAPIKey = @"teststring";
            client.SetGCMAPIKey(gcmAPIKey);
            var subscription = new PushSubscription(TEST_GCM_ENDPOINT, TEST_PUBLIC_KEY, TEST_PRIVATE_KEY);
            var message = client.GenerateRequestDetails(subscription, "test payload");
            var authorizationHeader = message.Headers.GetValues("Authorization").First();

            Assert.Equal("key=" + gcmAPIKey, authorizationHeader);
        }

        [Fact]
        public void TestSetGCMAPIKeyEmptyString()
        {
            var client = new WebPushClient();

            Assert.Throws(typeof(ArgumentException), delegate { client.SetGCMAPIKey(""); });
        }

        [Fact]
        public void TestSetGCMAPiKeyNonGCMPushService()
        {
            // Ensure that the API key doesn't get added on a service that doesn't accept it.
            var client = new WebPushClient();

            var gcmAPIKey = @"teststring";
            client.SetGCMAPIKey(gcmAPIKey);
            var subscription = new PushSubscription(TEST_FCM_ENDPOINT, TEST_PUBLIC_KEY, TEST_PRIVATE_KEY);
            var message = client.GenerateRequestDetails(subscription, "test payload");

            IEnumerable<string> values;
            Assert.False(message.Headers.TryGetValues("Authorization", out values));
        }

        [Fact]
        public void TestSetGCMAPIKeyNull()
        {
            var client = new WebPushClient();

            client.SetGCMAPIKey(@"somestring");
            client.SetGCMAPIKey(null);

            var subscription = new PushSubscription(TEST_GCM_ENDPOINT, TEST_PUBLIC_KEY, TEST_PRIVATE_KEY);
            var message = client.GenerateRequestDetails(subscription, "test payload");

            IEnumerable<string> values;
            Assert.False(message.Headers.TryGetValues("Authorization", out values));
        }

        [Fact]
        public void TestSetVapidDetails()
        {
            var client = new WebPushClient();

            client.SetVapidDetails("mailto:example@example.com", TEST_PUBLIC_KEY, TEST_PRIVATE_KEY);

            var subscription = new PushSubscription(TEST_FCM_ENDPOINT, TEST_PUBLIC_KEY, TEST_PRIVATE_KEY);
            var message = client.GenerateRequestDetails(subscription, "test payload");
            var authorizationHeader = message.Headers.GetValues("Authorization").First();
            var cryptoHeader = message.Headers.GetValues("Crypto-Key").First();

            Assert.True(authorizationHeader.StartsWith("WebPush "));
            Assert.True(cryptoHeader.Contains("p256ecdsa"));
        }
    }
}