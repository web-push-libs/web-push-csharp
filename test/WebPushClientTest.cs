using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using WebPush.Util;

namespace WebPush.Test
{
    [TestFixture]
    public class WebPushClientTest
    {
        private const string TEST_PUBLIC_KEY =
         @"BCvKwB2lbVUYMFAaBUygooKheqcEU-GDrVRnu8k33yJCZkNBNqjZj0VdxQ2QIZa4kV5kpX9aAqyBKZHURm6eG1A";

        private const string TEST_PRIVATE_KEY = @"on6X5KmLEFIVvPP3cNX9kE0OF6PV9TJQXVbnKU2xEHI";


        [Test]
        public void TestSetGCMAPIKey()
        {
            WebPushClient client = new WebPushClient();

            string gcmApiKey = @"teststring";
            client.SetGCMAPIKey(gcmApiKey);
            PushSubscription subscription = new PushSubscription(@"https://android.googleapis.com/gcm/send/", TEST_PUBLIC_KEY, TEST_PRIVATE_KEY);
            HttpRequestMessage message = client.GenerateRequestDetails(subscription, "test payload");
            string authorizationHeader = message.Headers.GetValues("Authorization").First();

            Assert.AreEqual("key=" + gcmApiKey, authorizationHeader);
        }

        [Test]
        public void TestSetGCMAPIKeyEmptyString()
        {
            WebPushClient client = new WebPushClient();

            Assert.Throws(typeof(ArgumentException), delegate
            {
                client.SetGCMAPIKey("");
            });
        }

        [Test]
        public void TestSetGCMAPIKeyNull()
        {
            WebPushClient client = new WebPushClient();

            client.SetGCMAPIKey(@"somestring");
            client.SetGCMAPIKey(null);

            PushSubscription subscription = new PushSubscription(@"https://android.googleapis.com/gcm/send/", TEST_PUBLIC_KEY, TEST_PRIVATE_KEY);
            HttpRequestMessage message = client.GenerateRequestDetails(subscription, "test payload");

            IEnumerable<string> values;
            Assert.False(message.Headers.TryGetValues("Authorization", out values));
        }

        [Test]
        public void TestSetGCMAPiKeyNonGCMPushService()
        {
            // Ensure that the API key doesn't get added on a service that doesn't accept it.
            WebPushClient client = new WebPushClient();

            string gcmApiKey = @"teststring";
            client.SetGCMAPIKey(gcmApiKey);
            PushSubscription subscription = new PushSubscription(@"https://fcm.googleapis.com/fcm/send/efz_TLX_rLU:APA91bE6U0iybLYvv0F3mf6", TEST_PUBLIC_KEY, TEST_PRIVATE_KEY);
            HttpRequestMessage message = client.GenerateRequestDetails(subscription, "test payload");

            IEnumerable<string> values;
            Assert.False(message.Headers.TryGetValues("Authorization", out values));
        }
    }
}
