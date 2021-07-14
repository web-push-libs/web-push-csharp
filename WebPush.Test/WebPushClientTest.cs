using Microsoft.VisualStudio.TestTools.UnitTesting;
using RichardSzalay.MockHttp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using WebPush.Model;

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

        private const string TestFirefoxEndpoint =
            @"https://updates.push.services.mozilla.com/wpush/v2/gBABAABgOe_sGrdrsT35ljtA4O9xCX";

        public const string TestSubject = "mailto:example@example.com";

        private MockHttpMessageHandler httpMessageHandlerMock;
        private WebPushClient client;

        [TestInitialize]
        public void InitializeTest()
        {
            httpMessageHandlerMock = new MockHttpMessageHandler();
            client = new WebPushClient(httpMessageHandlerMock.ToHttpClient());
        }

        [TestMethod]
        public void TestGcmApiKeyInOptions()
        {
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
            Assert.ThrowsException<ArgumentException>(delegate
            { client.SetGcmApiKey(""); });
        }

        [TestMethod]
        public void TestSetGcmApiKeyNonGcmPushService()
        {
            // Ensure that the API key doesn't get added on a service that doesn't accept it.
            var gcmAPIKey = @"teststring";
            client.SetGcmApiKey(gcmAPIKey);
            var subscription = new PushSubscription(TestFirefoxEndpoint, TestPublicKey, TestPrivateKey);
            var message = client.GenerateRequestDetails(subscription, @"test payload");

            Assert.IsFalse(message.Headers.TryGetValues(@"Authorization", out var values));
        }

        [TestMethod]
        public void TestSetGcmApiKeyNull()
        {
            client.SetGcmApiKey(@"somestring");
            client.SetGcmApiKey(null);

            var subscription = new PushSubscription(TestGcmEndpoint, TestPublicKey, TestPrivateKey);
            var message = client.GenerateRequestDetails(subscription, @"test payload");

            Assert.IsFalse(message.Headers.TryGetValues("Authorization", out var values));
        }

        [TestMethod]
        public void TestSetVapidDetails()
        {
            client.SetVapidDetails(TestSubject, TestPublicKey, TestPrivateKey);

            var subscription = new PushSubscription(TestFirefoxEndpoint, TestPublicKey, TestPrivateKey);
            var message = client.GenerateRequestDetails(subscription, @"test payload");
            var authorizationHeader = message.Headers.GetValues(@"Authorization").First();
            var cryptoHeader = message.Headers.GetValues(@"Crypto-Key").First();

            Assert.IsTrue(authorizationHeader.StartsWith(@"WebPush "));
            Assert.IsTrue(cryptoHeader.Contains(@"p256ecdsa"));
        }

        [TestMethod]
        public void TestFcmAddsAuthorizationHeader()
        {
            client.SetGcmApiKey(@"somestring");
            var subscription = new PushSubscription(TestFcmEndpoint, TestPublicKey, TestPrivateKey);
            var message = client.GenerateRequestDetails(subscription, @"test payload");
            var authorizationHeader = message.Headers.GetValues(@"Authorization").First();

            Assert.IsTrue(authorizationHeader.StartsWith(@"key="));
        }

        [TestMethod]
        [DataRow(HttpStatusCode.Created)]
        [DataRow(HttpStatusCode.Accepted)]
        public void TestHandlingSuccessHttpCodes(HttpStatusCode status)
        {
            TestSendNotification(status);
        }

        [TestMethod]
        [DataRow(HttpStatusCode.BadRequest, "Bad Request")]
        [DataRow(HttpStatusCode.RequestEntityTooLarge, "Payload too large")]
        [DataRow((HttpStatusCode)429, "Too many request")]
        [DataRow(HttpStatusCode.NotFound, "Subscription no longer valid")]
        [DataRow(HttpStatusCode.Gone, "Subscription no longer valid")]
        [DataRow(HttpStatusCode.InternalServerError, "Received unexpected response code: 500")]
        public void TestHandlingFailureHttpCodes(HttpStatusCode status, string expectedMessage)
        {
            var actual = Assert.ThrowsException<WebPushException>(() => TestSendNotification(status));
            Assert.AreEqual(expectedMessage, actual.Message);
        }

        [TestMethod]
        [DataRow(HttpStatusCode.BadRequest, "authorization key missing", "Bad Request. Details: authorization key missing")]
        [DataRow(HttpStatusCode.RequestEntityTooLarge, "max size is 512", "Payload too large. Details: max size is 512")]
        [DataRow((HttpStatusCode)429, "the api is limited", "Too many request. Details: the api is limited")]
        [DataRow(HttpStatusCode.NotFound, "", "Subscription no longer valid")]
        [DataRow(HttpStatusCode.Gone, "", "Subscription no longer valid")]
        [DataRow(HttpStatusCode.InternalServerError, "internal error", "Received unexpected response code: 500. Details: internal error")]
        public void TestHandlingFailureMessages(HttpStatusCode status, string response, string expectedMessage)
        {
            var actual = Assert.ThrowsException<WebPushException>(() => TestSendNotification(status, response));
            Assert.AreEqual(expectedMessage, actual.Message);
        }

        [TestMethod]
        [DataRow(1)]
        [DataRow(5)]
        [DataRow(10)]
        [DataRow(50)]
        public void TestHandleInvalidPublicKeys(int charactersToDrop)
        {
            var invalidKey = TestPublicKey.Substring(0, TestPublicKey.Length - charactersToDrop);

            Assert.ThrowsException<InvalidEncryptionDetailsException>(() => TestSendNotification(HttpStatusCode.OK, response: null, invalidKey));
        }

        private void TestSendNotification(HttpStatusCode status, string response = null, string publicKey = TestPublicKey)
        {
            var subscription = new PushSubscription(TestFcmEndpoint, publicKey, TestPrivateKey);
            var httpContent = response == null ? null : new StringContent(response);
            httpMessageHandlerMock.When(TestFcmEndpoint).Respond(req  => new HttpResponseMessage { StatusCode = status, Content = httpContent });
            client.SetVapidDetails(TestSubject, TestPublicKey, TestPrivateKey);
            client.SendNotification(subscription, "123");
        }
    }
}