using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RichardSzalay.MockHttp;
using WebPush.Model;

namespace WebPush.Test;

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
    public void TestSetTopic()
    {
        var subscription = new PushSubscription(TestGcmEndpoint, TestPublicKey, TestPrivateKey);
        var message = client.GenerateRequestDetails(subscription, @"test payload", new WebPushOptions { Topic = "testtopic" });
        Assert.AreEqual(@"testtopic", message.Headers.GetValues(@"Topic").First());
    }

    [TestMethod]
    public void TestSetTopicFailures()
    {
        var subscription = new PushSubscription(TestGcmEndpoint, TestPublicKey, TestPrivateKey);
        Assert.ThrowsExactly<ArgumentException>(() => client.GenerateRequestDetails(subscription, @"test payload", new WebPushOptions { Topic = "failing topic #3" }));
    }


    [TestMethod]
    public void TestSetUrgency()
    {
        var subscription = new PushSubscription(TestGcmEndpoint, TestPublicKey, TestPrivateKey);
        var message = client.GenerateRequestDetails(subscription, @"test payload", new WebPushOptions { Urgency = Urgency.VeryLow });
        Assert.AreEqual(@"very-low", message.Headers.GetValues(@"Urgency").First());
    }

    [TestMethod]
    public void TestSetContentEncoding()
    {
        var subscription = new PushSubscription(TestGcmEndpoint, TestPublicKey, TestPrivateKey);
        var messageAes128gcm = client.GenerateRequestDetails(subscription, @"test payload", new WebPushOptions { ContentEncoding = ContentEncoding.Aes128gcm });
        Assert.AreEqual(@"aes128gcm", messageAes128gcm.Content.Headers.ContentEncoding.First());
        var messageAesgcm = client.GenerateRequestDetails(subscription, @"test payload", new WebPushOptions { ContentEncoding = ContentEncoding.Aesgcm });
        Assert.AreEqual(@"aesgcm", messageAesgcm.Content.Headers.ContentEncoding.First());
    }


    [TestMethod]
    public void TestSetVapidDetails()
    {
        client.SetVapidDetails(TestSubject, TestPublicKey, TestPrivateKey);

        var subscription = new PushSubscription(TestFirefoxEndpoint, TestPublicKey, TestPrivateKey);
        var message = client.GenerateRequestDetails(subscription, @"test payload", new WebPushOptions());
        var authorizationHeader = message.Headers.GetValues(@"Authorization").First();
        // var cryptoHeader = message.Headers.GetValues(@"Crypto-Key").First();

        // Assert.StartsWith(@"WebPush ", authorizationHeader);
        Assert.StartsWith(@"vapid ", authorizationHeader);
        // Assert.Contains(@"p256ecdsa", cryptoHeader);
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
        var actual = Assert.ThrowsExactly<WebPushException>(() => TestSendNotification(status));
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
        var actual = Assert.ThrowsExactly<WebPushException>(() => TestSendNotification(status, response));
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
#if NET8_0
        Assert.Throws<Exception>(() => TestSendNotification(HttpStatusCode.OK, response: null, invalidKey));
#endif
#if NET9_0_OR_GREATER
        Assert.ThrowsExactly<InvalidEncryptionDetailsException>(() => TestSendNotification(HttpStatusCode.OK, response: null, invalidKey));
#endif
    }

    private void TestSendNotification(HttpStatusCode status, string response = null, string publicKey = TestPublicKey)
    {
        var subscription = new PushSubscription(TestFcmEndpoint, publicKey, TestPrivateKey);
        var httpContent = response == null ? null : new StringContent(response);
        httpMessageHandlerMock.When(TestFcmEndpoint).Respond(req => new HttpResponseMessage { StatusCode = status, Content = httpContent });
        client.SetVapidDetails(TestSubject, TestPublicKey, TestPrivateKey);
        client.SendNotification(subscription, "123", new WebPushOptions());
    }

}
