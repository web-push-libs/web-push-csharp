using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;

namespace WebPush
{
    public class WebPushException : Exception
    {
        public WebPushException(string message, PushSubscription pushSubscription, HttpResponseMessage responseMessage) : base(message)
        {
            PushSubscription = pushSubscription;
            HttpResponseMessage = responseMessage;
        }

        public HttpStatusCode StatusCode => HttpResponseMessage.StatusCode;

        public HttpResponseHeaders Headers => HttpResponseMessage.Headers;
        public PushSubscription PushSubscription { get; set; }
        public HttpResponseMessage HttpResponseMessage { get; set; }
    }
}