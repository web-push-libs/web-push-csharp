using System;
using System.Net;
using System.Net.Http.Headers;

namespace WebPush
{
    public class WebPushException : Exception
    {
        public WebPushException(string message, HttpStatusCode statusCode, HttpResponseHeaders headers,
            PushSubscription pushSubscription) : base(message)
        {
            StatusCode = statusCode;
            Headers = headers;
            PushSubscription = pushSubscription;
        }

        public HttpStatusCode StatusCode { get; set; }
        public HttpResponseHeaders Headers { get; set; }
        public PushSubscription PushSubscription { get; set; }
    }
}