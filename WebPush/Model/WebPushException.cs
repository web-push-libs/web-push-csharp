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

		public WebPushException(string message, HttpStatusCode statusCode, HttpResponseHeaders headers,
			PushSubscription pushSubscription,string reasonPhrase) : this(
				message,statusCode,headers,pushSubscription)
		{
			ReasonPhrase = reasonPhrase;
		}

		public HttpStatusCode StatusCode { get; set; }
        public HttpResponseHeaders Headers { get; set; }
        public PushSubscription PushSubscription { get; set; }
		public string ReasonPhrase { get; set; }

	}
}