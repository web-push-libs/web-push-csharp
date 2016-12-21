using System;
using System.Net;
using System.Net.Http.Headers;

namespace WebPush
{
    public class WebPushException : Exception
    {
        public HttpStatusCode StatusCode { get; set; }
        public HttpResponseHeaders Headers { get; set; }

        public WebPushException(string message, HttpStatusCode statusCode, HttpResponseHeaders headers) : base(message)
        {
            StatusCode = statusCode;
            Headers = headers;
        }
    }
}
