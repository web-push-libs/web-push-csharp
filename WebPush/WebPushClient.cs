using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using WebPush.Util;

namespace WebPush
{
    public class WebPushClient
    {
        // default TTL is 4 weeks.
        private const int DefaultTtl = 2419200;

        private string _gcmAPIKey = null;
        private HttpClient _httpClient = null;
        private VapidDetails _vapidDetails = null;

        public WebPushClient()
        {
        }

        protected HttpClient httpClient
        {
            get
            {
                if (_httpClient == null)
                {
                    _httpClient = new HttpClient();
                }

                return _httpClient;
            }
        }

        /// <summary>
        /// When sending messages to a GCM endpoint you need to set the GCM API key
        /// by either calling setGCMAPIKey() or passing in the API key as an option
        /// to sendNotification()
        /// </summary>
        /// <param name="apiKey">The API key to send with the GCM request.</param>
        public void SetGCMAPIKey(string apiKey)
        {
            if (apiKey == null)
            {
                _gcmAPIKey = null;
                return;
            }

            if (String.IsNullOrEmpty(apiKey))
            {
                throw new ArgumentException(@"The GCM API Key should be a non-empty string or null.");
            }

            _gcmAPIKey = apiKey;
        }

        /// <summary>
        /// When marking requests where you want to define VAPID details, call this method
        /// before sendNotifications() or pass in the details and options to
        /// sendNotification.
        /// </summary>
        /// <param name="vapidDetails"></param>
        public void SetVapidDetails(VapidDetails vapidDetails)
        {
            VapidHelper.ValidateSubject(vapidDetails.Subject);
            VapidHelper.ValidatePublicKey(vapidDetails.PublicKey);
            VapidHelper.ValidatePrivateKey(vapidDetails.PrivateKey);

            _vapidDetails = vapidDetails;
        }

        /// <summary>
        /// When marking requests where you want to define VAPID details, call this method
        /// before sendNotifications() or pass in the details and options to
        /// sendNotification.
        /// </summary>
        /// <param name="subject">This must be either a URL or a 'mailto:' address</param>
        /// <param name="publicKey">The public VAPID key as a base64 encoded string</param>
        /// <param name="privateKey">The private VAPID key as a base64 encoded string</param>
        public void SetVapidDetails(string subject, string publicKey, string privateKey)
        {
            SetVapidDetails(new VapidDetails(subject, publicKey, privateKey));
        }

        /// <summary>
        /// To get a request without sending a push notification call this method.
        ///
        /// This method will throw an ArgumentException if there is an issue with the input.
        /// </summary>
        /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
        /// <param name="payload">The payload you wish to send to the user</param>
        /// <param name="options">Options for the GCM API key and vapid keys can be passed in if they are unique for each notification.</param>
        /// <returns>A HttpRequestMessage object that can be sent.</returns>
        public HttpRequestMessage GenerateRequestDetails(PushSubscription subscription, string payload, Dictionary<string, object> options = null)
        {
            if (!Uri.IsWellFormedUriString(subscription.Endpoint, UriKind.Absolute))
            {
                throw new ArgumentException(@"You must pass in a subscription with at least a valid endpoint");
            }

            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, subscription.Endpoint);

            if (!String.IsNullOrEmpty(payload) && (String.IsNullOrEmpty(subscription.Auth) || String.IsNullOrEmpty(subscription.P256DH)))
            {
                throw new ArgumentException(@"To send a message with a payload, the subscription must have 'auth' and 'p256dh' keys.");
            }

            string currentGCMAPiKey = _gcmAPIKey;
            VapidDetails currentVapidDetails = _vapidDetails;
            int timeToLive = DefaultTtl;
            Dictionary<string, object> extraHeaders = new Dictionary<string, object>();

            if (options != null)
            {
                List<string> validOptionsKeys = new List<string> { "headers", "gcmAPIKey", "vapidDetails", "TTL" };
                foreach (string key in options.Keys)
                {
                    if (!validOptionsKeys.Contains(key))
                    {
                        throw new ArgumentException(key + " is an invalid options. The valid options are" + String.Join(",", validOptionsKeys));
                    }
                }

                if (options.ContainsKey("headers"))
                {
                    Dictionary<string, object> headers = options["headers"] as Dictionary<string, object>;
                    if (headers == null)
                    {
                        throw new ArgumentException("options.headers must be of type Dictionary<string,object>");
                    }

                    extraHeaders = headers;
                }

                if (options.ContainsKey("gcmAPIKey"))
                {
                    string gcmAPIKey = options["gcmAPIKey"] as string;
                    if (gcmAPIKey == null)
                    {
                        throw new ArgumentException("options.gcmAPIKey must be of type string");
                    }

                    currentGCMAPiKey = gcmAPIKey;
                }

                if (options.ContainsKey("vapidDetails"))
                {
                    VapidDetails vapidDetails = options["vapidDetails"] as VapidDetails;
                    if (vapidDetails == null)
                    {
                        throw new ArgumentException("options.vapidDetails must be of type VapidDetails");
                    }

                    currentVapidDetails = vapidDetails;
                }

                if (options.ContainsKey("TTL"))
                {
                    int? ttl = options["TTL"] as int?;
                    if (ttl == null)
                    {
                        throw new ArgumentException("options.TTL must be of type int");
                    }

                    //at this stage ttl cannot be null.
                    timeToLive = (int)ttl;
                }
            }

            string cryptoKeyHeader = null;
            request.Headers.Add("TTL", timeToLive.ToString());

            foreach (KeyValuePair<string, object> header in extraHeaders)
            {
                request.Headers.Add(header.Key, header.Value.ToString());
            }

            if (!String.IsNullOrEmpty(payload))
            {
                if (String.IsNullOrEmpty(subscription.P256DH) || String.IsNullOrEmpty(subscription.Auth))
                {
                    throw new ArgumentException(@"Unable to send a message with payload to this subscription since it doesn't have the required encryption key");
                }

                EncryptionResult encryptedPayload = Encryptor.Encrypt(subscription.P256DH, subscription.Auth, payload);

                request.Content = new ByteArrayContent(encryptedPayload.Payload);
                request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
                request.Content.Headers.ContentLength = encryptedPayload.Payload.Length;
                request.Content.Headers.ContentEncoding.Add("aesgcm");
                request.Headers.Add("Encryption", "salt=" + encryptedPayload.Base64EncodeSalt());
                cryptoKeyHeader = @"dh=" + encryptedPayload.Base64EncodePublicKey();
            }
            else
            {
                request.Content = new ByteArrayContent(new byte[0]);
                request.Content.Headers.ContentLength = 0;
            }

            bool isGCM = subscription.Endpoint.StartsWith(@"https://android.googleapis.com/gcm/send");
            if (isGCM)
            {
                if (!String.IsNullOrEmpty(currentGCMAPiKey))
                {
                    request.Headers.TryAddWithoutValidation("Authorization", "key=" + currentGCMAPiKey);
                }
            }
            else if (currentVapidDetails != null)
            {
                Uri uri = new Uri(subscription.Endpoint);
                string audience = uri.Scheme + @"://" + uri.Host;

                Dictionary<string, string> vapidHeaders = VapidHelper.GetVapidHeaders(audience, currentVapidDetails.Subject, currentVapidDetails.PublicKey, currentVapidDetails.PrivateKey);
                request.Headers.Add(@"Authorization", vapidHeaders["Authorization"]);
                if (String.IsNullOrEmpty(cryptoKeyHeader))
                {
                    cryptoKeyHeader = vapidHeaders["Crypto-Key"];
                }
                else
                {
                    cryptoKeyHeader += @";" + vapidHeaders["Crypto-Key"];
                }
            }

            request.Headers.Add("Crypto-Key", cryptoKeyHeader);
            return request;
        }

        /// <summary>
        /// To send a push notification call this method with a subscription, optional payload and any options
        /// Will exception if unsuccessful
        /// </summary>
        /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
        /// <param name="payload">The payload you wish to send to the user</param>
        /// <param name="options">Options for the GCM API key and vapid keys can be passed in if they are unique for each notification.</param>
        public void SendNotification(PushSubscription subscription, string payload = null, Dictionary<string, object> options = null)
        {
            HttpRequestMessage request = GenerateRequestDetails(subscription, payload, options);
            Task<HttpResponseMessage> response = httpClient.SendAsync(request);
            response.Wait();

            throw new WebPushException(@"Received unexpected response code", response.Result.StatusCode, response.Result.Headers, subscription);
        }

        /// <summary>
        /// To send a push notification call this method with a subscription, optional payload and any options
        /// Will exception if unsuccessful
        /// </summary>
        /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
        /// <param name="payload">The payload you wish to send to the user</param>
        /// <param name="vapidDetails">The vapid details for the notification.</param>
        public void SendNotification(PushSubscription subscription, string payload, VapidDetails vapidDetails)
        {
            Dictionary<string, object> options = new Dictionary<string, object>();
            options["vapidDetails"] = vapidDetails;
            SendNotification(subscription, payload, options);
        }

        /// <summary>
        /// To send a push notification call this method with a subscription, optional payload and any options
        /// Will exception if unsuccessful
        /// </summary>
        /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
        /// <param name="payload">The payload you wish to send to the user</param>
        /// <param name="gcmAPIKey">The GCM API key</param>
        public void SendNotification(PushSubscription subscription, string payload, string gcmAPIKey)
        {
            Dictionary<string, object> options = new Dictionary<string, object>();
            options["gcmAPIKey"] = gcmAPIKey;
            SendNotification(subscription, payload, options);
        }

        /// <summary>
        /// To send a push notification asyncronously call this method with a subscription, optional payload and any options
        /// Will exception if unsuccessful
        /// </summary>
        /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
        /// <param name="payload">The payload you wish to send to the user</param>
        /// <param name="options">Options for the GCM API key and vapid keys can be passed in if they are unique for each notification.</param>
        public async Task SendNotificationAsync(PushSubscription subscription, string payload = null, Dictionary<string, object> options = null)
        {
            HttpRequestMessage request = GenerateRequestDetails(subscription, payload, options);
            HttpResponseMessage response = await httpClient.SendAsync(request);

            throw new WebPushException(@"Received unexpected response code", response.StatusCode, response.Headers, subscription);
        }

        /// <summary>
        /// To send a push notification asyncronously call this method with a subscription, optional payload and any options
        /// Will exception if unsuccessful
        /// </summary>
        /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
        /// <param name="payload">The payload you wish to send to the user</param>
        /// <param name="vapidDetails">The vapid details for the notification.</param>
        public async Task SendNotificationAsync(PushSubscription subscription, string payload, VapidDetails vapidDetails)
        {
            Dictionary<string, object> options = new Dictionary<string, object>();
            options["vapidDetails"] = vapidDetails;
            await SendNotificationAsync(subscription, payload, options);
        }

        /// <summary>
        /// To send a push notification asyncronously call this method with a subscription, optional payload and any options
        /// Will exception if unsuccessful
        /// </summary>
        /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
        /// <param name="payload">The payload you wish to send to the user</param>
        /// <param name="gcmAPIKey">The GCM API key</param>
        public async Task SendNotificationAsync(PushSubscription subscription, string payload, string gcmAPIKey)
        {
            Dictionary<string, object> options = new Dictionary<string, object>();
            options["gcmAPIKey"] = gcmAPIKey;
            await SendNotificationAsync(subscription, payload, options);
        }
    }
}