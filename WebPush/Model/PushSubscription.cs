namespace WebPush
{
    public class PushSubscription
    {
        public PushSubscription()
        {
        }

        public PushSubscription(string endpoint, string p256dh, string auth)
        {
            Endpoint = endpoint;
            P256DH = p256dh;
            Auth = auth;
        }

        public string Endpoint { get; set; }
        public string P256DH { get; set; }
        public string Auth { get; set; }
    }
}