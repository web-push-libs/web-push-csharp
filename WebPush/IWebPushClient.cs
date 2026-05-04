using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace WebPush;

public interface IWebPushClient : IDisposable
{
    /// <summary>
    ///     When marking requests where you want to define VAPID details, call this method
    ///     before sendNotifications() or pass in the details and options to
    ///     sendNotification.
    /// </summary>
    /// <param name="vapidDetails"></param>
    void SetVapidDetails(VapidDetails vapidDetails);

    /// <summary>
    ///     When marking requests where you want to define VAPID details, call this method
    ///     before sendNotifications() or pass in the details and options to
    ///     sendNotification.
    /// </summary>
    /// <param name="subject">This must be either a URL or a 'mailto:' address</param>
    /// <param name="publicKey">The public VAPID key as a base64 encoded string</param>
    /// <param name="privateKey">The private VAPID key as a base64 encoded string</param>
    void SetVapidDetails(string subject, string publicKey, string privateKey);

    /// <summary>
    ///     To get a request without sending a push notification call this method.
    ///     This method will throw an ArgumentException if there is an issue with the input.
    /// </summary>
    /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
    /// <param name="payload">The payload you wish to send to the user</param>
    /// <param name="options">
    ///     Options for vapid keys can be passed in if they are unique for each
    ///     notification.
    /// </param>
    /// <returns>A HttpRequestMessage object that can be sent.</returns>
    [Obsolete("Use GenerateRequestDetails with WebPushOptions")]
    HttpRequestMessage GenerateRequestDetails(PushSubscription subscription, string? payload,
        Dictionary<string, object>? options = null);

    /// <summary>
    ///     To get a request without sending a push notification call this method.
    ///     This method will throw an ArgumentException if there is an issue with the input.
    /// </summary>
    /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
    /// <param name="payload">The payload you wish to send to the user</param>
    /// <param name="options">
    ///     Options for the web push request, including vapid keys, if they are unique for each
    ///     notification.
    /// </param>
    /// <returns>A HttpRequestMessage object that can be sent.</returns>
    public HttpRequestMessage GenerateRequestDetails(PushSubscription subscription, string? payload, WebPushOptions? options = null);

    /// <summary>
    ///     To send a push notification call this method with a subscription, optional payload and any options
    ///     Will exception if unsuccessful
    /// </summary>
    /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
    /// <param name="payload">The payload you wish to send to the user</param>
    /// <param name="options">
    ///     Options for the web push request, including vapid keys, if they are unique for each
    ///     notification.
    /// </param>
    void SendNotification(PushSubscription subscription, string? payload = null, WebPushOptions? options = null);

    /// <summary>
    ///     To send a push notification call this method with a subscription, optional payload and any options
    ///     Will exception if unsuccessful
    /// </summary>
    /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
    /// <param name="payload">The payload you wish to send to the user</param>
    /// <param name="options">
    ///     Options for vapid keys can be passed in if they are unique for each
    ///     notification.
    /// </param>
    [Obsolete("Use SendNotification with WebPushOptions")]
    void SendNotification(PushSubscription subscription, string? payload = null,
        Dictionary<string, object>? options = null);

    /// <summary>
    ///     To send a push notification call this method with a subscription, optional payload and any options
    ///     Will exception if unsuccessful
    /// </summary>
    /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
    /// <param name="payload">The payload you wish to send to the user</param>
    /// <param name="vapidDetails">The vapid details for the notification.</param>
    void SendNotification(PushSubscription subscription, string payload, VapidDetails vapidDetails);

    /// <summary>
    ///     To send a push notification asynchronous call this method with a subscription, optional payload and any options
    ///     Will exception if unsuccessful
    /// </summary>
    /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
    /// <param name="payload">The payload you wish to send to the user</param>
    /// <param name="options">
    ///     Options for the web push request, including vapid keys, if they are unique for each
    ///     notification.
    /// </param>
    /// <param name="cancellationToken">The cancellation token to cancel operation.</param>
    Task SendNotificationAsync(PushSubscription subscription, string? payload = null, WebPushOptions? options = null, CancellationToken cancellationToken = default);

    /// <summary>
    ///     To send a push notification asynchronous call this method with a subscription, optional payload and any options
    ///     Will exception if unsuccessful
    /// </summary>
    /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
    /// <param name="payload">The payload you wish to send to the user</param>
    /// <param name="options">
    ///     Options for vapid keys can be passed in if they are unique for each
    ///     notification.
    /// </param>
    /// <param name="cancellationToken">The cancellation token to cancel operation.</param>
    [Obsolete("Use SendNotificationAsync with WebPushOptions")]
    Task SendNotificationAsync(PushSubscription subscription, string? payload = null,
        Dictionary<string, object>? options = null, CancellationToken cancellationToken = default);

    /// <summary>
    ///     To send a push notification asynchronous call this method with a subscription, optional payload and any options
    ///     Will exception if unsuccessful
    /// </summary>
    /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
    /// <param name="payload">The payload you wish to send to the user</param>
    /// <param name="vapidDetails">The vapid details for the notification.</param>
    /// <param name="cancellationToken"></param>
    Task SendNotificationAsync(PushSubscription subscription, string payload,
        VapidDetails vapidDetails, CancellationToken cancellationToken = default);
}