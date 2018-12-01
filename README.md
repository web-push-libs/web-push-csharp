<h1 align="center">web-push-csharp</h1>

<p align="center">
  <a href="https://travis-ci.org/web-push-libs/web-push-csharp">
    <img src="https://travis-ci.org/web-push-libs/web-push-csharp.svg?branch=master" alt="Travis Build Status" />
  </a>
  <a href="https://www.nuget.org/packages/WebPush/">
    <img src="https://buildstats.info/nuget/WebPush" alt="Nuget Package Details" />
  </a>
</p>

# Why

Web push requires that push messages triggered from a backend be done via the
[Web Push Protocol](https://tools.ietf.org/html/draft-ietf-webpush-protocol)
and if you want to send data with your push message, you must also encrypt
that data according to the [Message Encryption for Web Push spec](https://tools.ietf.org/html/draft-ietf-webpush-encryption).

This package makes it easy to send messages and will also handle legacy support
for browsers relying on GCM for message sending / delivery.

# Install

Installation is simple, just install via NuGet.

    Install-Package WebPush

# Demo Project

There is a ASP.NET MVC Core demo project located [here](https://github.com/coryjthompson/WebPushDemo)

# Usage

The common use case for this library is an application server using
a GCM API key and VAPID keys.

```csharp
using WebPush;

var pushEndpoint = @"https://fcm.googleapis.com/fcm/send/efz_TLX_rLU:APA91bE6U0iybLYvv0F3mf6uDLB6....";
var p256dh = @"BKK18ZjtENC4jdhAAg9OfJacySQiDVcXMamy3SKKy7FwJcI5E0DKO9v4V2Pb8NnAPN4EVdmhO............";
var auth = @"fkJatBBEl...............";

var subject = @"mailto:example@example.com";
var publicKey = @"BDjASz8kkVBQJgWcD05uX3VxIs_gSHyuS023jnBoHBgUbg8zIJvTSQytR8MP4Z3-kzcGNVnM...............";
var privateKey = @"mryM-krWj_6IsIMGsd8wNFXGBxnx...............";

var subscription = new PushSubscription(pushEndpoint, p256dh, auth);
var vapidDetails = new VapidDetails(subject, publicKey, privateKey);
//var gcmAPIKey = @"[your key here]";

var webPushClient = new WebPushClient();
try
{
	webPushClient.SendNotification(subscription, "payload", vapidDetails);
    //webPushClient.SendNotification(subscription, "payload", gcmAPIKey);
}
catch (WebPushException exception)
{
	Console.WriteLine("Http STATUS code" + exception.StatusCode);
}
```

# API Reference

## SendNotification(pushSubscription, payload, vapidDetails|gcmAPIKey|options)

```csharp
var subscription = new PushSubscription(pushEndpoint, p256dh, auth);

var options = new Dictionary<string,object>();
options["vapidDetails"] = new VapidDetails(subject, publicKey, privateKey);
//options["gcmAPIKey"] = @"[your key here]";

var webPushClient = new WebPushClient();
try
{
	webPushClient.SendNotification(subscription, "payload", options);
}
catch (WebPushException exception)
{
	Console.WriteLine("Http STATUS code" + exception.StatusCode);
}
```

> **Note:** `SendNotification()` you don't need to define a payload, and this
method will work without a GCM API Key and / or VAPID keys if the push service
supports it.

### Input

**Push Subscription**

The first argument must be an PushSubscription object containing the details for a push
subscription.

**Payload**

The payload is optional, but if set, will be the data sent with a push
message.

This must be a *string*
> **Note:** In order to encrypt the *payload*, the *pushSubscription* **must**
have a *keys* object with *p256dh* and *auth* values.

**Options**

Options is an optional argument that if defined should be an Dictionary<string,object> containing
any of the following values defined, although none of them are required.

- **gcmAPIKey** can be a GCM API key to be used for this request and this
request only. This overrides any API key set via `setGCMAPIKey()`.
- **vapidDetails** should be a VapidDetails object with *subject*, *publicKey* and
*privateKey* values defined. These values should follow the [VAPID Spec](https://tools.ietf.org/html/draft-thomson-webpush-vapid).
- **TTL** is a value in seconds that describes how long a push message is
retained by the push service (by default, four weeks).
- **headers** is an object with all the extra headers you want to add to the request.

<hr />

## GenerateVapidKeys()

```csharp
VapidDetails vapidKeys = VapidHelper.GenerateVapidKeys();

// Prints 2 URL Safe Base64 Encoded Strings
Console.WriteLine("Public {0}", vapidKeys.PublicKey);
Console.WriteLine("Private {0}", vapidKeys.PrivateKey);
```

### Input

None.

### Returns

Returns a VapidDetails object with **PublicKey** and **PrivateKey** values populated which are
URL Safe Base64 encoded strings.

> **Note:** You should create these keys once, store them and use them for all
> future messages you send.

<hr />

## SetGCMAPIKey(apiKey)

```csharp
webPushClient.SetGCMAPIKey(@"your-gcm-key");
```

### Input

This method expects the GCM API key that is linked to the `gcm_sender_id ` in
your web app manifest.

You can use a GCM API Key from the Google Developer Console or the
*Cloud Messaging* tab under a Firebase Project.

### Returns

None.

<hr />

## GetVapidHeaders(audience, subject, publicKey, privateKey, expiration)

```csharp
Uri uri = new Uri(subscription.Endpoint);
string audience = uri.Scheme + Uri.SchemeDelimiter + uri.Host;

Dictionary<string, string> vapidHeaders = VapidHelper.GetVapidHeaders(
  audience,
  @"mailto: example@example.com",
  publicKey,
  privateKey
);
```

The *GetVapidHeaders()* method will take in the values needed to create
an Authorization and Crypto-Key header.

### Input

The `GetVapidHeaders()` method expects the following input:

- *audience*: the origin of the **push service**.
- *subject*: the mailto or URL for your application.
- *publicKey*: the VAPID public key.
- *privateKey*: the VAPID private key.

### Returns

This method returns a Dictionary<string, string> intented to be headers of a web request. It will contain the following keys:

- *Authorization*
- *Crypto-Key*.

<hr />

# Browser Support

<table>
<thead>
<tr>
	<th><strong>Browser</strong></th>
    <th width="130px"><strong>Push without Payload</strong></th>
    <th width="130px"><strong>Push with Payload</strong></th>
    <th width="130px"><strong>VAPID</strong></th>
    <th><strong>Notes</strong></th>
</tr>
</thead>
<tbody>
<tr>
	<td>Chrome</td>
	<!-- Push without payloads support-->
   <td>✓ v42+</td>
   <!-- Push with payload support -->
   <td>✓ v50+</td>
   <!-- VAPID Support -->
   <td>✓ v52+</td>
   <td>In v51 and less, the `gcm_sender_id` is needed to get a push subscription.</td>
   </tr>

   <tr>
   <td>Firefox</td>

   <!-- Push without payloads support-->
   <td>✓ v44+</td>

   <!-- Push with payload support -->
   <td>✓ v44+</td>

   <!-- VAPID Support -->
   <td>✓ v46+</td>

   <td></td>
   </tr>

   <tr>
   <td>Opera</td>

   <!-- Push without payloads support-->
   <td>✓ v39+ Android <strong>*</strong>
       <br/>
       <br/>
       ✓ v42+ Desktop
</td>
   <!-- Push with payload support -->
   <td>✓ v39+ Android <strong>*</strong>
       <br/>
       <br/>
       ✓ v42+ Desktop
</td>

   <!-- VAPID Support -->
   <td>✓ v42+ Desktop</td>

   <td>
   <strong>*</strong> The `gcm_sender_id` is needed to get a push subscription.
   </td>
   </tr>

   <tr>
   <td>Edge</td>

   <!-- Push without payloads support-->
   <td>✓ v17+</td>

   <!-- Push with payload support -->
   <td>✓ v17+</td>

   <!-- VAPID Support -->
   <td>✓ v17+</td>

   <td></td>
   </tr>
   <tr>
   <td>Safari</td>

   <!-- Push without payloads support-->
   <td>✗</td>

   <!-- Push with payload support -->
   <td>✗</td>

   <!-- VAPID Support -->
   <td>✗</td>

   <td></td>
   </tr>

   <tr>
   <td>Samsung Internet Browser</td>
   <!-- Push without payloads support-->
   <td>✓ v4.0.10-53+</td>
   <!-- Push with payload support -->
   <td>✗</td>

   <!-- VAPID Support -->
   <td>✗</td>

   <td>The `gcm_sender_id` is needed to get a push subscription.</td>
   </tr>
  </tbody>
</table>

# Help

**Service Worker Cookbook**

The [Service Worker Cookbook](https://serviceworke.rs/) is full of Web Push
examples.

# Credits
- Ported from https://github.com/web-push-libs/web-push.
- Original Encryption code from https://github.com/LogicSoftware/WebPushEncryption
