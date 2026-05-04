using System.Collections.Generic;

namespace WebPush;

public class WebPushOptions
{
    public VapidDetails? VapidDetails { get; set; }
    public const int DefaultTtl = 2419200; // default is 4 weeks
    public int TTL { get; set; } = DefaultTtl;
    public const ContentEncoding DefaultContentEncoding = WebPush.ContentEncoding.Aes128gcm;
    public ContentEncoding? ContentEncoding { get; set; }
    public Urgency? Urgency { get; set; }
    public string? Topic { get; set; }
    public Dictionary<string, object>? ExtraHeaders { get; set; }

    // 'proxy',
    // 'agent',
    // 'timeout'
}
