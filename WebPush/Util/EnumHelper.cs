using System;
using System.Globalization;
using System.Text.RegularExpressions;

namespace WebPush.Util;

public static partial class EnumHelper2
{

    public static string ToKebabCaseLower<T>(this T val) where T : Enum
    {
        return RegexVariableName().Replace(val.ToString()!, "${first}-${remainder}").ToLower(CultureInfo.InvariantCulture);
    }

    [GeneratedRegex("(?<first>[a-z0-9]|(?<=[a-z0-9]))(?<remainder>[A-Z])", RegexOptions.None, matchTimeoutMilliseconds: 200)]
    private static partial Regex RegexVariableName();
}

