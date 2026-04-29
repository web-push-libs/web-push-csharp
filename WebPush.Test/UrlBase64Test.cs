using System.Linq;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[assembly: Parallelize(Scope = ExecutionScope.MethodLevel)]

namespace WebPush.Test;

[TestClass]
public class UrlBase64Test
{
    [TestMethod]
    public void TestBase64UrlDecode()
    {
        var expected = new byte[3] { 181, 235, 45 };
        var actual = Base64UrlEncoder.DecodeBytes(@"test");
        Assert.IsTrue(actual.SequenceEqual(expected));
    }

    [TestMethod]
    public void TestBase64UrlEncode()
    {
        var expected = @"test";
        var actual = Base64UrlEncoder.Encode([181, 235, 45]);
        Assert.AreEqual(expected, actual);
    }
}
