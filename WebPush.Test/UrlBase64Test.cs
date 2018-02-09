using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WebPush.Util;

namespace WebPush.Test
{
    [TestClass]
    public class UrlBase64Test
    {
        [TestMethod]
        public void TestBase64UrlDecode()
        {
            var expected = new byte[3] {181, 235, 45};
            var actual = UrlBase64.Decode(@"test");
            Assert.IsTrue(actual.SequenceEqual(expected));
        }

        [TestMethod]
        public void TestBase64UrlEncode()
        {
            var expected = @"test";
            var actual = UrlBase64.Encode(new byte[3] {181, 235, 45});
            Assert.AreEqual(expected, actual);
        }
    }
}