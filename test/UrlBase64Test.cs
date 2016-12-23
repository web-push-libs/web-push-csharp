using System;
using System.Linq;
using NUnit.Framework;
using WebPush.Util;

namespace WebPush.Test
{
    [TestFixture]
    public class UrlBase64Test
    {
        [Test]
        public void TestBase64UrlDecode()
        {
            byte[] expected = new byte[3] {181, 235, 45};
            byte[] actual = UrlBase64.Decode(@"test");
            Assert.IsTrue(actual.SequenceEqual(expected));
        }

        [Test]
        public void TestBase64UrlEncode()
        {
            string expected = @"test";
            string actual = UrlBase64.Encode(new byte[3] {181, 235, 45});
            Assert.AreEqual(expected, actual);
        }

    }
}
