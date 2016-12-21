using System;
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
            byte[] expected = new byte[3] {181, 235, 45};
            byte[] actual = UrlBase64.Decode(@"test");
            Assert.IsTrue(actual.SequenceEqual(expected));
        }

        [TestMethod]
        public void TestBase64UrlEncode()
        {
            string expected = @"test";
            string actual = UrlBase64.Encode(new byte[3] {181, 235, 45});
            Assert.AreEqual(expected, actual);
        }

    }
}
