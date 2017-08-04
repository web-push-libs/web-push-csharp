using System;
using System.Linq;
using WebPush.Util;
using Xunit;

namespace WebPush.Test
{
    public class UrlBase64Test
    {
        [Fact]
        public void TestBase64UrlDecode()
        {
            byte[] expected = new byte[3] {181, 235, 45};
            byte[] actual = UrlBase64.Decode(@"test");
            Assert.True(actual.SequenceEqual(expected));
        }

        [Fact]
        public void TestBase64UrlEncode()
        {
            string expected = @"test";
            string actual = UrlBase64.Encode(new byte[3] {181, 235, 45});
            Assert.Equal(expected, actual);
        }

    }
}