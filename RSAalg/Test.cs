using NUnit.Framework;

namespace RSAv2
{

    [TestFixture]
    public class TestRsa
    {
        
        [TestCase("123213123212132131322111321335453545543545334", 
            "765432456432456543534534544353454354345345", 
            "123978555668564587865645855879806999897890679")]
        public void AdditionTest(string first, 
            string second, string expected)
        {
            var bigFirst = new BigInteger(first);
            var bigSecond = new BigInteger(second);
            var bigExpected = new BigInteger(expected);
            Assert.AreEqual(bigFirst + bigSecond, bigExpected);
        }

        [TestCase("4324323252143252542343242343243243", 
            "4324323252143252542343242343243243", 
            "0")]
        public void SubtractTest(string first, string second, string expected)
        {
            var bigFirst = new BigInteger(first);
            var bigSecond = new BigInteger(second);
            var bigExpected = new BigInteger(expected);
            Assert.AreEqual(bigFirst - bigSecond, bigExpected);
        }

        [TestCase("4324323252143252542343242343243243", 
            "4324323252143252542343242343243243", 
            "18699771589026796103546516150803244034073549474342524243535865157049")]
        public void MultiplicationTest(string first, string second, string expected)
        {
            var bigFirst = new BigInteger(first);
            var bigSecond = new BigInteger(second);
            var bigExpected = new BigInteger(expected);
            Assert.AreEqual(bigFirst * bigSecond, bigExpected);
        }
        
        
        [TestCase("4324323252143252542343242343243243", 
            "4324323252143252542343242343243243", 
            "1")]
        public void  DivisionTest(string first, string second, string expected)
        {
            var bigFirst = new BigInteger(first);
            var bigSecond = new BigInteger(second);
            var bigExpected = new BigInteger(expected);
            Assert.AreEqual(bigFirst / bigSecond, bigExpected);
        }

        [TestCase("4324323252143252542343242343243243", 
            "432432325214325254", 
            "2343242343243243")]
        public void ModTest(string first, string second, string expected)
        {
            var bigFirst = new BigInteger(first);
            var bigSecond = new BigInteger(second);
            var bigExpected = new BigInteger(expected);
            Assert.AreEqual(bigFirst % bigSecond, bigExpected);
        }

        [TestCase("4324323252143252542343242343243243", 
            "432432325214325254")]
        public void MoreTest(string first, string second)
        {
            var bigFirst = new BigInteger(first);
            var bigSecond = new BigInteger(second);
            Assert.IsTrue(bigFirst > bigSecond);
        }
        
        [TestCase("4324323252143252542343242343243243", 
            "432432325214325254654326543564325325353535")]
        public void LessTest(string first, string second)
        {
            var bigFirst = new BigInteger(first);
            var bigSecond = new BigInteger(second);
            Assert.IsTrue(bigFirst < bigSecond);
        }
        
        [TestCase("4324323252143252542343242343243243", 
            "4324323252143252542343242343243243")]
        public void EqualTest(string first, string second)
        {
            var bigFirst = new BigInteger(first);
            var bigSecond = new BigInteger(second);
            Assert.IsTrue(bigFirst == bigSecond);
        }

        [TestCase("4324323252143252542343242343243243", 
            "452435432521121321313231322312323131")]
        public void NoEqualTest(string first, string second)
        {
            var bigFirst = new BigInteger(first);
            var bigSecond = new BigInteger(second);
            Assert.IsTrue(bigFirst != bigSecond);
        }

        [TestCase("1234")]
        public void RsaTest(string expected)
        {
            var testBigInt = new BigInteger(expected);
            var rsa = new RSACrypt(new BigInteger(47), new BigInteger(31));
            var keys = rsa.GenerateKeys();
            var crypt = rsa.Encrypt(keys.Item1, testBigInt);
            var decrypt = rsa.Decrypt(keys.Item2, crypt);
            Assert.IsTrue(testBigInt == decrypt);
        }

        
        [TestCase("efdnjvfjdsnfksf")]
        public void RsaTextTest(string expected)
        {
            var rsa = new RSACrypt(new BigInteger(47), new BigInteger(31));
            var keys = rsa.GenerateKeys();
            var crypt = rsa.EncryptMessage(keys.Item1, expected);
            var decrypt = rsa.DecryptMessage(keys.Item2, crypt);
            Assert.IsTrue(expected == decrypt);
        }
        
    }
}