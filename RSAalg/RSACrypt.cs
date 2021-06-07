using System;
using System.Linq;
using System.Text;
using Microsoft.VisualBasic;

namespace RSAv2
{
    public class PublicKey
    {
        public BigInteger E { get; private set; }

        public BigInteger N { get; private set; }

        public PublicKey(BigInteger e, BigInteger n)
        {
            this.E = e;
            this.N = n;
        }

    }
    
    public class PrivateKey
    {
        public BigInteger d { get; }

        public BigInteger n { get; }

        public PrivateKey(BigInteger d, BigInteger n)
        {
            this.d = d;
            this.n = n;
        }

    }


    public class RSACrypt
    {
        private BigInteger r { get; }

        private BigInteger t { get; }

        private BigInteger y { get; }


        public RSACrypt(BigInteger r, BigInteger t)
        {
            this.r = r;
            this.t = t;
            y = new BigInteger(17);
        }

        public Tuple<PublicKey, PrivateKey> GenerateKeys()
        {
            var n = r * t;
            var phi = (r - 1) * (t - 1);
            var d = new BigInteger(1);
            var compare = new BigInteger(1);
            while (((y * d) % phi) != compare)
            {
                
                d++;
                
            }
            return Tuple.Create(new PublicKey(y, n), new PrivateKey(d, n));
        }

        public BigInteger Encrypt(PublicKey key, BigInteger encryptMessage)
        {
            return encryptMessage.Pow(key.E) % key.N;
        }

        public BigInteger Decrypt(PrivateKey key, BigInteger decryptedMessage)
        {
            return decryptedMessage.Pow(key.d) % key.n;
        }

        public BigInteger[] EncryptMessage(PublicKey key, string text)
        {
            var bytes = text.Select(sym => (byte) sym).ToArray();
            var cryptBytes = bytes
                .Select(bt => Encrypt(key, new BigInteger(bt)))
                .ToArray();
            return cryptBytes;
        }

        public string DecryptMessage(PrivateKey key, BigInteger[] decryptedMessage)
        {
            var decrypt = decryptedMessage
                .Select(bg => (byte) BigInteger.ToInt32(Decrypt(key, bg)))
                .Select(bt => (char) bt)
                .ToArray();
            return string.Join("", decrypt);
        }
    }
}