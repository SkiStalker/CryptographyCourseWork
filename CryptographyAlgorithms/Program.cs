using System.Numerics;
using System.Security.Cryptography;

namespace CryptographyAlgorithms
{
    public class XTR1
    {
        public class EncryptedMessage
        {
            public BigInteger TrGb { get; set; }
            public BigInteger E { get; set; }
        }

        public class PublicKey
        {
            public BigInteger P { get; set; }
            public BigInteger Q { get; set; }
            public BigInteger TrG { get; set; }
            public BigInteger TrGk { get; set; }
        }

        public class PrivateKey
        {
            public BigInteger P { get; set; }
            public BigInteger K { get; set; }
        }


        public enum PrimaryTest
        {
            Fermat,
            SolovayStrassen,
            MillerRabin
        }

        private readonly PrimaryTest primaryTest;
        private readonly int keyBitLength;
        private readonly double primaryProbability;

        public XTR1(int keyBitLength, PrimaryTest primaryTest, double primaryProbability)
        {
            this.primaryTest = primaryTest;
            this.primaryProbability = primaryProbability;
            this.keyBitLength = keyBitLength;
        }


        private BigInteger ModSub(BigInteger a, BigInteger b, BigInteger p)
        {
            BigInteger res = a - b;

            BigInteger cf = res / p;
            
            if (res < BigInteger.Zero)
            {
                res += cf * p;
            }

            return res % p;
        }

        public BigInteger S(BigInteger c, BigInteger n, BigInteger p)
        {
            if (n == BigInteger.Zero)
            {
                return 3;
            }
            else if (n == BigInteger.One)
            {
                return c;
            }
            else
            {
                BigInteger cn_1 = 3;
                BigInteger cn = new BigInteger(c.ToByteArray(), true);
                BigInteger cn1 = ModSub(c * c, 2 * BigInteger.ModPow(c, p, p), p);
                BigInteger localN = new BigInteger(n.ToByteArray(), true);

                if (!n.IsEven)
                {
                    localN -= 1;
                }


                while (localN != BigInteger.Zero)
                {
                    (cn_1, cn, cn1) = (
                        (ModSub(cn_1 * cn, BigInteger.ModPow(c, p, p) * BigInteger.ModPow(cn, p, p), p) +
                         BigInteger.ModPow(cn1, p, p)) % p,
                        ModSub(BigInteger.ModPow(cn, 2, p), 2 * BigInteger.ModPow(cn, p, p), p),
                        (ModSub(cn1 * cn, BigInteger.ModPow(c, p, p) * BigInteger.ModPow(cn, p, p), p) +
                         BigInteger.ModPow(cn_1, p, p)) % p
                    );

                    localN >>= 1;
                }

                if (!n.IsEven)
                {
                    cn = cn1;
                }


                return cn;
            }
        }

        delegate void GenerateFunction(ref BigInteger? res, ref bool findRes, Semaphore semRes, Mutex mutexRes,
            int byteLength);


        private BigInteger FastGenerateDigit(GenerateFunction generateFunction, int byteLength)
        {
            BigInteger? res = null;

            bool findRes = false;
            int threadsCnt = Environment.ProcessorCount;
            Semaphore semRes = new Semaphore(0, threadsCnt);
            Mutex mutexRes = new Mutex();

            for (int i = 0; i < threadsCnt; i++)
            {
                new Thread(() => { generateFunction(ref res, ref findRes, semRes, mutexRes, byteLength); }).Start();
            }

            for (int i = 0; i < threadsCnt; i++)
            {
                semRes.WaitOne();
            }

            return res ?? throw new NullReferenceException(nameof(res));
        }

        private void GenerateR(ref BigInteger? r, ref bool findR, Semaphore semR, Mutex mutexR,
            int byteLength)
        {
            RandomNumberGenerator generator = RandomNumberGenerator.Create();
            byte[] rBytes = new byte[byteLength];
            generator.GetBytes(rBytes);
            BigInteger tmpR = new BigInteger(rBytes, true);

            IPrimaryTest? primaryTestImplementation = null;
            switch (primaryTest)
            {
                case PrimaryTest.Fermat:
                {
                    primaryTestImplementation = new FermatTest();
                    break;
                }
                case PrimaryTest.SolovayStrassen:
                {
                    primaryTestImplementation = new SolovayStrassenTest();
                    break;
                }
                case PrimaryTest.MillerRabin:
                {
                    primaryTestImplementation = new MillerRabinTest();
                    break;
                }
                default:
                {
                    throw new ArgumentException("Unknown primary test");
                }
            }

            bool alive = true;
            while (alive)
            {
                mutexR.WaitOne();
                alive = !findR;
                mutexR.ReleaseMutex();
                if (findR)
                {
                    continue;
                }

                if (primaryTestImplementation.Test(tmpR * tmpR - tmpR + 1, primaryProbability))
                {
                    mutexR.WaitOne();
                    if (!findR)
                    {
                        r = tmpR;
                        findR = true;
                    }

                    mutexR.ReleaseMutex();
                    break;
                }
                else
                {
                    tmpR += 1;
                }
            }

            semR.Release();
        }

        private void GenerateK(ref BigInteger? k, BigInteger r, BigInteger q, ref bool findK, Semaphore semK,
            Mutex mutexK,
            int byteLength)
        {
            RandomNumberGenerator generator = RandomNumberGenerator.Create();
            byte[] kBytes = new byte[byteLength];
            generator.GetBytes(kBytes);
            BigInteger tmpK = new BigInteger(kBytes, true);

            IPrimaryTest? primaryTestImplementation = null;
            switch (primaryTest)
            {
                case PrimaryTest.Fermat:
                {
                    primaryTestImplementation = new FermatTest();
                    break;
                }
                case PrimaryTest.SolovayStrassen:
                {
                    primaryTestImplementation = new SolovayStrassenTest();
                    break;
                }
                case PrimaryTest.MillerRabin:
                {
                    primaryTestImplementation = new MillerRabinTest();
                    break;
                }
                default:
                {
                    throw new ArgumentException("Unknown primary test");
                }
            }

            bool alive = true;
            while (alive)
            {
                mutexK.WaitOne();
                alive = !findK;
                mutexK.ReleaseMutex();
                if (findK)
                {
                    continue;
                }

                if (primaryTestImplementation.Test(r + tmpK * q, primaryProbability) && (r + tmpK * q) % 3 == 2)
                {
                    mutexK.WaitOne();
                    if (!findK)
                    {
                        k = tmpK;
                        findK = true;
                    }

                    mutexK.ReleaseMutex();
                    break;
                }
                else
                {
                    tmpK += 1;
                }
            }

            semK.Release();
        }

        private void GenerateTrG(ref BigInteger? trG, BigInteger p, BigInteger q, ref bool findTrG, Semaphore semTrG,
            Mutex mutexTrG,
            int byteLength)
        {
            BigInteger p2 = p * p;

            RandomNumberGenerator generator = RandomNumberGenerator.Create();
            byte[] cBytes = new byte[byteLength];
            BigInteger c;
            do
            {
                generator.GetNonZeroBytes(cBytes);
                c = new BigInteger(cBytes, true);
            } while (c < p || c >= p2 || BigInteger.ModPow(c, p + 1, p2) < p);

            bool alive = true;
            while (alive)
            {
                mutexTrG.WaitOne();
                alive = !findTrG;
                mutexTrG.ReleaseMutex();
                if (findTrG)
                {
                    continue;
                }

                BigInteger d = S(c, (p2 - p + 1) / q, p2);

                if (BigInteger.ModPow(d, q, p2) == 1)
                {
                    mutexTrG.WaitOne();
                    if (!findTrG)
                    {
                        trG = d;
                        findTrG = true;
                    }

                    mutexTrG.ReleaseMutex();
                    break;
                }
                else
                {
                    c += BigInteger.One;
                }
            }

            semTrG.Release();
        }


        public (PrivateKey, PublicKey) GenerateKeys()
        {
            BigInteger r = FastGenerateDigit(GenerateR, keyBitLength / 8);

            BigInteger q = r * r - r + 1;

            BigInteger k = FastGenerateDigit(
                delegate(ref BigInteger? res, ref bool findRes, Semaphore semRes, Mutex mutexRes, int length)
                {
                    GenerateK(ref res, r, q, ref findRes, semRes, mutexRes, length);
                }, 2);


            BigInteger p = r + k * q;
            BigInteger p2 = p * p;


            BigInteger trG =
                FastGenerateDigit(
                    delegate(ref BigInteger? res, ref bool findRes, Semaphore semRes, Mutex mutexRes, int length)
                    {
                        GenerateTrG(ref res, p, q, ref findRes, semRes, mutexRes, length);
                    },
                    p.GetByteCount() + 1);

            RandomNumberGenerator generator = RandomNumberGenerator.Create();
            BigInteger secretK;
            byte[] secretKBytes = new byte[q.GetByteCount() - 1];
            do
            {
                generator.GetNonZeroBytes(secretKBytes);
                secretK = new BigInteger(secretKBytes, true);
            } while (secretK < 2 || secretK > q - 3);

            BigInteger trGk = S(trG, k, p2);

            return (new PrivateKey
            {
                P = p,
                K = k
            }, new PublicKey
            {
                P = p,
                Q = q,
                TrG = trG,
                TrGk = trGk
            });
        }

        public EncryptedMessage Encrypt(BigInteger msg, PublicKey publicKey)
        {
            BigInteger p2 = publicKey.P * publicKey.P;
            RandomNumberGenerator generator = RandomNumberGenerator.Create();
            BigInteger b;
            byte[] secretKBytes = new byte[publicKey.Q.GetByteCount() - 1];
            do
            {
                generator.GetNonZeroBytes(secretKBytes);
                b = new BigInteger(secretKBytes, true);
            } while (b < 2 || b > publicKey.Q - 3);

            BigInteger trGb = S(publicKey.TrG, b, p2);
            BigInteger trGbK = S(publicKey.TrGk, b, p2);
            return new EncryptedMessage
            {
                TrGb = trGb,
                E = msg
            };
        }

        public BigInteger Decrypt(EncryptedMessage encryptedMessage, PrivateKey privateKey)
        {
            BigInteger p2 = privateKey.P * privateKey.P;
            BigInteger trGbK = S(encryptedMessage.TrGb, privateKey.K, p2);
            
            return encryptedMessage.E;
        }
    }


    public static class Program
    {
        public static string ToHexString(uint[] arr)
        {
            byte[] res = new byte[arr.Length * 4];
            for (int i = 0; i < res.Length; i++)
            {
                res[i] = (byte)(arr[i / 4] >> (24 - 8 * (i % 4)));
            }

            return Convert.ToHexString(res);
        }

        static void Main(string[] args)
        {
            XTR1 xtr1 = new XTR1(64, XTR1.PrimaryTest.MillerRabin, 0.9);

            (XTR1.PrivateKey privateKey, XTR1.PublicKey publicKey)= xtr1.GenerateKeys();
            BigInteger msg = 12345;
            XTR1.EncryptedMessage encMsg = xtr1.Encrypt(msg, publicKey);

            BigInteger res = xtr1.Decrypt(encMsg, privateKey);
            
            
            Console.ReadLine();
        }
    }
}