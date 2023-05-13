using System;
using System.Numerics;
using System.Security.Cryptography;
using CryptographyAlgorithms;

public class XTR
{
    public class PrivateKey
    {
        public BigInteger P { get; set; }
        public BigInteger G { get; set; }
        public BigInteger X { get; set; }
    }

    public class PublicKey
    {
        public BigInteger P { get; set; }
        public BigInteger G { get; set; }
        public BigInteger Y { get; set; }
    }

    public class EncryptedMessage
    {
        public BigInteger A { get; set; }
        public BigInteger B { get; set; }
    }


    public enum PrimaryTest
    {
        Fermat,
        SolovayStrassen,
        MillerRabin
    }

    delegate void GenerateFunction(ref BigInteger? res, ref bool findRes, Semaphore semRes, Mutex mutexRes,
        int byteLength);

    private readonly PrimaryTest primaryTest;
    private readonly int keyBitLength;
    private readonly double primaryProbability;

    public XTR(int keyBitLength, PrimaryTest primaryTest, double primaryProbability)
    {
        this.primaryTest = primaryTest;
        this.primaryProbability = primaryProbability;
        this.keyBitLength = keyBitLength;
    }

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

    private void GeneratePrimaryDigit(ref BigInteger? primaryDigit, ref bool findPrimary, Semaphore semRes,
        Mutex mutexRes, int byteLength)
    {
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

        byte[] tmpBytes = new byte[byteLength];
        RandomNumberGenerator generator = RandomNumberGenerator.Create();
        generator.GetNonZeroBytes(tmpBytes);
        BigInteger tmpPrimary = new BigInteger(tmpBytes, true);

        if (tmpPrimary.IsEven)
        {
            tmpPrimary += BigInteger.One;
        }

        bool alive = true;
        while (alive)
        {
            mutexRes.WaitOne();
            alive = !findPrimary;
            mutexRes.ReleaseMutex();
            if (findPrimary)
            {
                continue;
            }

            if (primaryTestImplementation.Test(tmpPrimary, primaryProbability))
            {
                mutexRes.WaitOne();
                if (!findPrimary)
                {
                    primaryDigit = tmpPrimary;
                    findPrimary = true;
                }

                mutexRes.ReleaseMutex();
                break;
            }
            else
            {
                tmpPrimary += 2;

                if (tmpPrimary % 5 == 0)
                {
                    tmpPrimary += 2;
                }
            }
        }

        semRes.Release();
    }


    private void GenerateG(ref BigInteger? g, BigInteger p, ref bool findG, Semaphore gSem, Mutex mutexG,
        int byteLength)
    {
        RandomNumberGenerator generator = RandomNumberGenerator.Create();
        byte[] gBytes = new byte[byteLength];
        generator.GetBytes(gBytes);
        BigInteger tmpG = new BigInteger(gBytes, true);

        bool alive = true;
        while (alive)
        {
            mutexG.WaitOne();
            alive = !findG;
            mutexG.ReleaseMutex();
            if (findG)
            {
                continue;
            }

            if (BigInteger.GreatestCommonDivisor(tmpG, p) == 1)
            {
                if (BigInteger.ModPow(tmpG, p - 1, p) == 1)
                {
                    mutexG.WaitOne();
                    if (!findG)
                    {
                        g = tmpG;
                        findG = true;
                    }

                    mutexG.ReleaseMutex();
                    break;
                }
            }

            tmpG += 1;
        }

        gSem.Release();
    }


    public (PrivateKey, PublicKey) GenerateKeys()
    {
        BigInteger p = FastGenerateDigit(GeneratePrimaryDigit, keyBitLength / 8);
        BigInteger g =
            FastGenerateDigit(
                delegate(ref BigInteger? g, ref bool findG, Semaphore semG, Mutex mutexG, int byteLength)
                {
                    GenerateG(ref g, p, ref findG, semG, mutexG, byteLength);
                }, keyBitLength / 8 - 3);


        RandomNumberGenerator generator = RandomNumberGenerator.Create();
        byte[] xBytes = new byte[p.GetByteCount() - 1
        ];
        BigInteger x;
        do
        {
            generator.GetNonZeroBytes(xBytes);
            x = new BigInteger(xBytes, true);
        } while (x < 2 || x >= (p - BigInteger.One));


        BigInteger y = BigInteger.ModPow(g, x, p);
        return (new PrivateKey
        {
            P = p,
            G = g,
            X = x
        }, new PublicKey
        {
            P = p,
            G = g,
            Y = y
        });
    }

    public EncryptedMessage Encrypt(BigInteger message, PublicKey publicKey)
    {
        RandomNumberGenerator generator = RandomNumberGenerator.Create();
        byte[] kBytes = new byte[publicKey.P.GetByteCount() - 1];
        BigInteger k;
        do
        {
            generator.GetNonZeroBytes(kBytes);
            k = new BigInteger(kBytes, true);
        } while (k < 2 || k >= (publicKey.P - BigInteger.One) ||
                 BigInteger.GreatestCommonDivisor(k, publicKey.P - BigInteger.One) != 1);


        return new EncryptedMessage
        {
            A = BigInteger.ModPow(publicKey.G, k, publicKey.P),

            B = (BigInteger.ModPow(publicKey.Y, k, publicKey.P) * message) % publicKey.P
        };
    }

    public BigInteger Decrypt(EncryptedMessage encryptedMessage, PrivateKey privateKey)
    {
        return (encryptedMessage.B *
                BigInteger.ModPow(BigInteger.ModPow(encryptedMessage.A, privateKey.X, privateKey.P), privateKey.P - 2,
                    privateKey.P)) % privateKey.P;
    }
}