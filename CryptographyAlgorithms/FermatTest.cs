using System.Numerics;
using System.Security.Cryptography;

namespace CryptographyAlgorithms;

public class FermatTest : IPrimaryTest
{
    public bool Test(BigInteger d, double primaryProbability)
    {
        if (primaryProbability < 0.5 || primaryProbability >= 1)
        {
            throw new ArgumentException("Incorrect probability");
        }

        double k = Math.Log(1 - primaryProbability);
        if (Math.Abs(k - (int)k) > 0)
        {
            k++;
            k = Math.Round(k);
        }

        if (d == BigInteger.One)
        {
            return false;
        }

        if (d.IsEven)
        {
            return false;
        }

        RandomNumberGenerator generator = RandomNumberGenerator.Create();
        byte[] tmpBytes = new byte[d.GetByteCount()];
        for (int i = 0; i < k; i++)
        {
            generator.GetNonZeroBytes(tmpBytes);
            BigInteger tmpRand = new BigInteger(tmpBytes, true);
            BigInteger res = tmpRand % (d - 2) + BigInteger.One;
            if (BigInteger.ModPow(res, d - BigInteger.One, d) != BigInteger.One)
            {
                return false;
            }
        }

        return true;
    }
}