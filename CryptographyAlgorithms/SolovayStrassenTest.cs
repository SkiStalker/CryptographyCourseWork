using System.Numerics;
using System.Security.Cryptography;

namespace CryptographyAlgorithms;

public class SolovayStrassenTest : IPrimaryTest
{
    public bool Test(BigInteger d, double primaryProbability)
    {
        if (primaryProbability < 0.5 || primaryProbability >= 1)
        {
            throw new ArgumentException("Incorrect probability");
        }

        double k = Math.Log2(1 / (1 - primaryProbability));
        if (Math.Abs(k - (int)k) > 0)
        {
            k++;
            k = Math.Round(k);
        }

        if (d < 2)
            return false;

        if (d.IsEven)
            return false;

        RandomNumberGenerator generator = RandomNumberGenerator.Create();
        byte[] tmpBytes = new byte[d.GetByteCount()];

        for (int i = 0; i < k; i++)
        {
            generator.GetNonZeroBytes(tmpBytes);
            BigInteger tmpRand = new BigInteger(tmpBytes, true);

            BigInteger a = tmpRand % (d - BigInteger.One) + BigInteger.One;

            if (a < 2)
                a += 2;

            if (BigInteger.GreatestCommonDivisor(a, d) > 1)
                return false;

            int sj = Symbols.JacobySymbol(a, d);
            BigInteger fa = BigInteger.ModPow(a, (d - 1) / 2, d);

            if (sj == 1)
            {
                if (fa != sj)
                    return false;
            }
            else if (sj == -1)
            {
                if (fa != d - 1)
                    return false;
            }
        }

        return true;
    }
}