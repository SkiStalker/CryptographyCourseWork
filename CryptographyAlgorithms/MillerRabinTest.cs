using System.Numerics;
using System.Security.Cryptography;

namespace CryptographyAlgorithms;

public class MillerRabinTest : IPrimaryTest
{
    public bool Test(BigInteger d, double primaryProbability)
    {
        if (primaryProbability < 0.5 || primaryProbability >= 1)
        {
            throw new ArgumentException("Incorrect probability");
        }

        double k = 0.5 * Math.Log2(1 / (1 - primaryProbability));
        if (Math.Abs(k - (int)k) > 0)
        {
            k++;
            k = Math.Round(k);
        }

        if (d == 2 || d == 3)
            return true;

        if (d < 2 || d % 2 == 0)
            return false;

        BigInteger t = d - 1;

        int s = 0;

        while (t % 2 == 0)
        {
            t /= 2;
            s += 1;
        }

        for (int i = 0; i < k; i++)
        {
            RandomNumberGenerator rng = RandomNumberGenerator.Create();

            byte[] tA = new byte[d.ToByteArray().LongLength];

            BigInteger a;

            do
            {
                rng.GetBytes(tA);
                a = new BigInteger(tA);
            } while (a < 2 || a >= d - 2);

            BigInteger x = BigInteger.ModPow(a, t, d);

            if (x == 1 || x == d - 1)
                continue;

            for (int r = 1; r < s; r++)
            {
                x = BigInteger.ModPow(x, 2, d);

                if (x == 1)
                    return false;

                if (x == d - 1)
                    break;
            }

            if (x != d - 1)
                return false;
        }

        return true;
    }
}