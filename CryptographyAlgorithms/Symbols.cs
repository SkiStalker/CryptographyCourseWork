using System.Numerics;

namespace CryptographyAlgorithms;

public static class Symbols
{
    public static int LegendreSymbol(BigInteger a, BigInteger p)
    {
        if (a == BigInteger.One)
        {
            return 1;
        }

        if (a.IsEven)
        {
            return Convert.ToInt32(LegendreSymbol(a / 2, p) *
                                   BigIntegerTools.FastPower(-1, (p * p - 1) / 8));
        }

        if ((!a.IsEven) && (a != BigInteger.One))
        {
            return Convert.ToInt32(LegendreSymbol(p % a, a) *
                                   BigIntegerTools.FastPower(-1, (a - 1) * (p - 1) / 4));
        }

        return 0;
    }

    public static int JacobySymbol(BigInteger a, BigInteger b)
    {
        if (BigInteger.GreatestCommonDivisor(a, b) != BigInteger.One)
            return 0;

        int r = 1;

        if (a < BigInteger.Zero)
        {
            a = -a;
            if (b % 4 == 3)
                r = -r;
        }

        int t;

        while (true)
        {
            t = 0;
            while (a.IsEven)
            {
                t++;
                a /= 2;
            }

            if (t % 2 == 1)
            {
                if (b % 8 == 3 || b % 8 == 5)
                    r = -r;
            }

            if ((a % 4) == 3 && (b % 4) == 3)
            {
                r = -r;
            }

            BigInteger c = a;
            a = b % c;
            b = c;
            if (a == 0)
            {
                return r;
            }
        }
    }
}