using System.Numerics;
using System.Security.Cryptography;

namespace CryptographyAlgorithms;

public static class MathTools
{
    public static BigInteger FindNonTrivialUnityCube(BigInteger p)
    {
        RandomNumberGenerator rng = RandomNumberGenerator.Create();
        BigInteger p2 = BigIntegerTools.FastPower(p, 2);
        bool findRes = false;
        BigInteger d;
        byte[] dBytes = new byte[p2.GetByteCount() - 1];

        do
        {
            rng.GetNonZeroBytes(dBytes);
            d = new BigInteger(dBytes);
        } while (d < 2 || d >= p2);

        while (!findRes)
        {
            if (BigInteger.ModPow(d, 3, p2) == BigInteger.One && ((p * p + p + BigInteger.One) % p2 == 0))
            {
                findRes = true;
            }
            else
            {
                d = (d + BigInteger.One) % p2;

                if (d == BigInteger.One)
                {
                    d += BigInteger.One;
                }
            }
        }

        return d;
    }

    public static (BigInteger, BigInteger, BigInteger) SolveCubicEquationByMod(BigInteger a, BigInteger b, BigInteger d,
        BigInteger e, BigInteger mod)
    {
        BigInteger f1 = (3 * a * d - b * b) / (3 * a * a);
        BigInteger f0 = (27 * a * a * e - 9 * a * b * d + 2 * b * b * b) / (27 * a * a * a);

        BigInteger dr = f0 * f0 + (4 * f1 * f1 * f1) / 27;

        BigInteger r0 = (-f0 + BigIntegerTools.Sqrt(dr)) / 2;
        BigInteger r1 = (-f0 - BigIntegerTools.Sqrt(dr)) / 2;


        BigInteger u;
        BigInteger v;
        if (r0 == 0 && r1 == 0)
        {
            u = 0;
            v = 0;
        }
        else
        {
            u = BigIntegerTools.FindCubeRootAnswer(r1);
            v = -f1 / (3 * u);
        }

        BigInteger w = FindNonTrivialUnityCube(mod);
        return (u + v - b / (3 * a), u * w + v * w * w - b / (3 * a), u * w * w + v * w - b / (3 * a));
    }

    public static List<(BigInteger, BigInteger)> FactorizeDigit(BigInteger n)
    {
        List<BigInteger> tmpRes = new List<BigInteger>();

        while ((n % 2) == 0)
        {
            n = n / 2;
            tmpRes.Add(2);
        }

        BigInteger b = 3;
        BigInteger c = BigIntegerTools.Sqrt(n) + 1;
        while (b < c)
        {
            if ((n % b) == 0)
            {
                if (n / b * b - n == 0)
                {
                    tmpRes.Add(b);
                    n = n / b;
                    c = BigIntegerTools.Sqrt(n) + 1;
                }
                else
                    b += 2;
            }
            else
                b += 2;
        }

        List<(BigInteger, BigInteger)> res = new List<(BigInteger, BigInteger)>();
        foreach (var grp in tmpRes.GroupBy(item => item))
        {
            int count = grp.Count();
            res.Add((grp.Key, count));
        }

        return res;
    }
}