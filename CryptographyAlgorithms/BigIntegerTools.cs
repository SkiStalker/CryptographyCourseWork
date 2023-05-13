using System.Numerics;

namespace CryptographyAlgorithms;

public static class BigIntegerTools
{
    public static BigInteger FindCubeRootAnswer(BigInteger number)
    {
        BigInteger min = 0, max = number, middle = 0;

        while (min <= max)
        {
            middle = (min + max) / 2;

            BigInteger cubeRoot = middle * middle * middle;

            if (cubeRoot == number)
            {
                break;
            }
            else if (cubeRoot > number)
            {
                max = middle - 1;
            }
            else
            {
                min = middle + 1;
            }
        }

        return middle;
    }

    public static BigInteger FastPower(BigInteger x, BigInteger n)
    {
        BigInteger pw = new BigInteger(n.ToByteArray(), true);
        BigInteger num = new BigInteger(x.ToByteArray(), true);


        BigInteger result = BigInteger.One;
        
        
        while (pw > 0)
        {
            if (pw.IsEven)
            {
                num = BigInteger.Multiply(num, num);;
                pw >>= 1;
            }
            else
            {
                
                result = BigInteger.Multiply(result, num);
                pw -= BigInteger.One;
            }
        }

        return result;
    }

    public static BigInteger GcdEx(BigInteger a, BigInteger b, out BigInteger x, out BigInteger y)
    {
        if (b < a)
        {
            (a, b) = (b, a);
        }

        if (a == 0)
        {
            x = 0;
            y = 1;
            return b;
        }

        BigInteger gcd = GcdEx(b % a, a, out x, out y);

        BigInteger newY = x;
        BigInteger newX = y - (b / a) * x;

        x = newX;
        y = newY;
        return gcd;
    }

    public static BigInteger Sqrt(BigInteger n)
    {
        if (n == 0) return 0;
        if (n > 0)
        {
            int bitLength = Convert.ToInt32(Math.Ceiling(BigInteger.Log(n, 2)));
            BigInteger root = BigInteger.One << (bitLength / 2);

            while (!IsSqrt(n, root))
            {
                root += n / root;
                root /= 2;
            }

            return root;
        }

        throw new ArithmeticException("NaN");
    }

    private static bool IsSqrt(BigInteger n, BigInteger root)
    {
        BigInteger lowerBound = root * root;
        BigInteger upperBound = (root + 1) * (root + 1);

        return (n >= lowerBound && n < upperBound);
    }
}