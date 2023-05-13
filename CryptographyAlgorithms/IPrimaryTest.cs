using System.Numerics;

namespace CryptographyAlgorithms;

public interface IPrimaryTest
{
    public bool Test(BigInteger d, double primaryProbability);
}