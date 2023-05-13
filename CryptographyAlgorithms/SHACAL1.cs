namespace CryptographyAlgorithms;

public class SHACAL1 : IEncrypting
{
    private byte[] key = Array.Empty<byte>();


    private readonly Func<uint, uint, uint, uint>[] fs = new Func<uint, uint, uint, uint>[]
    {
        (x, y, z) => (x & y) | (~x & z),
        (x, y, z) => x ^ y ^ z,
        (x, y, z) => (x & y) | (x & z) | (y & z),
        (x, y, z) => x ^ y ^ z
    };

    private readonly uint[] m = new uint[] { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };

    private uint CyclicLeftShift(uint d, int n)
    {
        return (d << n) | (d >> (32 - n));
    }

    private uint CyclicRightShift(uint d, int n)
    {
        return (d >> n) | (d << (32 - n));
    }

    private uint ApplyF(uint x, uint y, uint z, int roundNumber)
    {
        return fs[roundNumber / 20](x, y, z);
    }

    private uint GetM(int roundNumber)
    {
        return m[roundNumber / 20];
    }

    private uint[] ExpandKey()
    {
        uint[] roundKeys = new uint[80];
        for (int i = 0; i < 16; i++)
        {
            roundKeys[i] = (uint)((key[i] << 24) | (key[i + 1] << 16) | (key[i + 2] << 8) | key[i + 3]);
        }

        for (int i = 16; i < 80; i++)
        {
            roundKeys[i] =
                CyclicLeftShift((roundKeys[i - 3] ^ roundKeys[i - 8] ^ roundKeys[i - 14] ^ roundKeys[i - 16]), 1);
        }

        return roundKeys;
    }

    private uint SmartCast(long d)
    {
        return (uint)d;
    }
    
    public byte[] Encrypt(byte[] data)
    {
        if (data.Length != 20)
        {
            throw new ArgumentException("Incorrect data length");
        }

        uint[] tmpRes = new uint[5];

        for (int i = 0; i < data.Length; i += 4)
        {
            tmpRes[i / 4] = (uint)((data[i] << 24) | (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3]);
        }

        uint[] k = ExpandKey();

        (uint a, uint b, uint c, uint d, uint e) = (tmpRes[0], tmpRes[1], tmpRes[2], tmpRes[3], tmpRes[4]);
        
        for (int i = 0; i < 80; i++)
        {
            (
                    a,
                    b,
                    c,
                    d,
                    e
                )
                = (
                    k[i] + CyclicLeftShift(a, 5) + ApplyF(b, c, d, i) +
                    e + GetM(i),
                    a,
                    CyclicLeftShift(b, 30),
                    c,
                    d
                );
        }

        (tmpRes[0], tmpRes[1], tmpRes[2], tmpRes[3], tmpRes[4]) = (a, b, c, d, e);

        byte[] res = new byte[20];
        for (int i = 0; i < res.Length; i++)
        {
            res[i] = (byte)(tmpRes[i / 4] >> (24 - 8 * (i % 4)));
        }

        return res;
    }

    public byte[] Decrypt(byte[] data)
    {
        if (data.Length != 20)
        {
            throw new ArgumentException("Incorrect data length");
        }

        uint[] tmpRes = new uint[5];

        for (int i = 0; i < data.Length; i+=4)
        {
            tmpRes[i / 4] = (uint)((data[i] << 24) | (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3]);
        }


        (uint a, uint b, uint c, uint d, uint e) = (tmpRes[0], tmpRes[1], tmpRes[2], tmpRes[3], tmpRes[4]);

        uint[] k = ExpandKey();

        for (int i = 79; i > -1; i--)
        {
            (
                    a,
                    b,
                    c,
                    d,
                    e
                )
                = (
                    b,
                    CyclicRightShift(c, 30),
                    d,
                    e,
                    a - k[i] - CyclicLeftShift(b, 5) -
                          ApplyF(CyclicRightShift(c, 30), d, e, i) -
                     GetM(i)
                );
        }

        (tmpRes[0], tmpRes[1], tmpRes[2], tmpRes[3], tmpRes[4]) = (a, b, c, d, e);

        byte[] res = new byte[20];
        for (int i = 0; i < res.Length; i++)
        {
            res[i] = (byte)(tmpRes[i / 4] >> (24 - 8 * (i % 4)));
        }

        return res;
    }

    public void SetKey(byte[] keyBytes)
    {
        if (keyBytes.Length < 16 || keyBytes.Length > 64)
        {
            throw new ArgumentException("Incorrect key length");
        }

        if (keyBytes.Length < 64)
        {
            this.key = new byte[64];
            keyBytes.CopyTo(key, 0);
        }
        else
        {
            this.key = keyBytes;
        }
    }
}