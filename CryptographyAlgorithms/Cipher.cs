using System.Numerics;

namespace CryptographyAlgorithms;

public class Cipher
{
    private readonly IEncrypting blockCryptAlg;
    private readonly CryptRule cryptRule;
    private readonly byte[]? initVector;
    private readonly AlgorithmType algorithmType;
    private readonly PaddingType paddingType;
    private readonly int bitBlockLength;

    public enum CryptRule
    {
        ECB,
        CBC,
        CFB,
        OFB,
        CTR,
        RD,
        RDH
    }


    public enum PaddingType
    {
        PKCS7,
        ISO_10126,
        ANSI_X_923
    }

    public enum AlgorithmType
    {
        SHACAL1
    }

    public static byte[] GenerateKey(int bitKeyLength)
    {
        if (bitKeyLength < 128 || bitKeyLength > 512)
        {
            throw new ArgumentException("Incorrect key bit length");
        }

        int sz = bitKeyLength / 8;
        byte[] key = new byte[sz];
        new Random().NextBytes(key);

        return key;
    }

    public static byte[] GenerateInitVector(int bitInitVectorLength)
    {
        if (bitInitVectorLength == 0 || bitInitVectorLength < 0 || bitInitVectorLength % 8 != 0)
        {
            throw new ArgumentException("Incorrect init vector bit length");
        }

        int sz = bitInitVectorLength / 8;
        byte[] initVector = new byte[sz];
        new Random().NextBytes(initVector);
        return initVector;
    }


    public Cipher(byte[] key, int bitBlockLength, AlgorithmType algorithmType, CryptRule cryptRule,
        PaddingType paddingType,
        byte[]? initVector = null)
    {
        if (key.Length == 0 || key.Length % 8 != 0)
        {
            throw new ArgumentException("Incorrect key length");
        }

        switch (algorithmType)
        {
            case AlgorithmType.SHACAL1:
            {
                SHACAL1 shacal1 = new SHACAL1();
                shacal1.SetKey(key);
                blockCryptAlg = shacal1;
                break;
            }
            default:
                throw new ArgumentException();
        }

        this.bitBlockLength = bitBlockLength;
        this.cryptRule = cryptRule;
        this.initVector = initVector;
        this.algorithmType = algorithmType;
        this.paddingType = paddingType;
    }

    public event Action<int, int> NotifyCryptProgress;

    private void ThreadCrypt(int i, byte[] tmpData, byte[] cryptData, int off, Semaphore semaphore,
        Func<byte[], byte[]> crypt)
    {
        int threadOff = i;
        byte[] threadTmpData = new byte[tmpData.Length];
        tmpData.CopyTo(threadTmpData, 0);
        byte[] threadCryptData = cryptData;
        new Thread(() =>
        {
            byte[] threadData = crypt(threadTmpData);


            for (int j = 0; j < threadData.Length; j++)
            {
                threadCryptData[j + threadOff + off] = threadData[j];
                NotifyCryptProgress?.Invoke(j + threadOff + off, threadCryptData.Length);
            }

            semaphore.Release();
        }).Start();
    }

    public void Encrypt(byte[] data, out byte[] encryptData)
    {
        bool multiThread = false;

        int blockLength = bitBlockLength / 8;

        int inputDataLength = data.Length;
        byte dataModLen = (byte)(blockLength - data.Length % (blockLength));
        int off = 0;
        BigInteger? delta = null;
        byte[] padding = new byte[dataModLen];
        byte[]? tmpInitVector = (byte[]?)initVector?.Clone();
        byte[] cryptData = Array.Empty<byte>();

        Random random = new Random();
        for (int i = 0; i < dataModLen; i++)
        {
            switch (paddingType)
            {
                case PaddingType.PKCS7:
                    padding[i] = dataModLen;
                    break;
                case PaddingType.ISO_10126:
                    if (i == dataModLen - 1)
                    {
                        padding[i] = dataModLen;
                    }
                    else
                    {
                        padding[i] = (byte)random.Next();
                    }

                    break;
                case PaddingType.ANSI_X_923:
                    if (i == dataModLen - 1)
                    {
                        padding[i] = dataModLen;
                    }
                    else
                    {
                        padding[i] = 0;
                    }

                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

        data = data.Concat(padding).ToArray();

        if (cryptRule == CryptRule.RD || cryptRule == CryptRule.RDH)
        {
            if (tmpInitVector == null)
            {
                throw new Exception("Null reference to init vector");
            }

            off = blockLength;
            encryptData = new byte[data.Length + blockLength];

            cryptData = blockCryptAlg.Encrypt(tmpInitVector);
            delta = new BigInteger(tmpInitVector
                .Take(new Range(tmpInitVector.Length / 2, tmpInitVector.Length))
                .ToArray());

            for (int i = 0; i < cryptData.Length; i++)
            {
                encryptData[i] = cryptData[i];
            }

            if (cryptRule == CryptRule.RDH)
            {
                if (tmpInitVector == null)
                {
                    throw new Exception("Null reference to init vector");
                }

                off = (blockLength) * 2;
                encryptData = new byte[data.Length + (blockLength) * 2];
                for (int i = 0; i < cryptData.Length; i++)
                {
                    encryptData[i] = cryptData[i];
                }

                byte[] hash = new byte[blockLength];
                for (int i = 0; i < inputDataLength; i++)
                {
                    hash[i % (blockLength)] ^= data[i];
                }

                for (int i = 0; i < hash.Length; i++)
                {
                    hash[i] ^= tmpInitVector[i];
                }

                cryptData = blockCryptAlg.Encrypt(hash);

                for (int i = 0; i < cryptData.Length; i++)
                {
                    encryptData[i + (blockLength)] = cryptData[i];
                }

                byte[] tmp = (new BigInteger(tmpInitVector) + delta).Value.ToByteArray() ??
                             throw new NullReferenceException();
                tmpInitVector = tmp.Skip((blockLength) - tmp.Length).ToArray();
            }
        }
        else
        {
            encryptData = new byte[data.Length];
        }

        Semaphore semaphore = new Semaphore(0, data.Length / blockLength);
        
        for (int i = 0; i < data.Length; i += blockLength)
        {
            byte[] tmpData = data.Take(new Range(i, i + blockLength)).ToArray() ??
                             throw new NullReferenceException();

            switch (cryptRule)
            {
                case CryptRule.ECB:
                {
                    multiThread = true;
                    ThreadCrypt(i, tmpData, encryptData, off, semaphore,
                        (localData) => blockCryptAlg.Encrypt(localData));
                    break;
                }
                case CryptRule.CBC:
                {
                    if (tmpInitVector == null)
                    {
                        throw new Exception("Null reference to init vector");
                    }


                    for (int k = 0; k < tmpData.Length; k++)
                    {
                        tmpData[k] ^= tmpInitVector[k];
                    }

                    cryptData = blockCryptAlg.Encrypt(tmpData);

                    tmpInitVector = cryptData;
                    break;
                }
                case CryptRule.CFB:
                {
                    if (tmpInitVector == null)
                    {
                        throw new Exception("Null reference to init vector");
                    }

                    cryptData = blockCryptAlg.Encrypt(tmpInitVector);

                    for (int k = 0; k < tmpData.Length; k++)
                    {
                        cryptData[k] ^= tmpData[k];
                    }

                    tmpInitVector = cryptData;

                    break;
                }
                case CryptRule.OFB:
                {
                    if (tmpInitVector == null)
                    {
                        throw new Exception("Null reference to init vector");
                    }

                    cryptData = blockCryptAlg.Encrypt(tmpInitVector);

                    cryptData.CopyTo(tmpInitVector, 0);

                    for (int k = 0; k < cryptData.Length; k++)
                    {
                        cryptData[k] ^= tmpData[k];
                    }

                    break;
                }
                case CryptRule.CTR:
                {
                    multiThread = true;
                    if (tmpInitVector == null)
                    {
                        throw new Exception("Null reference to init vector");
                    }


                    byte[] threadTmpInitVector = new byte[tmpInitVector.Length];
                    tmpInitVector.CopyTo(threadTmpInitVector, 0);
                    ThreadCrypt(i, tmpData, encryptData, off, semaphore, (localData) =>
                    {
                        byte[] threadCryptData = blockCryptAlg.Encrypt(threadTmpInitVector);
                        for (int k = 0; k < tmpData.Length; k++)
                        {
                            threadCryptData[k] ^= localData[k];
                        }

                        return threadCryptData;
                    });


                    byte[] tmp = (new BigInteger(tmpInitVector) + 1).ToByteArray();
                    tmpInitVector = tmp.Skip(blockLength - tmp.Length).ToArray();

                    break;
                }
                case CryptRule.RD:
                case CryptRule.RDH:
                {
                    multiThread = true;
                    if (tmpInitVector == null)
                    {
                        throw new Exception("Null reference to init vector");
                    }

                    if (delta == null)
                    {
                        throw new Exception("Null reference to delta");
                    }

                    byte[] threadTmpInitVector = new byte[tmpInitVector.Length];
                    tmpInitVector.CopyTo(threadTmpInitVector, 0);

                    ThreadCrypt(i, tmpData, encryptData, off, semaphore, (localData) =>
                    {
                        for (int k = 0; k < tmpData.Length; k++)
                        {
                            localData[k] ^= threadTmpInitVector[k];
                        }

                        return blockCryptAlg.Encrypt(localData);
                    });


                    byte[] tmp = (new BigInteger(tmpInitVector) + delta).Value.ToByteArray() ??
                                 throw new NullReferenceException();
                    tmpInitVector = tmp.Skip(blockLength - tmp.Length).ToArray();

                    break;
                }
            }

            if (!multiThread)
            {
                for (int j = 0; j < cryptData.Length; j++)
                {
                    encryptData[j + i + off] = cryptData[j];
                    NotifyCryptProgress?.Invoke(j + i + off, data.Length);
                }
            }
        }

        if (multiThread)
        {
            for (int i = 0; i < data.Length / blockLength; i++)
            {
                semaphore.WaitOne();
            }
        }
    }

    public void Decrypt(byte[] data, out byte[] decryptData)
    {
        bool multiThread = false;
        int blockLength = bitBlockLength / 8;

        byte[] cryptData = Array.Empty<byte>();
        byte[]? tmpInitVector = (byte[]?)initVector?.Clone();
        BigInteger? delta = null;
        int off = 0;
        byte[] hash = Array.Empty<byte>();
        if (cryptRule == CryptRule.RD)
        {
            off = -blockLength;
            decryptData = new byte[data.Length - blockLength];
        }
        else if (cryptRule == CryptRule.RDH)
        {
            off = -(2 * blockLength);
            decryptData = new byte[data.Length - blockLength * 2];
        }
        else
        {
            decryptData = new byte[data.Length];
        }

        Semaphore semaphore = new Semaphore(0, data.Length / blockLength);
        for (int i = 0; i < data.Length; i += blockLength)
        {
            byte[] tmpData = data.Take(new Range(i, i + blockLength)).ToArray() ??
                             throw new NullReferenceException();


            switch (cryptRule)
            {
                case CryptRule.ECB:
                {
                    multiThread = true;
                    ThreadCrypt(i, tmpData, decryptData, off, semaphore,
                        (localData) => blockCryptAlg.Decrypt(localData));
                    break;
                }
                case CryptRule.CBC:
                {
                    if (tmpInitVector == null)
                    {
                        throw new Exception("Null reference to init vector");
                    }

                    cryptData = blockCryptAlg.Decrypt(tmpData);

                    for (int k = 0; k < cryptData.Length; k++)
                    {
                        cryptData[k] ^= tmpInitVector[k];
                    }

                    tmpInitVector = tmpData;
                    break;
                }
                case CryptRule.CFB:
                {
                    if (tmpInitVector == null)
                    {
                        throw new Exception("Null reference to init vector");
                    }

                    cryptData = blockCryptAlg.Encrypt(tmpInitVector);

                    for (int k = 0; k < tmpData.Length; k++)
                    {
                        cryptData[k] ^= tmpData[k];
                    }

                    tmpInitVector = tmpData;
                    break;
                }
                case CryptRule.OFB:
                {
                    if (tmpInitVector == null)
                    {
                        throw new Exception("Null reference to init vector");
                    }

                    cryptData = blockCryptAlg.Encrypt(tmpInitVector);

                    cryptData.CopyTo(tmpInitVector, 0);

                    for (int k = 0; k < cryptData.Length; k++)
                    {
                        cryptData[k] ^= tmpData[k];
                    }

                    break;
                }
                case CryptRule.CTR:
                {
                    multiThread = true;
                    if (tmpInitVector == null)
                    {
                        throw new Exception("Null reference to init vector");
                    }

                    byte[] threadTmpInitVector = new byte[tmpInitVector.Length];
                    tmpInitVector.CopyTo(threadTmpInitVector, 0);
                    ThreadCrypt(i, tmpData, decryptData, off, semaphore, (localData) =>
                    {
                        byte[] threadCryptData = blockCryptAlg.Encrypt(threadTmpInitVector);
                        for (int k = 0; k < tmpData.Length; k++)
                        {
                            threadCryptData[k] ^= localData[k];
                        }

                        return threadCryptData;
                    });

                    byte[] tmp = (new BigInteger(tmpInitVector) + 1).ToByteArray();
                    tmpInitVector = tmp.Skip(blockLength - tmp.Length).ToArray();
                    break;
                }
                case CryptRule.RD:
                {
                    multiThread = true;
                    if (i == 0)
                    {
                        tmpInitVector = blockCryptAlg.Decrypt(tmpData);
                        semaphore.Release();
                        delta = new BigInteger(tmpInitVector
                            .Take(new Range(tmpInitVector.Length / 2, tmpInitVector.Length))
                            .ToArray());
                    }
                    else
                    {
                        if (tmpInitVector == null)
                        {
                            throw new Exception("Null reference to init vector");
                        }

                        if (delta == null)
                        {
                            throw new Exception("Null reference to delta");
                        }

                        byte[] threadTmpInitVector = new byte[tmpInitVector.Length];
                        tmpInitVector.CopyTo(threadTmpInitVector, 0);

                        ThreadCrypt(i, tmpData, decryptData, off, semaphore, (localData) =>
                        {
                            byte[] threadDecryptData = blockCryptAlg.Decrypt(localData);
                            
                            for (int k = 0; k < tmpData.Length; k++)
                            {
                                threadDecryptData[k] ^= threadTmpInitVector[k];
                            }

                            return threadDecryptData;
                        });
                        
                        byte[] tmp = (new BigInteger(tmpInitVector) + delta).Value.ToByteArray() ??
                                     throw new NullReferenceException();
                        tmpInitVector = tmp.Skip(8 - tmp.Length).ToArray();
                    }

                    break;
                }
                case CryptRule.RDH:
                {
                    multiThread = true;
                    if (i == 0)
                    {
                        tmpInitVector = blockCryptAlg.Decrypt(tmpData);
                        semaphore.Release();
                        delta = new BigInteger(tmpInitVector
                            .Take(new Range(tmpInitVector.Length / 2, tmpInitVector.Length))
                            .ToArray());
                    }
                    else if (i == blockLength)
                    {
                        if (tmpInitVector == null)
                        {
                            throw new Exception("Null reference to init vector");
                        }

                        hash = blockCryptAlg.Decrypt(tmpData);
                        semaphore.Release();
                        for (int k = 0; k < tmpData.Length; k++)
                        {
                            hash[k] ^= tmpInitVector[k];
                        }

                        byte[] tmp = (new BigInteger(tmpInitVector) + delta)?.ToByteArray() ??
                                     throw new NullReferenceException();
                        tmpInitVector = tmp.Skip(blockLength - tmp.Length).ToArray();
                    }
                    else
                    {
                        if (tmpInitVector == null)
                        {
                            throw new Exception("Null reference to init vector");
                        }

                        if (delta == null)
                        {
                            throw new Exception("Null reference to delta");
                        }

                        byte[] threadTmpInitVector = new byte[tmpInitVector.Length];
                        tmpInitVector.CopyTo(threadTmpInitVector, 0);

                        ThreadCrypt(i, tmpData, decryptData, off, semaphore, (localData) =>
                        {
                            byte[] threadDecryptData = blockCryptAlg.Decrypt(localData);
                            
                            for (int k = 0; k < tmpData.Length; k++)
                            {
                                threadDecryptData[k] ^= threadTmpInitVector[k];
                            }

                            return threadDecryptData;
                        });

                        byte[] tmp = (new BigInteger(tmpInitVector) + delta).Value.ToByteArray() ??
                                     throw new NullReferenceException();
                        tmpInitVector = tmp.Skip(blockLength - tmp.Length).ToArray();
                    }

                    break;
                }
            }

            if (!multiThread)
            {
                for (int j = 0; j < cryptData.Length; j++)
                {
                    decryptData[j + i + off] = cryptData[j];
                    NotifyCryptProgress?.Invoke(j + i + off, data.Length);
                }
            }
        }

        if (multiThread)
        {
            for (int i = 0; i < data.Length / blockLength; i++)
            {
                semaphore.WaitOne();
            }
        }
        

        int paddingLen = decryptData.Last();
        decryptData = decryptData.Take(decryptData.Length - paddingLen).ToArray();

        if (cryptRule == CryptRule.RDH)
        {
            byte[] tmpHash = new byte[blockLength];
            for (int i = 0; i < decryptData.Length; i++)
            {
                tmpHash[i % blockLength] ^= decryptData[i];
            }

            for (int i = 0; i < tmpHash.Length; i++)
            {
                if (tmpHash[i] != hash[i])
                {
                    throw new InvalidDataException();
                }
            }
        }
    }

    public void Encrypt(string inputFile, string outputFile)
    {
        byte[] data = File.ReadAllBytes(inputFile);
        Encrypt(data, out byte[] res);
        File.WriteAllBytes(outputFile, res);
    }

    public void Decrypt(string inputFile, string outputFile)
    {
        byte[] data = File.ReadAllBytes(inputFile);
        Decrypt(data, out byte[] res);
        File.WriteAllBytes(outputFile, res);
    }
}