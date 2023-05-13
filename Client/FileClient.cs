using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CryptographyAlgorithms;

namespace Client;

public class FileClient
{
    private enum Operation : byte
    {
        GetFilesList = 1,
        UploadFile,
        DownloadFile,
        UpdateFile,
        CloseConnection
    }

    private enum OperationStatus : byte
    {
        Success,
        Error
    }

    private readonly TcpClient client;
    private BinaryReader? reader;
    private BinaryWriter? writer;
    private Cipher? cipher;
    private readonly UTF8Encoding encoder;

    public FileClient()
    {
        client = new TcpClient();
        encoder = new UTF8Encoding();
        reader = null;
        writer = null;
        cipher = null;
    }

    private XTR.PublicKey ReadPublicKey()
    {
        if (reader == null || writer == null)
        {
            throw new NullReferenceException();
        }
        
        int yLength = reader.ReadInt32();
        byte[] y = reader.ReadBytes(yLength);
        int gLength = reader.ReadInt32();
        byte[] g = reader.ReadBytes(gLength);
        int pLength = reader.ReadInt32();
        byte[] p = reader.ReadBytes(pLength);

        return new XTR.PublicKey
        {
            P = new BigInteger(p, true),
            G = new BigInteger(g, true),
            Y = new BigInteger(y, true)
        };
    }

    private void WriteAsymmetricData(byte[] data, XTR xtr, XTR.PublicKey publicKey)
    {
        if (reader == null || writer == null)
        {
            throw new NullReferenceException();
        }
        
        XTR.EncryptedMessage asymmetricData = xtr.Encrypt(new BigInteger(data, true), publicKey);

        int aLength = asymmetricData.A.GetByteCount();
        writer.Write(aLength);
        writer.Write(asymmetricData.A.ToByteArray());
        
        int bLength = asymmetricData.B.GetByteCount();
        writer.Write(bLength);
        writer.Write(asymmetricData.B.ToByteArray());
        
    }
    
    public void Connect(string ip, int port)
    {
        try
        {
            client.Connect(IPAddress.Parse(ip), port);
            NetworkStream ns = client.GetStream();

            reader = new BinaryReader(ns);
            writer = new BinaryWriter(ns);

            XTR xtr = new XTR(640, XTR.PrimaryTest.MillerRabin, 0.9);

            XTR.PublicKey publicKey = ReadPublicKey();

            byte[] sessionKey = Cipher.GenerateKey(512);
            
            
            WriteAsymmetricData(sessionKey, xtr, publicKey);
            
            byte[] iv = Cipher.GenerateInitVector(160);
            
            
            WriteAsymmetricData(iv, xtr, publicKey);

            cipher = new Cipher(sessionKey, 160, Cipher.AlgorithmType.SHACAL1, Cipher.CryptRule.RD,
                Cipher.PaddingType.PKCS7, iv);

            if ((OperationStatus)reader.ReadByte() != OperationStatus.Success)
            {
                throw new Exception("Failure key exchange");
            }
        }
        catch (Exception)
        {
            reader = null;
            writer = null;
            cipher = null;
            throw;
        }
    }

    private OperationStatus ReadOperationStatus()
    {
        return (OperationStatus)ReadData()[0];
    }

    private Operation ReadOperation()
    {
        return (Operation)ReadData()[0];
    }

    private void WriteOperation(Operation op)
    {
        WriteData(new byte[] { (byte)op });
    }

    private void WriteOperationStatus(OperationStatus status)
    {
        WriteData(new byte[] { (byte)status });
    }

    private byte[] ReadData()
    {
        if (reader == null || writer == null || cipher == null)
        {
            throw new NullReferenceException();
        }

        int encryptDataLength = reader.ReadInt32();
        byte[] encryptData = reader.ReadBytes(encryptDataLength);

        cipher.Decrypt(encryptData, out byte[] data);
        return data;
    }

    private void WriteData(byte[] data)
    {
        if (reader == null || writer == null || cipher == null)
        {
            throw new NullReferenceException();
        }

        cipher.Encrypt(data, out byte[] encryptData);

        writer.Write(encryptData.Length);
        writer.Write(encryptData);
    }

    private string ReadString()
    {
        return encoder.GetString(ReadData());
    }

    private void WriteString(string str)
    {
        WriteData(encoder.GetBytes(str));
    }


    private bool AbstractOperation(Operation op, out string? answer, Action concreteOperation)
    {
        WriteOperation(op);

        if (ReadOperation() != op)
        {
            answer = ReadString();
            return false;
        }

        if (ReadOperationStatus() != OperationStatus.Success)
        {
            answer = ReadString();
            return false;
        }
        else
        {
            answer = ReadString();
            concreteOperation();

            return true;
        }
    }

    public bool GetFilesList(out string[]? filesList, out string? answer)
    {
        filesList = null;
        string[]? localFilesList = filesList;

        bool res = AbstractOperation(Operation.GetFilesList, out answer,
            () => { localFilesList = encoder.GetString(ReadData()).Split(","); });
        filesList = localFilesList;
        return res;
    }

    public bool DownloadFile(string fileName, out byte[]? data, out string? answer)
    {
        data = null;
        byte[]? localData = data;


        bool res = AbstractOperation(Operation.DownloadFile, out answer, () => { localData = ReadData(); });

        data = localData;
        return res;
    }

    public bool UploadFile(string fileName, byte[] data, out string? answer)
    {
        return AbstractOperation(Operation.UploadFile, out answer, () =>
        {
            WriteString(Path.GetFileName(fileName));
            WriteData(File.ReadAllBytes(fileName));
        });
    }

    public bool UpdateFile(string fileName, byte[] data, out string? answer)
    {
        return AbstractOperation(Operation.UpdateFile, out answer, () =>
        {
            WriteString(Path.GetFileName(fileName));
            WriteData(File.ReadAllBytes(fileName));
        });
    }

    public bool CloseConnection(out string? answer)
    {
        return AbstractOperation(Operation.CloseConnection, out answer, () => { });
    }
}