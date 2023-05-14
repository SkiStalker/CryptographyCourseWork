using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text;
using CryptographyAlgorithms;

namespace Client;

public class FileClient : IDisposable
{
    private enum Operation : byte
    {
        GetFilesList = 1,
        UploadFile,
        DownloadFile,
        UpdateFile,
        CloseConnection,
        DeleteFile
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


    public void AddCryptCallback(Action<int, int> callback)
    {
        if (cipher != null)
        {
            cipher.NotifyCryptProgress += callback;
        }
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
        writer.Flush();
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
        writer.Flush();
    }

    private string ReadString()
    {
        return encoder.GetString(ReadData());
    }

    private void WriteString(string str)
    {
        WriteData(encoder.GetBytes(str));
    }


    private bool AbstractOperation(Operation op, out string? answer, Action initOperation, Action invokeOperation)
    {
        try
        {
            WriteOperation(op);

            if (ReadOperation() != op)
            {
                answer = ReadString();
                return false;
            }

            initOperation();

            if (ReadOperationStatus() != OperationStatus.Success)
            {
                answer = ReadString();
                return false;
            }
            else
            {
                answer = ReadString();
                invokeOperation();
                return true;
            }
        }
        catch
        {
            answer = "Internal server error";
            return false;
        }
    }

    public bool DeleteFile(string fileName, out string? answer)
    {
        return AbstractOperation(Operation.DeleteFile, out answer, () => { WriteString(fileName); }, () => { });
    }

    public bool GetFilesList(out string[]? filesList, out string? answer)
    {
        filesList = null;
        string[]? localFilesList = filesList;

        bool res = AbstractOperation(Operation.GetFilesList, out answer, () => { },
            () =>
            {
                localFilesList = encoder.GetString(ReadData()).Split(",");
                WriteOperationStatus(OperationStatus.Success);
            });
        filesList = localFilesList;
        return res;
    }

    public bool DownloadFile(string fileName, out byte[]? data, out string? answer)
    {
        data = null;
        byte[]? localData = data;
        bool res = AbstractOperation(Operation.DownloadFile, out answer,
            () => { WriteString(Path.GetFileName(fileName)); }, () =>
            {
                localData = ReadData();
                WriteOperationStatus(OperationStatus.Success);
            });

        data = localData;
        return res;
    }

    public bool UploadFile(string fileName, byte[] data, out string? answer)
    {
        return AbstractOperation(Operation.UploadFile, out answer, () => { WriteString(Path.GetFileName(fileName)); },
            () => { WriteData(data); });
    }

    public bool UpdateFile(string fileName, byte[] data, out string? answer)
    {
        return AbstractOperation(Operation.UpdateFile, out answer, () => { WriteString(Path.GetFileName(fileName)); },
            () => { WriteData(data); });
    }

    public bool CloseConnection(out string? answer)
    {
        return AbstractOperation(Operation.CloseConnection, out answer, () => { }, () => { });
    }

    public void Dispose()
    {
        client.Close();
        client.Dispose();
        reader?.Close();
        reader?.Dispose();
        writer?.Close();
        writer?.Dispose();
    }
}