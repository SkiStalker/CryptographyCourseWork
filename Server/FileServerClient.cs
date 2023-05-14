using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using CryptographyAlgorithms;

namespace Server;

public class FileServerClient
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
    private readonly Config config;
    private readonly UTF8Encoding encoder;

    public IPEndPoint? GetIpEndPoint()
    {
        return client.Client.RemoteEndPoint as IPEndPoint;
    }

    public FileServerClient(TcpClient tcpClient, Config config)
    {
        client = tcpClient;
        this.config = config;
        encoder = new UTF8Encoding();
    }

    private bool CorrectFileName(string fileName)
    {
        char[] incorrectChars = Path.GetInvalidFileNameChars();
        foreach (char c in fileName)
        {
            if (incorrectChars.Contains(c))
                return false;
        }
        
        return true;
    }

    private string MakeUniqueFileName(string fileName)
    {
        if (File.Exists($"{config.RootPath}/{fileName}"))
        {
            int i = 1;
            string tmpFilename = Path.GetFileNameWithoutExtension(fileName);
            string ext = Path.GetExtension(fileName);

            while (File.Exists($"{config.RootPath}{tmpFilename}_{i}{ext}"))
            {
                ext += 1;
            }

            return $"{tmpFilename}_{i}{ext}";
        }
        else
        {
            return fileName;
        }
    }

    private void Logging(string msg)
    {
        IPEndPoint? endPoint = GetIpEndPoint();
        if (endPoint != null)
        {
            Console.WriteLine($"Client with ip: {endPoint.Address} and port:{endPoint.Port} - {msg}");
        }
        else
        {
            Console.WriteLine(msg);
        }
    }
    private string ReadString(BinaryReader reader, Cipher cipher)
    {
        return encoder.GetString(ReadData(reader, cipher));
    }


    private void WriteString(string str, BinaryWriter writer, Cipher cipher)
    {
        byte[] answerBytes = encoder.GetBytes(str);

        cipher.Encrypt(answerBytes, out byte[] encryptData);

        writer.Write(encryptData.Length);
        writer.Write(encryptData);
    }


    private void WriteOperationStatus(OperationStatus status, BinaryWriter writer, Cipher cipher)
    {
        WriteData(new byte[] { (byte)status }, writer, cipher);
    }

    private OperationalStatus ReadOperationStatus(BinaryReader reader, Cipher cipher)
    {
        return (OperationalStatus)ReadData(reader, cipher)[0];
    }

    private void WriteOperation(Operation op, BinaryWriter writer, Cipher cipher)
    {
        WriteData(new byte[] { (byte)op }, writer, cipher);
    }

    private Operation ReadOperation(BinaryReader reader, Cipher cipher)
    {
        return (Operation)ReadData(reader, cipher)[0];
    }

    private void WriteData(byte[] data, BinaryWriter writer, Cipher cipher)
    {
        cipher.Encrypt(data, out byte[] encryptData);

        writer.Write(encryptData.Length);
        writer.Write(encryptData);
    }

    private byte[] ReadData(BinaryReader reader, Cipher cipher)
    {
        int encryptDataLength = reader.ReadInt32();
        byte[] encryptData = reader.ReadBytes(encryptDataLength);
        cipher.Decrypt(encryptData, out byte[] data);
        return data;
    }


    private void WritePartPublicKey(BigInteger part, BinaryWriter writer)
    {
        int partBytesLength = part.GetByteCount();
        writer.Write(partBytesLength);
        writer.Write(part.ToByteArray());
    }

    private byte[] ReadAsymmetricData(BinaryReader reader, XTR xtr, XTR.PrivateKey privateKey)
    {
        int encryptALength = reader.ReadInt32();
        byte[] encryptA = reader.ReadBytes(encryptALength);
        int encryptBLength = reader.ReadInt32();
        byte[] encryptB = reader.ReadBytes(encryptBLength);

        BigInteger res = xtr.Decrypt(new XTR.EncryptedMessage()
            { A = new BigInteger(encryptA, true), B = new BigInteger(encryptB, true) }, privateKey);


        byte[] resBytes = res.ToByteArray();
        
        Array.Resize(ref resBytes, (int)Math.Ceiling(res.GetBitLength() / 8.0));
        return resBytes;
    }

    public void Process()
    {
        using NetworkStream stream = client.GetStream();
        using BinaryReader reader = new BinaryReader(stream);
        using BinaryWriter writer = new BinaryWriter(stream);
        bool alive = true;

        XTR xtr = new XTR(640, XTR.PrimaryTest.MillerRabin, 0.9);
        (XTR.PrivateKey privateKey, XTR.PublicKey publicKey) = xtr.GenerateKeys();
        
        
        WritePartPublicKey(publicKey.Y, writer);
        WritePartPublicKey(publicKey.G, writer);
        WritePartPublicKey(publicKey.P, writer);
        writer.Flush();


        byte[] sessionKey = ReadAsymmetricData(reader, xtr, privateKey);

        byte[] iv = ReadAsymmetricData(reader, xtr, privateKey);

        Cipher cipher = new Cipher(sessionKey, 160, Cipher.AlgorithmType.SHACAL1, Cipher.CryptRule.RD,
            Cipher.PaddingType.PKCS7, iv);
        

        while (alive)
        {
            Operation op = ReadOperation(reader, cipher);

            switch (op)
            {
                case Operation.GetFilesList:
                {
                    WriteOperation(Operation.GetFilesList, writer, cipher);

                    WriteOperationStatus(OperationStatus.Success, writer, cipher);

                    WriteString("Read files list permitted", writer, cipher);
                    writer.Flush();
                    string[] files = Directory.GetFiles(config.RootPath);

                    IEnumerable<string?> suitFiles = files.Where(File.Exists).Select(Path.GetFileName);
                    string fileNames = string.Join(",", suitFiles);

                    WriteData(encoder.GetBytes(fileNames), writer, cipher);
                    ReadOperationStatus(reader, cipher);
                    break;
                }
                case Operation.CloseConnection:
                {
                    WriteOperation(Operation.CloseConnection, writer, cipher);
                    WriteOperationStatus(OperationStatus.Success, writer, cipher);
                    WriteString("Close connection permitted", writer, cipher);
                    writer.Flush();
                    alive = false;
                    break;
                }
                case Operation.DeleteFile:
                {
                    WriteOperation(Operation.DeleteFile, writer, cipher);
                    string fileName = ReadString(reader, cipher);
                    if (File.Exists($"{config.RootPath}/{fileName}"))
                    {
                        WriteOperationStatus(OperationStatus.Success, writer, cipher);
                        WriteString($"Delete file {fileName} permitted", writer, cipher);
                        writer.Flush();
                        File.Delete(Path.GetFullPath($"{config.RootPath}/{fileName}"));
                    }
                    else
                    {
                        WriteOperationStatus(OperationStatus.Error, writer, cipher);
                        WriteString($"File with name {fileName} is not exist", writer, cipher);
                        writer.Flush();
                    }
                    
                    break;
                }
                case Operation.DownloadFile:
                {
                    WriteOperation(Operation.DownloadFile, writer, cipher);
                    string fileName = ReadString(reader, cipher);
                    if (File.Exists($"{config.RootPath}/{fileName}"))
                    {
                        WriteOperationStatus(OperationStatus.Success, writer, cipher);
                        WriteString($"Download file {fileName} permitted", writer, cipher);
                        WriteData(File.ReadAllBytes(Path.GetFullPath($"{config.RootPath}/{fileName}")), writer, cipher);
                        writer.Flush();
                        ReadOperationStatus(reader, cipher);
                    }
                    else
                    {
                        WriteOperationStatus(OperationStatus.Error, writer, cipher);
                        WriteString($"File with name {fileName} is not exist", writer, cipher);
                        writer.Flush();
                    }

                    break;
                }
                case Operation.UpdateFile:
                {
                    WriteOperation(Operation.UpdateFile, writer, cipher);

                    string fileName = ReadString(reader, cipher);

                    if (File.Exists($"{config.RootPath}/{fileName}"))
                    {
                        WriteOperationStatus(OperationStatus.Success, writer, cipher);
                        WriteString($"Update file {fileName} permitted", writer, cipher);
                        writer.Flush();
                        using FileStream fStream = new FileStream( Path.GetFullPath($"{config.RootPath}/{fileName}"),
                            FileMode.Create);
                        fStream.Write(ReadData(reader, cipher));
                    }
                    else
                    {
                        WriteOperationStatus(OperationStatus.Error, writer, cipher);
                        WriteString($"File with name \"{fileName}\" is not exist", writer, cipher);
                        writer.Flush();
                    }

                    break;
                }
                case Operation.UploadFile:
                {
                    WriteOperation(Operation.UploadFile, writer, cipher);

                    string fileName = ReadString(reader, cipher);

                    if (CorrectFileName(fileName))
                    {
                        WriteOperationStatus(OperationStatus.Success, writer, cipher);
                        fileName = MakeUniqueFileName(fileName);
                        WriteString($"Upload file {fileName} permitted", writer, cipher);
                        writer.Flush();
                        using FileStream fStream = new FileStream( Path.GetFullPath($"{config.RootPath}/{fileName}"),
                            FileMode.CreateNew);
                        fStream.Write(ReadData(reader, cipher));
                    }
                    else
                    {
                        WriteOperationStatus(OperationStatus.Error, writer, cipher);
                        WriteString($"Incorrect file name \"{fileName}\"", writer, cipher);
                        writer.Flush();
                    }

                    break;
                }
                default:
                {
                    WriteOperation((Operation)0, writer, cipher);
                    WriteString($"Unknown operation", writer, cipher);
                    writer.Flush();
                    break;
                }
            }
        }
    }
}