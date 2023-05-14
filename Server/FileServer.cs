using System.Net;
using System.Net.Sockets;

namespace Server;

public class FileServer
{
    private readonly IPAddress ipAddress;
    private int port;
    private readonly TcpListener listener;
    private readonly Config config;

    public FileServer(Config config)
    {
        ipAddress = IPAddress.Parse(config.Ip);
        port = config.Port;
        listener = new TcpListener(new IPEndPoint(ipAddress, port));
        this.config = config;
    }

    public void Run()
    {
        try
        {
            listener.Start();

            while (true)
            {
                TcpClient client = listener.AcceptTcpClient();

                new Thread(() =>
                {
                    FileServerClient fileServerClient = new FileServerClient(client, config);
                    IPEndPoint? clientIpEndpoint = fileServerClient.GetIpEndPoint();
                    try
                    {
                        if (clientIpEndpoint != null)
                        {
                            Console.WriteLine(
                                $"Client with ip \"{clientIpEndpoint.Address}\" and port \"{clientIpEndpoint.Port}\""
                                + $" connected");
                        }
                        else
                        {
                            Console.WriteLine($"Client connected");
                        }
                        
                        fileServerClient.Process();

                        if (clientIpEndpoint != null)
                        {
                            Console.WriteLine(
                                $"Client with ip \"{clientIpEndpoint.Address}\" and port \"{clientIpEndpoint.Port}\""
                                + $" disconnected");
                        }
                        else
                        {
                            Console.WriteLine($"Client disconnected");
                        }
                    }
                    catch (Exception ex)
                    {
                        if (clientIpEndpoint != null)
                        {
                            Console.WriteLine(
                                $"Client with ip \"{clientIpEndpoint.Address}\" and port \"{clientIpEndpoint.Port}\""
                                + $"disconnected with exception \"{ex.Message}\"");
                        }
                        else
                        {
                            Console.WriteLine($"Client disconnected with exception {ex.Message}");
                        }
                    }
                    finally
                    {
                        client.Close();
                    }
                }).Start();
            }
        }
        finally
        {
            listener.Stop();
        }
    }
}