namespace Server;

public class Config
{
    public Config(string rootPath, string ip, int port)
    {
        RootPath = rootPath;
        Ip = ip;
        Port = port;
    }

    public string RootPath { get; set; }
    public string Ip { get; set; }
    public int Port { get; set; }
}