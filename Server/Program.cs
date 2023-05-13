using System.Net;
using System.Numerics;

namespace Server
{
    class Program
    {
        static void Main(string[] args)
        {
            FileServer server = new FileServer(new Config("/", "127.0.0.1", 5000));
            server.Run();
        }
    }
}