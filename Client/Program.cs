namespace Client;

static class Program
{
    static void Main(string[] args)
    {
        FileClient fileClient = new FileClient();
        fileClient.Connect("127.0.0.1", 5000);
        fileClient.CloseConnection(out string? answer);
        Console.WriteLine(answer);
    }
}

