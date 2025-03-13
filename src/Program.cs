using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

if (args.Length < 1)
{
    Console.WriteLine("Please provide a command.");
    return;
}
string command = args[0];

if (command == "init")
{
    Directory.CreateDirectory(".git");
    Directory.CreateDirectory(".git/objects");
    Directory.CreateDirectory(".git/refs");
    File.WriteAllText(".git/HEAD", "ref: refs/heads/main\n");
    Console.WriteLine("Initialized git directory");
}
else if (command == "cat-file" && args[1] == "-p")
{
    string fileName = args[2];
    string path = Path.Combine(".git", "objects", fileName[..2], fileName[2..]);
    using FileStream fileStream = File.OpenRead(path);
    using ZLibStream zLibStream = new(fileStream, CompressionMode.Decompress);
    MemoryStream uncompressedStream = new();
    zLibStream.CopyTo(uncompressedStream);
    Memory<byte> memory = new Memory<byte>(uncompressedStream.GetBuffer())[..(int)uncompressedStream.Length];
    string objectType = Encoding.UTF8.GetString(memory.Span[..4]);
    int nullByteIndex = memory[5..].Span.IndexOf((byte)0);
    Memory<byte> blobStr = memory[5..][(nullByteIndex + 1)..];

    if (int.TryParse(Encoding.UTF8.GetString(memory[5..].Span[..nullByteIndex]), out int blobLength) && blobLength != blobStr.Length)
    {
        Console.WriteLine("Bad blob length");
        return;
    }

    Console.Write(Encoding.UTF8.GetString(blobStr.Span));
}
else if (command == "hash-object" && args[1] == "-w")
{
    string filePath = args[2];
    string fileContent = File.ReadAllText(filePath);

    // Create the blob header
    string header = $"blob {fileContent.Length}\0";
    byte[] headerBytes = Encoding.UTF8.GetBytes(header);
    byte[] contentBytes = Encoding.UTF8.GetBytes(fileContent);

    // Combine header and content
    byte[] blobData = new byte[headerBytes.Length + contentBytes.Length];
    Buffer.BlockCopy(headerBytes, 0, blobData, 0, headerBytes.Length);
    Buffer.BlockCopy(contentBytes, 0, blobData, headerBytes.Length, contentBytes.Length);

    // Compute SHA-1 hash
    using SHA1 sha1 = SHA1.Create();
    byte[] hashBytes = sha1.ComputeHash(blobData);
    string hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

    // Write the object to .git/objects
    string objectDir = Path.Combine(".git", "objects", hash[..2]);
    string objectPath = Path.Combine(objectDir, hash[2..]);
    Directory.CreateDirectory(objectDir);

    using FileStream fileStream = File.Create(objectPath);
    using ZLibStream zLibStream = new(fileStream, CompressionMode.Compress);
    zLibStream.Write(blobData, 0, blobData.Length);

    // Print the hash
    Console.WriteLine(hash);
}
else if (command == "ls-tree")
{
    bool nameOnly = args[1] == "--name-only";
    string treeSha = nameOnly ? args[2] : args[1];

    string path = Path.Combine(".git", "objects", treeSha[..2], treeSha[2..]);
    using FileStream fileStream = File.OpenRead(path);
    using ZLibStream zLibStream = new(fileStream, CompressionMode.Decompress);
    MemoryStream uncompressedStream = new();
    zLibStream.CopyTo(uncompressedStream);
    byte[] treeData = uncompressedStream.ToArray();

    int pos = 0;
    while (pos < treeData.Length)
    {
        // Parse mode
        int spaceIndex = Array.IndexOf(treeData, (byte)' ', pos);
        string mode = Encoding.UTF8.GetString(treeData, pos, spaceIndex - pos);
        pos = spaceIndex + 1;

        // Parse name
        int nullIndex = Array.IndexOf(treeData, (byte)0, pos);
        string name = Encoding.UTF8.GetString(treeData, pos, nullIndex - pos);
        pos = nullIndex + 1;

        // Parse SHA (20 bytes)
        byte[] shaBytes = new byte[20];
        Array.Copy(treeData, pos, shaBytes, 0, 20);
        string sha = BitConverter.ToString(shaBytes).Replace("-", "").ToLower();
        pos += 20;

        // Output based on flags
        if (nameOnly)
        {
            Console.WriteLine(name);
        }
        else
        {
            string type = mode == "40000" ? "tree" : "blob";
            Console.WriteLine($"{mode} {type} {sha}    {name}");
        }
    }
}
else
{
    throw new ArgumentException($"Unknown command {command}");
}