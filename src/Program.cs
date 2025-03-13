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
    if (args.Length < 3)
    {
        Console.WriteLine("Usage: ls-tree [--name-only] <tree_sha>");
        return;
    }

    bool nameOnly = args[1] == "--name-only";
    string treeSha = nameOnly ? args[2] : args[1];
    string treePath = Path.Combine(".git", "objects", treeSha[..2], treeSha[2..]);

    if (!File.Exists(treePath))
    {
        Console.WriteLine($"Tree object not found: {treeSha}");
        return;
    }

    // Step 1: Read and decompress the tree object
    byte[] treeData;
    using (FileStream fileStream = File.OpenRead(treePath))
    using (ZLibStream zlibStream = new ZLibStream(fileStream, CompressionMode.Decompress))
    using (MemoryStream memoryStream = new MemoryStream())
    {
        zlibStream.CopyTo(memoryStream);
        treeData = memoryStream.ToArray();
    }

    // Step 2: Parse the tree object
    int offset = 0;
    while (offset < treeData.Length)
    {
        // Read mode (e.g., 40000 for directories, 100644 for files)
        int spaceIndex = Array.IndexOf(treeData, (byte)' ', offset);
        string mode = Encoding.UTF8.GetString(treeData[offset..spaceIndex]);
        offset = spaceIndex + 1;

        // Read name (file/directory name)
        int nullByteIndex = Array.IndexOf(treeData, (byte)0, offset);
        string name = Encoding.UTF8.GetString(treeData[offset..nullByteIndex]);
        offset = nullByteIndex + 1;

        // Read SHA-1 hash (20 bytes)
        byte[] shaBytes = treeData[offset..(offset + 20)];
        string sha = BitConverter.ToString(shaBytes).Replace("-", "").ToLower();
        offset += 20;

        // Output based on --name-only flag
        if (nameOnly)
        {
            Console.WriteLine(name);
        }
        else
        {
            string type = mode.StartsWith("4") ? "tree" : "blob";
            Console.WriteLine($"{mode} {type} {sha}\t{name}");
        }
    }
}
else
{
    throw new ArgumentException($"Unknown command {command}");
}