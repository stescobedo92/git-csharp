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
  var hash = args[2];
  var treePath = Path.Combine(".git", "objects", hash[..2], hash[2..]);
  var contentBytes = File.ReadAllBytes(treePath);
  
  using var memoryStream = new MemoryStream(contentBytes);
  using var zStream = new ZLibStream(memoryStream, CompressionMode.Decompress);
  using var reader = new StreamReader(zStream);
  
  var treeObject = reader.ReadToEnd();
  var splittedContent = treeObject.Split("\0");
  var fileNames = splittedContent.Skip(1).Select(s => s.Split(" ").Last()).SkipLast(1);
  
  foreach (var fileName in fileNames) 
  {
    Console.WriteLine(fileName);
  }
}
else if (command == "write-tree")
{
    string workingDirectory = Directory.GetCurrentDirectory();
    string gitDirectory = Path.Combine(workingDirectory, ".git");

    // Recursively create the tree object for the working directory
    string treeHash = CreateTreeObject(workingDirectory, gitDirectory);

    // Print the tree hash
    Console.WriteLine(treeHash);
}
else
{
    throw new ArgumentException($"Unknown command {command}");
}

static string CreateTreeObject(string directory, string gitDirectory)
{
    var entries = new List<(string Mode, string Name, string Hash)>();

    foreach (var file in Directory.GetFiles(directory))
    {
        if (Path.GetFileName(file) == ".git") continue;

        string fileContent = File.ReadAllText(file);
        string fileHash = CreateBlobObject(fileContent, gitDirectory);

        entries.Add(("100644", Path.GetFileName(file), fileHash));
    }

    foreach (var subDir in Directory.GetDirectories(directory))
    {
        if (Path.GetFileName(subDir) == ".git") continue;

        string subDirHash = CreateTreeObject(subDir, gitDirectory);
        entries.Add(("40000", Path.GetFileName(subDir), subDirHash));
    }

    // Sort entries by name
    entries.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.Ordinal));

    // Create the tree content
    var treeContent = new MemoryStream();
    foreach (var entry in entries)
    {
        string entryLine = $"{entry.Mode} {entry.Name}\0{HexToBytes(entry.Hash)}";
        treeContent.Write(Encoding.UTF8.GetBytes(entryLine), 0, entryLine.Length);
    }

    // Create the tree object
    string treeHeader = $"tree {treeContent.Length}\0";
    var treeObject = new MemoryStream();
    treeObject.Write(Encoding.UTF8.GetBytes(treeHeader), 0, treeHeader.Length);
    treeContent.WriteTo(treeObject);

    // Compute the SHA-1 hash of the tree object
    using SHA1 sha1 = SHA1.Create();
    byte[] hashBytes = sha1.ComputeHash(treeObject.ToArray());
    string treeHash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

    // Write the tree object to .git/objects
    string objectDir = Path.Combine(gitDirectory, "objects", treeHash[..2]);
    string objectPath = Path.Combine(objectDir, treeHash[2..]);
    Directory.CreateDirectory(objectDir);

    using FileStream fileStream = File.Create(objectPath);
    using ZLibStream zLibStream = new(fileStream, CompressionMode.Compress);
    zLibStream.Write(treeObject.ToArray(), 0, (int)treeObject.Length);

    return treeHash;
}

static string CreateBlobObject(string content, string gitDirectory)
{
    string header = $"blob {content.Length}\0";
    byte[] headerBytes = Encoding.UTF8.GetBytes(header);
    byte[] contentBytes = Encoding.UTF8.GetBytes(content);

    byte[] blobData = new byte[headerBytes.Length + contentBytes.Length];
    Buffer.BlockCopy(headerBytes, 0, blobData, 0, headerBytes.Length);
    Buffer.BlockCopy(contentBytes, 0, blobData, headerBytes.Length, contentBytes.Length);

    using SHA1 sha1 = SHA1.Create();
    byte[] hashBytes = sha1.ComputeHash(blobData);
    string hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

    string objectDir = Path.Combine(gitDirectory, "objects", hash[..2]);
    string objectPath = Path.Combine(objectDir, hash[2..]);
    Directory.CreateDirectory(objectDir);

    using FileStream fileStream = File.Create(objectPath);
    using ZLibStream zLibStream = new(fileStream, CompressionMode.Compress);
    zLibStream.Write(blobData, 0, blobData.Length);

    return hash;
}

static byte[] HexToBytes(string hex)
{
    byte[] bytes = new byte[hex.Length / 2];
    for (int i = 0; i < hex.Length; i += 2)
    {
        bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
    }
    return bytes;
}