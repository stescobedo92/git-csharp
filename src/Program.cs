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
  var currentPath = Directory.GetCurrentDirectory();
  var currentFilePathHash = GenerateTreeObjectFileHash(currentPath);
  var hashString = Convert.ToHexString(currentFilePathHash).ToLower();
  Console.Write(hashString);
}
else if (command == "commit-tree") 
{
  if (args.Length < 6 || args[1] == null || args[3] != "-p" || args[5] != "-m")
  {
    Console.WriteLine("Usage: commit-tree <tree_sha> -p <commit_sha> -m <message>");
    return;
  }

  string treeSha = args[1];
  string parentCommitSha = args[4];
  string message = args[6];

  // Hardcoded author/committer information
  string authorName = "John Doe";
  string authorEmail = "john.doe@example.com";
  DateTimeOffset timestamp = DateTimeOffset.UtcNow;

  // Create the commit object content
  string commitContent = $"tree {treeSha}\n" +
                         $"parent {parentCommitSha}\n" +
                         $"author {authorName} <{authorEmail}> {timestamp.ToUnixTimeSeconds()} +0000\n" +
                         $"committer {authorName} <{authorEmail}> {timestamp.ToUnixTimeSeconds()} +0000\n" +
                         $"\n" +
                         $"{message}\n";

  // Convert the commit content to bytes
  byte[] commitBytes = Encoding.UTF8.GetBytes(commitContent);

  // Create the commit header
  string header = $"commit {commitBytes.Length}\0";
  byte[] headerBytes = Encoding.UTF8.GetBytes(header);

  // Combine header and content
  byte[] commitObject = new byte[headerBytes.Length + commitBytes.Length];
  Buffer.BlockCopy(headerBytes, 0, commitObject, 0, headerBytes.Length);
  Buffer.BlockCopy(commitBytes, 0, commitObject, headerBytes.Length, commitBytes.Length);

  // Compute SHA-1 hash
  using SHA1 sha1 = SHA1.Create();
  byte[] hashBytes = sha1.ComputeHash(commitObject);
  string hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

  // Write the commit object to .git/objects
  string objectDir = Path.Combine(".git", "objects", hash[..2]);
  string objectPath = Path.Combine(objectDir, hash[2..]);
  Directory.CreateDirectory(objectDir);

  using FileStream fileStream = File.Create(objectPath);
  using ZLibStream zLibStream = new(fileStream, CompressionMode.Compress);
  zLibStream.Write(commitObject, 0, commitObject.Length);

  // Print the commit hash
  Console.WriteLine(hash);
}
else
{
    throw new ArgumentException($"Unknown command {command}");
}

byte[] CreateObjectHeaderInBytes(string gitObjectType, byte[] input) => Encoding.UTF8.GetBytes($"{gitObjectType} {input.Length}\0");

byte[] GenerateHashByte(string gitObjectType, byte[] input) 
{
  var objectHeader = CreateObjectHeaderInBytes(gitObjectType, input);
  var gitObject = (objectHeader.Concat(input)).ToArray();
  var hash = SHA1.HashData(gitObject);
  using MemoryStream memoryStream = new MemoryStream();
  using (ZLibStream zlibStream = new ZLibStream(memoryStream, CompressionLevel.Optimal)) 
  {
    zlibStream.Write(gitObject, 0, gitObject.Length);
  }
  
  var compressedObject = memoryStream.ToArray();
  var hashString = Convert.ToHexString(hash).ToLower();
  Directory.CreateDirectory($".git/objects/{hashString[..2]}");
  File.WriteAllBytes($".git/objects/{hashString[..2]}/{hashString[2..]}",compressedObject);

  return hash;
}

byte[]? GenerateTreeObjectFileHash(string currentPath) 
{
  if (currentPath.Contains(".git"))
    return null;

  var files = Directory.GetFiles(currentPath);
  var directories = Directory.GetDirectories(currentPath);
  var treeEntries = new List<TreeEntry>();
  
  foreach (var file in files) 
  {
    string fileName = Path.GetFileName(file);
    var fileContentInBytes = File.ReadAllBytes(file);
    var fileHash = GenerateHashByte("blob", fileContentInBytes);
    var fileEntry = new TreeEntry("100644", fileName, fileHash);
    treeEntries.Add(fileEntry);
  }
  
  for (var i = 0; i < directories.Length; i++) 
  {
    var directoryName = Path.GetFileName(directories[i]);
    var directoryHash = GenerateTreeObjectFileHash(directories[i]);
    
    if (directoryHash is not null) 
    {
      var directoryEntry = new TreeEntry("40000", directoryName, directoryHash);
      treeEntries.Add(directoryEntry);
    }
  }

  return GenerateHashByte("tree", CreateTreeObject(treeEntries));
}

byte[] CreateTreeObject(List<TreeEntry> treeEntries) 
{
  using var memoryStream = new MemoryStream();
  using var streamWriter = new StreamWriter(memoryStream, new UTF8Encoding(false));
  
  foreach (var entry in treeEntries.OrderBy(x => x.FileName)) 
  {
    var line = $"{entry.Mode} {entry.FileName}\x00";
    streamWriter.Write(line);
    streamWriter.Flush();
    memoryStream.Write(entry.Hash, 0, entry.Hash.Length);
  }

  streamWriter.Flush();
  return memoryStream.ToArray();
}

public record TreeEntry(string Mode, string FileName, byte[] Hash);