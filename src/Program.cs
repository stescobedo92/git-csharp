using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using LibGit2Sharp;

class Program 
{
  static void Main(string[] args) 
  {
    if (args.Length < 1) {
      Console.WriteLine("Please provide a command.");
      return;
    }
    // Debug log
    Console.Error.WriteLine("Logs from your program will appear here!");
    string command = args[0];
    // --------------------
    // INIT
    // --------------------
    if (command == "init") {
      Directory.CreateDirectory(".git");
      Directory.CreateDirectory(".git/objects");
      Directory.CreateDirectory(".git/refs");
      File.WriteAllText(".git/HEAD", "ref: refs/heads/main\n");
      Console.WriteLine("Initialized git directory");
    }
    else if (command == "clone") {
      // We'll do the same approach the Rust code does:
      //  if the user only supplies <repoUrl>, we guess a folder name
      //  else we use the second argument as directory
      if (args.Length < 2) {
        Console.WriteLine("Usage: clone <repoUrl> [<directory>]");
        return;
      }
      string repoUrl = args[1];
      string directory;
      if (args.Length >= 3) {
        // use user-supplied directory
        directory = args[2];
      } else {
        // parse from the final path segment, stripping .git if present
        Uri uri;
        try {
          uri = new Uri(repoUrl);
        } catch {
          Console.WriteLine($"Invalid repo URL: {repoUrl}");
          return;
        }
        // e.g. if path is "/user/repo.git", last segment is "repo.git"
        string lastSegment = uri.Segments.Last().TrimEnd('/');
        if (lastSegment.EndsWith(".git", StringComparison.OrdinalIgnoreCase)) {
          lastSegment = lastSegment.Substring(0, lastSegment.Length - 4);
        }
        directory = lastSegment;
      }
      // Actually clone using LibGit2Sharp
      try {
        Repository.Clone(repoUrl, directory);
        Console.WriteLine($"Cloned repository from {repoUrl} into {directory}");
      } catch (Exception ex) {
        Console.WriteLine($"Error cloning repository: {ex.Message}");
      }
    }
    else if (command == "cat-file" && args.Length >= 3) {
      string option = args[1];
      string objectHash = args[2];
      if (option != "-p") {
        Console.WriteLine(
            "Unsupported option for cat-file. Only '-p' is supported.");
        return;
      }
      try {
        // Build the path: .git/objects/<first2>/<remaining38>
        string objectDir = $".git/objects/{objectHash.Substring(0, 2)}";
        string objectFile = objectHash.Substring(2);
        string objectPath = Path.Combine(objectDir, objectFile);
        if (!File.Exists(objectPath)) {
          Console.WriteLine($"Object {objectHash} not found.");
          return;
        }
        // Read & decompress
        byte[] compressedData = File.ReadAllBytes(objectPath);
        byte[] decompressedData;
        using (var memoryStream = new MemoryStream(compressedData)) using (
            var zlibStream = new ZLibStream(
                memoryStream,
                CompressionMode.Decompress)) using (var outputStream =
                                                        new MemoryStream()) {
          zlibStream.CopyTo(outputStream);
          decompressedData = outputStream.ToArray();
        }
        // Parse "blob <size>\0<content>" or other object formats
        string decompressedString = Encoding.UTF8.GetString(decompressedData);
        int nullByteIndex = decompressedString.IndexOf('\0');
        if (nullByteIndex == -1) {
          Console.WriteLine("Invalid object format.");
          return;
        }
        // Print just the content (skip the header)
        string content = decompressedString.Substring(nullByteIndex + 1);
        Console.Write(content);
      } catch (Exception ex) {
        Console.WriteLine($"Error reading object: {ex.Message}");
      }
    }
    else if (command == "hash-object") {
      if (args.Length < 3) {
        Console.WriteLine("Usage: hash-object -w <file>");
        return;
      }
      string option = args[1];
      string filePath = args[2];
      if (option != "-w") {
        Console.WriteLine(
            $"Unsupported option {option} for hash-object. Only '-w' is supported.");
        return;
      }
      if (!File.Exists(filePath)) {
        Console.WriteLine($"File '{filePath}' does not exist.");
        return;
      }
      try {
        // Read file bytes
        byte[] fileBytes = File.ReadAllBytes(filePath);
        // Construct the blob data: "blob <size>\0<content>"
        string header = $"blob {fileBytes.Length}\0";
        byte[] headerBytes = Encoding.UTF8.GetBytes(header);
        byte[] blobData = new byte[headerBytes.Length + fileBytes.Length];
        Buffer.BlockCopy(headerBytes, 0, blobData, 0, headerBytes.Length);
        Buffer.BlockCopy(fileBytes, 0, blobData, headerBytes.Length,
                         fileBytes.Length);
        // Compute SHA-1
        byte[] sha1Hash;
        using (SHA1 sha1 = SHA1.Create()) {
          sha1Hash = sha1.ComputeHash(blobData);
        }
        // Convert to hex
        string hashHex =
            BitConverter.ToString(sha1Hash).Replace("-", "").ToLower();
        // Compress & write object
        byte[] compressedData;
        using (var inputStream = new MemoryStream(blobData)) using (
            var outputStream = new MemoryStream()) {
          using (var zlibStream = new ZLibStream(
                     outputStream, CompressionMode.Compress, true)) {
            inputStream.CopyTo(zlibStream);
          }
          compressedData = outputStream.ToArray();
        }
        string objectDir =
            Path.Combine(".git", "objects", hashHex.Substring(0, 2));
        string objectFile = hashHex.Substring(2);
        Directory.CreateDirectory(objectDir);
        string objectPath = Path.Combine(objectDir, objectFile);
        // Write only if not existing
        if (!File.Exists(objectPath)) {
          File.WriteAllBytes(objectPath, compressedData);
        }
        // Print the SHA
        Console.WriteLine(hashHex);
      } catch (Exception ex) {
        Console.WriteLine($"Error hashing/writing object: {ex.Message}");
      }
    }
    else if (command == "ls-tree" && args.Length >= 3) {
      string option = args[1];
      string treeHash = args[2];
      if (option != "--name-only") {
        Console.WriteLine(
            "Unsupported option for ls-tree. Only '--name-only' is supported.");
        return;
      }
      try {
        // Locate object file
        string objectDir =
            Path.Combine(".git", "objects", treeHash.Substring(0, 2));
        string objectFile = treeHash.Substring(2);
        string objectPath = Path.Combine(objectDir, objectFile);
        if (!File.Exists(objectPath)) {
          Console.WriteLine($"Object {treeHash} not found.");
          return;
        }
        // Decompress
        byte[] compressedData = File.ReadAllBytes(objectPath);
        byte[] decompressedData;
        using (var memoryStream = new MemoryStream(compressedData)) using (
            var zlibStream = new ZLibStream(
                memoryStream,
                CompressionMode.Decompress)) using (var outputStream =
                                                        new MemoryStream()) {
          zlibStream.CopyTo(outputStream);
          decompressedData = outputStream.ToArray();
        }
        // Must start with "tree <size>\0"
        int firstNull = Array.IndexOf(decompressedData, (byte)0);
        if (firstNull < 0) {
          Console.WriteLine("Invalid tree object: missing header null byte.");
          return;
        }
        string header = Encoding.UTF8.GetString(decompressedData, 0, firstNull);
        if (!header.StartsWith("tree ")) {
          Console.WriteLine(
              "Invalid tree object: header does not start with 'tree '.");
          return;
        }
        // The rest is tree entries
        int contentStart = firstNull + 1;
        byte[] treeContent = new byte[decompressedData.Length - contentStart];
        Buffer.BlockCopy(decompressedData, contentStart, treeContent, 0,
                         treeContent.Length);
        // Parse each entry
        int index = 0;
        while (index < treeContent.Length) {
          int spacePos = FindByte(treeContent, (byte)' ', index);
          if (spacePos < 0) {
            Console.WriteLine("Invalid tree object: missing space after mode.");
            return;
          }
          int nullPos = FindByte(treeContent, (byte)0, spacePos + 1);
          if (nullPos < 0) {
            Console.WriteLine(
                "Invalid tree object: missing null terminator after filename.");
            return;
          }
          string filename = Encoding.UTF8.GetString(treeContent, spacePos + 1,
                                                    nullPos - (spacePos + 1));
          // skip the 20-byte SHA
          int shaStart = nullPos + 1;
          if (shaStart + 20 > treeContent.Length) {
            Console.WriteLine(
                "Invalid tree object: not enough bytes for SHA-1.");
            return;
          }
          index = shaStart + 20;
          // Print only the filename for --name-only
          Console.WriteLine(filename);
        }
      } catch (Exception ex) {
        Console.WriteLine($"Error reading tree object: {ex.Message}");
      }
    }
    else if (command == "write-tree") {
      try {
        // Build a tree for the current directory, ignoring .git
        string treeSha = WriteTree(".");
        Console.WriteLine(treeSha);
      } catch (Exception ex) {
        Console.WriteLine($"Error writing tree: {ex.Message}");
      }
    }
    else if (command == "commit-tree") {
      try {
        if (args.Length < 2) {
          Console.WriteLine(
              "Usage: commit-tree <tree_sha> -p <parent_sha> -m <message>");
          return;
        }
        string treeSha = args[1];
        string parentSha = null;
        string message = null;
        for (int i = 2; i < args.Length; i++) {
          if (args[i] == "-p" && i + 1 < args.Length) {
            parentSha = args[i + 1];
            i++;
          } else if (args[i] == "-m" && i + 1 < args.Length) {
            message = args[i + 1];
            i++;
          }
        }
        string commitHash = CreateCommit(treeSha, parentSha, message);
        Console.WriteLine(commitHash);
      } catch (Exception ex) {
        Console.WriteLine($"Error creating commit: {ex.Message}");
      }
    } else {
      throw new ArgumentException($"Unknown command {command}");
    }
  }
  private static string CreateCommit(string treeSha, string parentSha,
                                     string message) {
    string authorName = "Example Author";
    string authorEmail = "author@example.com";
    long timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    string timezone = "+0000";
    var sb = new StringBuilder();
    sb.AppendLine($"tree {treeSha}");
    if (!string.IsNullOrEmpty(parentSha)) {
      sb.AppendLine($"parent {parentSha}");
    }
    sb.AppendLine(
        $"author {authorName} <{authorEmail}> {timestamp} {timezone}");
    sb.AppendLine(
        $"committer {authorName} <{authorEmail}> {timestamp} {timezone}");
    sb.AppendLine();
    if (!string.IsNullOrEmpty(message)) {
      sb.AppendLine(message);
    }
    byte[] commitContent = Encoding.UTF8.GetBytes(sb.ToString());
    string header = $"commit {commitContent.Length}\0";
    byte[] headerBytes = Encoding.UTF8.GetBytes(header);
    byte[] finalData = new byte[headerBytes.Length + commitContent.Length];
    Buffer.BlockCopy(headerBytes, 0, finalData, 0, headerBytes.Length);
    Buffer.BlockCopy(commitContent, 0, finalData, headerBytes.Length,
                     commitContent.Length);
    byte[] sha1Hash;
    using (SHA1 sha1 = SHA1.Create()) {
      sha1Hash = sha1.ComputeHash(finalData);
    }
    string hashHex = BitConverter.ToString(sha1Hash).Replace("-", "").ToLower();
    WriteObjectToGit(sha1Hash, finalData);
    return hashHex;
  }
  
  private static int FindByte(byte[] data, byte target, int startIndex) {
    for (int i = startIndex; i < data.Length; i++) {
      if (data[i] == target)
        return i;
    }
    return -1;
  }
  
  static string WriteTree(string directoryPath) {
    var entries = new List<(string Mode, string Name, byte[] Sha)>();
    // 1) Files => "100644"
    foreach (var filePath in Directory.GetFiles(directoryPath)) {
      if (Path.GetFileName(filePath) == ".gitignore")
        continue;
      byte[] fileSha = HashFileAsBlob(filePath);
      string fileName = Path.GetFileName(filePath);
      entries.Add(("100644", fileName, fileSha));
    }
    // 2) Directories => "40000"
    foreach (var subDir in Directory.GetDirectories(directoryPath)) {
      string dirName = Path.GetFileName(subDir);
      if (dirName == ".git")
        continue;
      byte[] subTreeSha = WriteTreeAsBytes(subDir);
      entries.Add(("40000", dirName, subTreeSha));
    }
    // sort
    entries.Sort((a, b) =>
                     string.Compare(a.Name, b.Name, StringComparison.Ordinal));
    using (var memStream = new MemoryStream()) {
      foreach (var (mode, name, shaBytes) in entries) {
        byte[] modeBytes = Encoding.ASCII.GetBytes(mode + " ");
        memStream.Write(modeBytes, 0, modeBytes.Length);
        byte[] nameBytes = Encoding.UTF8.GetBytes(name);
        memStream.Write(nameBytes, 0, nameBytes.Length);
        memStream.WriteByte(0);
        memStream.Write(shaBytes, 0, shaBytes.Length);
      }
      byte[] treeContent = memStream.ToArray();
      string header = $"tree {treeContent.Length}\0";
      byte[] headerBytes = Encoding.ASCII.GetBytes(header);
      byte[] finalData = new byte[headerBytes.Length + treeContent.Length];
      Buffer.BlockCopy(headerBytes, 0, finalData, 0, headerBytes.Length);
      Buffer.BlockCopy(treeContent, 0, finalData, headerBytes.Length,
                       treeContent.Length);
      byte[] sha1Hash;
      using (SHA1 sha1 = SHA1.Create()) {
        sha1Hash = sha1.ComputeHash(finalData);
      }
      WriteObjectToGit(sha1Hash, finalData);
      return BitConverter.ToString(sha1Hash).Replace("-", "").ToLower();
    }
  }
  static byte[] WriteTreeAsBytes(string directoryPath) {
    string shaHex = WriteTree(directoryPath);
    return ShaHexStringToBytes(shaHex);
  }
  
  static byte[] HashFileAsBlob(string filePath) {
    byte[] fileBytes = File.ReadAllBytes(filePath);
    string header = $"blob {fileBytes.Length}\0";
    byte[] headerBytes = Encoding.UTF8.GetBytes(header);
    byte[] blobData = new byte[headerBytes.Length + fileBytes.Length];
    Buffer.BlockCopy(headerBytes, 0, blobData, 0, headerBytes.Length);
    Buffer.BlockCopy(fileBytes, 0, blobData, headerBytes.Length,
                     fileBytes.Length);
    byte[] sha1Hash;
    using (SHA1 sha1 = SHA1.Create()) { sha1Hash = sha1.ComputeHash(blobData); }
    WriteObjectToGit(sha1Hash, blobData);
    return sha1Hash;
  }
  
  static void WriteObjectToGit(byte[] sha1Hash, byte[] data) {
    string hashHex = BitConverter.ToString(sha1Hash).Replace("-", "").ToLower();
    string dir = Path.Combine(".git", "objects", hashHex.Substring(0, 2));
    string fileName = hashHex.Substring(2);
    string objectPath = Path.Combine(dir, fileName);
    if (File.Exists(objectPath))
      return; // already exists
    Directory.CreateDirectory(dir);
    byte[] compressed;
    using (var inputStream = new MemoryStream(data)) using (
        var outputStream = new MemoryStream()) {
      using (var zlib =
                 new ZLibStream(outputStream, CompressionMode.Compress, true)) {
        inputStream.CopyTo(zlib);
      }
      compressed = outputStream.ToArray();
    }
    File.WriteAllBytes(objectPath, compressed);
  }
  
  static byte[] ShaHexStringToBytes(string hex) {
    byte[] result = new byte[20];
    for (int i = 0; i < 20; i++) {
      string twoHex = hex.Substring(i * 2, 2);
      result[i] = Convert.ToByte(twoHex, 16);
    }
    return result;
  }
}