using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks; // Added for async HttpClient
using System.Runtime.InteropServices; // Added for OSPlatform and UnixFileMode

// Represents a Git object entry within a tree
public record TreeEntry(string Mode, string FileName, byte[] Hash);

// Represents a parsed object from a packfile
public record PackObject(string Type, byte[] Data, long Offset, long BaseOffset = -1, string? BaseHash = null);

public class Program
{
    // Dictionary to cache objects read from packfile before storing, useful for delta resolution
    private static Dictionary<long, PackObject> _packObjectsByOffset = new Dictionary<long, PackObject>();
    private static Dictionary<string, PackObject> _packObjectsByHash = new Dictionary<string, PackObject>(); // If base is identified by hash

    public static async Task Main(string[] args) // Changed to async Task for HttpClient
    {
        if (args.Length < 1)
        {
            Console.WriteLine("Please provide a command.");
            return;
        }
        string command = args[0];

        // --- Existing commands (init, cat-file, hash-object, ls-tree, write-tree, commit-tree) ---
        if (command == "init")
        {
            Directory.CreateDirectory(".git");
            Directory.CreateDirectory(".git/objects");
            Directory.CreateDirectory(".git/refs");
            File.WriteAllText(".git/HEAD", "ref: refs/heads/main\n");
            Console.WriteLine("Initialized git directory");
        }
        else if (command == "cat-file" && args.Length > 2 && args[1] == "-p")
        {
            try
            {
                string hash = args[2];
                byte[] data = ReadObject(hash); // Use helper to read/decompress
                int nullByteIndex = Array.IndexOf(data, (byte)0);
                if (nullByteIndex == -1)
                {
                    Console.Error.WriteLine($"Error: Invalid object format for {hash}");
                    return;
                }
                string content = Encoding.UTF8.GetString(data, nullByteIndex + 1, data.Length - (nullByteIndex + 1));
                Console.Write(content);
            }
            catch (FileNotFoundException)
            {
                Console.Error.WriteLine($"Error: Object {args[2]} not found.");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"An error occurred in cat-file: {ex.Message}");
            }
        }
        else if (command == "hash-object" && args.Length > 2 && args[1] == "-w")
        {
            try
            {
                string filePath = args[2];
                byte[] fileContentBytes = File.ReadAllBytes(filePath); // Read as bytes
                byte[] hashBytes = GenerateHashByte("blob", fileContentBytes); // Pass bytes

                // Null-forgiving operator used here to silence the compiler's null warning
                string hash = Convert.ToHexString(hashBytes!).ToLower(); 
                Console.WriteLine(hash);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"An error occurred in hash-object: {ex.Message}");
            }
        }
        else if (command == "ls-tree" && args.Length > 2 && args[1] == "--name-only") // Adjusted for common usage
        {
            try
            {
                string treeHash = args[2];
                byte[] treeData = ReadObject(treeHash); // Use helper
                int currentPos = Array.IndexOf(treeData, (byte)0) + 1; // Skip header
                while (currentPos < treeData.Length)
                {
                    int spaceIndex = Array.IndexOf(treeData, (byte)' ', currentPos);
                    if (spaceIndex == -1) break;
                    int nullIndex = Array.IndexOf(treeData, (byte)0, spaceIndex + 1);
                    if (nullIndex == -1) break;
                    string fileName = Encoding.UTF8.GetString(treeData, spaceIndex + 1, nullIndex - (spaceIndex + 1));
                    Console.WriteLine(fileName);
                    currentPos = nullIndex + 1 + 20; // Move past hash
                }
            }
            catch (FileNotFoundException)
            {
                Console.Error.WriteLine($"Error: Tree object {args[2]} not found.");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"An error occurred in ls-tree: {ex.Message}");
            }
        }
        else if (command == "write-tree")
        {
            try
            {
                var currentPath = Directory.GetCurrentDirectory();
                var currentFilePathHash = GenerateTreeObjectFileHash(currentPath); // Returns byte[]?

                // Fix for CS8604: Check if hash is null before converting
                if (currentFilePathHash != null)
                {
                    var hashString = Convert.ToHexString(currentFilePathHash).ToLower(); // Safe now
                    Console.Write(hashString);
                }
                else
                {
                    // Handle case where tree hash couldn't be generated (e.g., empty dir)
                    // Outputting hash of empty tree is standard Git behavior
                    byte[] emptyTree = Array.Empty<byte>();
                    byte[] emptyTreeHashBytes = GenerateHashByte("tree", emptyTree);
                    Console.Write(Convert.ToHexString(emptyTreeHashBytes).ToLower());
                    // Console.Error.WriteLine("Warning: Generated hash for an empty tree.");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"An error occurred in write-tree: {ex.Message}");
                Console.Error.WriteLine(ex.StackTrace);
            }
        }
        else if (command == "commit-tree")
        {
            try
            {
                if (args.Length < 6 || args[2] != "-p" || args[4] != "-m")
                {
                    Console.WriteLine("Usage: commit-tree <tree_sha> -p <parent_sha> -m <message>");
                    return;
                }

                string treeSha = args[1];
                string parentSha = args[3];
                string message = args[5];

                string author = "Author Name <author@example.com>";
                string committer = "Committer Name <committer@example.com>";
                long unixTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                TimeSpan offset = TimeZoneInfo.Local.GetUtcOffset(DateTimeOffset.UtcNow);
                string timezone = $"{(offset < TimeSpan.Zero ? "-" : "+")}{offset:hhmm}";

                StringBuilder commitContent = new StringBuilder();
                commitContent.AppendLine($"tree {treeSha}");
                commitContent.AppendLine($"parent {parentSha}");
                commitContent.AppendLine($"author {author} {unixTimestamp} {timezone}");
                commitContent.AppendLine($"committer {committer} {unixTimestamp} {timezone}");
                commitContent.AppendLine();
                commitContent.AppendLine(message);

                byte[] commitBytes = Encoding.UTF8.GetBytes(commitContent.ToString());
                byte[] commitHash = GenerateHashByte("commit", commitBytes);
                string hashString = Convert.ToHexString(commitHash).ToLower();
                Console.WriteLine(hashString);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"An error occurred in commit-tree: {ex.Message}");
            }
        }
        // --- Clone Command Implementation ---
        else if (command == "clone")
        {
            if (args.Length < 3)
            {
                Console.WriteLine("Usage: clone <repository_url> <target_directory>");
                return;
            }

            string repoUrl = args[1].TrimEnd('/'); // Ensure no trailing slash
            string targetDir = args[2];

            if (Directory.Exists(targetDir))
            {
                if (Directory.EnumerateFileSystemEntries(targetDir).Any())
                {
                    Console.Error.WriteLine($"Error: Target directory '{targetDir}' exists and is not empty.");
                    return;
                }
            }
            else
            {
                Directory.CreateDirectory(targetDir);
            }

            string originalDirectory = Directory.GetCurrentDirectory();
            try
            {
                Directory.SetCurrentDirectory(targetDir);

                Directory.CreateDirectory(".git");
                Directory.CreateDirectory(".git/objects");
                Directory.CreateDirectory(".git/refs");
                Directory.CreateDirectory(".git/refs/heads");
                File.WriteAllText(".git/HEAD", "ref: refs/heads/main\n");

                Console.WriteLine($"Cloning into '{Path.GetFileName(targetDir)}'...");

                using (var client = new HttpClient())
                {
                    client.DefaultRequestHeaders.UserAgent.ParseAdd("csharp-git-client/1.0");
                    client.DefaultRequestHeaders.Accept.ParseAdd("application/x-git-upload-pack-result");

                    // --- Step 1: Discover references ---
                    string infoRefsUrl = $"{repoUrl}/info/refs?service=git-upload-pack";
                    Console.WriteLine($"Fetching refs from {infoRefsUrl}");
                    HttpResponseMessage infoRefsResponse = await client.GetAsync(infoRefsUrl);

                    if (!infoRefsResponse.IsSuccessStatusCode)
                    {
                        Console.Error.WriteLine($"Failed to fetch refs: {infoRefsResponse.StatusCode}");
                        string errorContent = await infoRefsResponse.Content.ReadAsStringAsync();
                        Console.Error.WriteLine($"Server response: {errorContent}");
                        return;
                    }

                    using var infoRefsStream = await infoRefsResponse.Content.ReadAsStreamAsync();
                    var refs = await ParseInfoRefs(infoRefsStream);

                    if (!refs.Any())
                    {
                        Console.Error.WriteLine("No refs found.");
                        return;
                    }

                    string? headCommit = null;
                    string? headRefName = null;
                    if (refs.TryGetValue("HEAD", out string headTargetRef) && refs.TryGetValue(headTargetRef, out string targetCommit))
                    {
                        headCommit = targetCommit;
                        headRefName = headTargetRef;
                    }
                    else if (refs.TryGetValue("refs/heads/main", out string mainCommit))
                    {
                        headCommit = mainCommit;
                        headRefName = "refs/heads/main";
                    }
                    else if (refs.TryGetValue("refs/heads/master", out string masterCommit))
                    {
                        headCommit = masterCommit;
                        headRefName = "refs/heads/master";
                    }

                    if (string.IsNullOrEmpty(headCommit) || string.IsNullOrEmpty(headRefName))
                    {
                        Console.Error.WriteLine("Could not determine HEAD commit or ref name from available refs:");
                        foreach (var kvp in refs) Console.WriteLine($"- {kvp.Value} {kvp.Key}");
                        return;
                    }

                    Console.WriteLine($"Determined HEAD commit: {headCommit} ({headRefName})");

                    // Null-forgiving operator used here to silence the compiler's null warning
                    File.WriteAllText(".git/HEAD", $"ref: {headRefName!}\n");

                    // --- Step 2: Negotiate and fetch packfile ---
                    string uploadPackUrl = $"{repoUrl}/git-upload-pack";
                    Console.WriteLine($"Requesting packfile from {uploadPackUrl}");

                    // Minimal "want" request
                    string minimalWantLine = $"want {headCommit}\n";
                    string requestBody = $"{(minimalWantLine.Length + 4):x4}{minimalWantLine}00000009done\n";
                    Console.WriteLine($"DEBUG: Sending request body (pkt-line):\n{requestBody.Replace("\n", "\\n\n")}"); // Debug output

                    var content = new StringContent(requestBody, Encoding.UTF8, "application/x-git-upload-pack-request");
                    HttpResponseMessage packResponse = await client.PostAsync(uploadPackUrl, content);

                    if (!packResponse.IsSuccessStatusCode)
                    {
                        Console.Error.WriteLine($"Failed to fetch pack: {packResponse.StatusCode}"); 
                        string errorContent = await packResponse.Content.ReadAsStringAsync();
                        Console.Error.WriteLine($"Server response: {errorContent}");
                        return;
                    }

                    // --- Step 3: Process packfile ---
                    Console.WriteLine("Receiving packfile...");
                    using var packStream = await packResponse.Content.ReadAsStreamAsync();
                    await ProcessPackfile(packStream); // Process the stream

                    // --- Step 4: Checkout HEAD ---
                    Console.WriteLine($"Checking out commit {headCommit}");
                    CheckoutHead(headCommit);

                    Console.WriteLine($"Successfully cloned repository to {targetDir}");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"An error occurred during clone: {ex.Message}");
                Console.Error.WriteLine(ex.StackTrace);
            }
            finally
            {
                Directory.SetCurrentDirectory(originalDirectory);
                _packObjectsByOffset.Clear();
                _packObjectsByHash.Clear();
            }
        }
        else
        {
            Console.Error.WriteLine($"Unknown command {command}");
        }
    }

    // --- Helper Methods ---

    static byte[] ReadObject(string hash)
    {
        string path = Path.Combine(".git", "objects", hash.Substring(0, 2), hash.Substring(2));
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Object file not found: {path}", path);
        }
        using FileStream fileStream = File.OpenRead(path);
        using MemoryStream compressedStream = new MemoryStream();
        fileStream.CopyTo(compressedStream);
        compressedStream.Position = 0;
        using MemoryStream decompressedStream = new MemoryStream();
        using ZLibStream zLibStream = new ZLibStream(compressedStream, CompressionMode.Decompress);
        zLibStream.CopyTo(decompressedStream);
        return decompressedStream.ToArray();
    }

    static byte[] CreateObjectHeaderInBytes(string gitObjectType, long size)
    {
        return Encoding.UTF8.GetBytes($"{gitObjectType} {size}\0");
    }

    static byte[] GenerateHashByte(string gitObjectType, byte[] contentBytes)
    {
        var objectHeader = CreateObjectHeaderInBytes(gitObjectType, contentBytes.Length);
        var gitObject = new byte[objectHeader.Length + contentBytes.Length];
        Buffer.BlockCopy(objectHeader, 0, gitObject, 0, objectHeader.Length);
        Buffer.BlockCopy(contentBytes, 0, gitObject, objectHeader.Length, contentBytes.Length);

        var hash = SHA1.HashData(gitObject);
        var hashString = Convert.ToHexString(hash).ToLower();

        using var memoryStream = new MemoryStream();
        using (var zlibStream = new ZLibStream(memoryStream, CompressionLevel.Optimal, true))
        {
            zlibStream.Write(gitObject, 0, gitObject.Length);
        }
        var compressedObject = memoryStream.ToArray();

        var objectDir = Path.Combine(".git", "objects", hashString.Substring(0, 2));
        var objectPath = Path.Combine(objectDir, hashString.Substring(2));
        Directory.CreateDirectory(objectDir);
        File.WriteAllBytes(objectPath, compressedObject);

        return hash;
    }

    static byte[]? GenerateTreeObjectFileHash(string currentPath)
    {
        if (Path.GetFileName(currentPath) == ".git") return null;
        var entries = new List<TreeEntry>();
        foreach (var file in Directory.GetFiles(currentPath))
        {
            string fileName = Path.GetFileName(file);
            if (fileName == ".git") continue;
            var fileContentInBytes = File.ReadAllBytes(file);
            var fileHash = GenerateHashByte("blob", fileContentInBytes);
            string mode = "100644"; // Basic mode detection

            // Check executable attribute on non-Windows
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var fileInfo = new FileInfo(file);
                if ((fileInfo.Attributes & FileAttributes.System) == 0)
                {
                    try
                    {
                        if ((File.GetUnixFileMode(file) & UnixFileMode.UserExecute) != 0)
                        {
                            mode = "100755";
                        }
                    }
                    catch { /* ignore errors */ }
                }
            }

            entries.Add(new TreeEntry(mode, fileName, fileHash));
        }

        foreach (var directory in Directory.GetDirectories(currentPath))
        {
            var directoryName = Path.GetFileName(directory);
            if (directoryName == ".git") continue;
            var directoryHash = GenerateTreeObjectFileHash(directory);
            if (directoryHash != null)
            {
                entries.Add(new TreeEntry("40000", directoryName, directoryHash));
            }
        }

        // Return null for empty non-.git dirs? Or empty tree hash?
        if (!entries.Any()) return null; 
        var treeContent = CreateTreeObjectContent(entries);
        return GenerateHashByte("tree", treeContent);
    }

    static byte[] CreateTreeObjectContent(List<TreeEntry> treeEntries)
    {
        treeEntries.Sort((x, y) =>
        {
            byte[] xBytes = Encoding.UTF8.GetBytes(x.FileName);
            byte[] yBytes = Encoding.UTF8.GetBytes(y.FileName);
            int len = Math.Min(xBytes.Length, yBytes.Length);
            for (int i = 0; i < len; i++)
            {
                if (xBytes[i] != yBytes[i]) return xBytes[i].CompareTo(yBytes[i]);
            }
            return xBytes.Length.CompareTo(yBytes.Length);
        });

        using var memoryStream = new MemoryStream();
        foreach (var entry in treeEntries)
        {
            byte[] modeBytes = Encoding.UTF8.GetBytes(entry.Mode + " ");
            byte[] nameBytes = Encoding.UTF8.GetBytes(entry.FileName);
            byte[] nullByte = { 0 };

            memoryStream.Write(modeBytes, 0, modeBytes.Length);
            memoryStream.Write(nameBytes, 0, nameBytes.Length);
            memoryStream.Write(nullByte, 0, 1);
            memoryStream.Write(entry.Hash, 0, entry.Hash.Length);
        }
        return memoryStream.ToArray();
    }

    // --- Clone Specific Helpers ---

    static async Task<string> ReadPktLine(Stream stream)
    {
        byte[] lengthBytes = new byte[4];
        int totalRead = 0;
        while (totalRead < 4)
        {
            int read = await stream.ReadAsync(lengthBytes, totalRead, 4 - totalRead);
            if (read == 0) return "";
            totalRead += read;
        }

        string lengthHex = Encoding.ASCII.GetString(lengthBytes);
        if (lengthHex == "0000") return "0000";

        if (!int.TryParse(lengthHex, System.Globalization.NumberStyles.HexNumber, null, out int length))
            throw new InvalidDataException($"Invalid pkt-line length: {lengthHex}");

        if (length < 4) throw new InvalidDataException($"Invalid pkt-line length value: {length}");
        if (length == 4) return ""; // Null packet

        int dataLength = length - 4;
        byte[] dataBytes = new byte[dataLength];
        totalRead = 0;
        while (totalRead < dataLength)
        {
            int read = await stream.ReadAsync(dataBytes, totalRead, dataLength - totalRead);
            if (read == 0) throw new EndOfStreamException("Unexpected end of stream while reading pkt-line data.");
            totalRead += read;
        }

        // Trim trailing newline if present
        if (dataBytes.LastOrDefault() == '\n')
            return Encoding.UTF8.GetString(dataBytes, 0, dataBytes.Length - 1);
        else
            return Encoding.UTF8.GetString(dataBytes);
    }

    static async Task<Dictionary<string, string>> ParseInfoRefs(Stream stream)
    {
        var refs = new Dictionary<string, string>();

        string firstLine = await ReadPktLine(stream); // Read # service=... line
        if (!firstLine.StartsWith("# service=git-upload-pack"))
        {
            Console.Error.WriteLine($"Warning: Expected '# service=git-upload-pack', got '{firstLine}'");
        }
        await ReadPktLine(stream); // flush packet after service line

        string? headSymRefTarget = null;

        while (true)
        {
            string line = await ReadPktLine(stream);
            if (line == "0000") break;

            string[] parts = line.Split(' ');
            if (parts.Length < 2) continue;

            string hash = parts[0];
            string refName = parts[1];

            // Check for capabilities on the first ref line (usually HEAD)
            if (parts.Length > 2 && refName == "HEAD")
            {
                foreach (string capability in parts.Skip(2))
                {
                    if (capability.StartsWith("symref=HEAD:"))
                    {
                        headSymRefTarget = capability.Substring("symref=HEAD:".Length);
                    }
                }
            }

            if (refName.EndsWith("^{}")) // Peeled tag
            {
                string baseTagName = refName.Substring(0, refName.Length - 3);
                if (!refs.ContainsKey(baseTagName)) refs[baseTagName] = hash; 
            }
            else
            {
                refs[refName] = hash;
            }
        }

        // Ensure HEAD points to the actual commit hash
        if (headSymRefTarget != null && refs.ContainsKey(headSymRefTarget))
        {
            refs["HEAD"] = refs[headSymRefTarget];
        }
        else if (refs.ContainsKey("HEAD") && headSymRefTarget != null)
        {
            Console.Error.WriteLine($"Warning: HEAD is symref to '{headSymRefTarget}' but target ref was not found.");
        }
        else if (!refs.ContainsKey("HEAD"))
        {
            Console.Error.WriteLine("Warning: Could not resolve HEAD commit hash.");
        }

        return refs;
    }

    static async Task ProcessPackfile(Stream packStream)
    {
        _packObjectsByOffset.Clear();
        _packObjectsByHash.Clear();

        using var bufferedStream = new BufferedStream(packStream);
        using var reader = new BinaryReader(bufferedStream, Encoding.ASCII, true);

        byte[] signature = reader.ReadBytes(4);
        if (Encoding.ASCII.GetString(signature) != "PACK") 
            throw new InvalidDataException("Invalid packfile signature.");
        uint version = ReadNetworkUInt32(reader);
        if (version != 2)
            throw new NotSupportedException($"Unsupported packfile version: {version}");
        uint objectCount = ReadNetworkUInt32(reader);
        Console.WriteLine($"Packfile contains {objectCount} objects.");

        List<PackObject> readObjects = new List<PackObject>();

        for (uint i = 0; i < objectCount; i++)
        {
            long approxOffset = -1; // not strictly tracked in this example
            try
            {
                var packObject = await ReadPackObjectFromReader(reader, approxOffset);
                if (packObject != null)
                {
                    readObjects.Add(packObject);
                    _packObjectsByOffset[packObject.Offset] = packObject;
                }
                else
                {
                    Console.Error.WriteLine($"Warning: Failed to read object #{i + 1}. Skipping.");
                    break;
                }
            }
            catch (EndOfStreamException ex)
            {
                Console.Error.WriteLine($"Error reading object #{i + 1}: Unexpected end of stream. {ex.Message}");
                break;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error reading object #{i + 1}: {ex.Message}\n{ex.StackTrace}");
                break;
            }
        }

        Console.WriteLine($"Finished reading raw objects. Resolving deltas and storing...");
        foreach (var obj in readObjects)
        {
            try { StorePackObject(obj); }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error storing object originally at offset {obj.Offset}: {ex.Message}");
            }
        }
        Console.WriteLine("Finished processing packfile.");
    }

    static async Task<PackObject?> ReadPackObjectFromReader(BinaryReader reader, long approxObjectOffset)
    {
        byte firstByte = reader.ReadByte();
        int typeNum = (firstByte >> 4) & 7;
        long size = firstByte & 0x0F;
        int shift = 4;
        while ((firstByte & 0x80) != 0)
        {
            firstByte = reader.ReadByte();
            size |= (long)(firstByte & 0x7F) << shift;
            shift += 7;
        }

        string type = typeNum switch
        {
            1 => "commit",
            2 => "tree",
            3 => "blob",
            4 => "tag",
            6 => "ofs_delta",
            7 => "ref_delta",
            _ => throw new NotSupportedException($"Unsupported pack object type: {typeNum} at offset ~{approxObjectOffset}")
        };

        long baseOffset = -1;
        string? baseHash = null;
        long actualObjectOffsetForDelta = -1;

        if (type == "ofs_delta")
        {
            long negativeOffset = ReadVariableLengthOffset(reader);
            baseOffset = negativeOffset;
            actualObjectOffsetForDelta = approxObjectOffset;
        }
        else if (type == "ref_delta")
        {
            byte[] hashBytes = reader.ReadBytes(20);
            baseHash = Convert.ToHexString(hashBytes).ToLower();
        }

        using var decompressedStream = new MemoryStream();
        try
        {
            using (var zlibStream = new ZLibStream(reader.BaseStream, CompressionMode.Decompress, true))
            {
                await zlibStream.CopyToAsync(decompressedStream);
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error during ZLib decompression for object type {type}: {ex.Message}");
            return null;
        }

        byte[] data = decompressedStream.ToArray();

        if (typeNum >= 1 && typeNum <= 4 && data.Length != (int)size)
        {
            Console.Error.WriteLine($"Warning: Decompressed size mismatch for {type}. Expected {size}, got {data.Length}.");
        }

        return new PackObject(type, data, actualObjectOffsetForDelta, baseOffset, baseHash);
    }

    static long ReadVariableLengthOffset(BinaryReader reader)
    {
        long offset = 0;
        byte currentByte;
        int shift = 0;
        do
        {
            currentByte = reader.ReadByte();
            if (shift == 0)
            {
                offset = currentByte & 0x7F;
            }
            else
            {
                offset += 1;
                offset <<= 7;
                offset |= (currentByte & 0x7F);
            }
            shift += 7;
        } while ((currentByte & 0x80) != 0);

        return offset;
    }

    static uint ReadNetworkUInt32(BinaryReader reader)
    {
        byte[] bytes = reader.ReadBytes(4);
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
        return BitConverter.ToUInt32(bytes, 0);
    }

    static string StorePackObject(PackObject packObject)
    {
        string potentialHash = CalculateObjectHash(packObject.Type, packObject.Data);
        if (_packObjectsByHash.ContainsKey(potentialHash))
        {
            return potentialHash;
        }

        byte[] finalData;
        string objectType = packObject.Type;

        if (packObject.Type == "ofs_delta" || packObject.Type == "ref_delta")
        {
            PackObject baseObject = FindBaseObject(packObject);
            string baseHash = StorePackObject(baseObject);
            byte[] baseData = ReadObjectDataFromAnywhere(baseHash);

            finalData = ApplyDelta(baseData, packObject.Data);
            objectType = baseObject.Type;
        }
        else
        {
            finalData = packObject.Data;
            objectType = packObject.Type;
        }

        byte[] hashBytes = GenerateHashByte(objectType, finalData);
        string hashString = Convert.ToHexString(hashBytes).ToLower();

        _packObjectsByHash[hashString] = new PackObject(objectType, finalData, -1);

        return hashString;
    }

    static string CalculateObjectHash(string objectType, byte[] contentBytes)
    {
        var objectHeader = CreateObjectHeaderInBytes(objectType, contentBytes.Length);
        var gitObject = new byte[objectHeader.Length + contentBytes.Length];
        Buffer.BlockCopy(objectHeader, 0, gitObject, 0, objectHeader.Length);
        Buffer.BlockCopy(contentBytes, 0, gitObject, objectHeader.Length, contentBytes.Length);

        var hash = SHA1.HashData(gitObject);
        return Convert.ToHexString(hash).ToLower();
    }

    static PackObject FindBaseObject(PackObject deltaObject)
    {
        if (deltaObject.Type == "ofs_delta")
        {
            long negativeOffset = deltaObject.BaseOffset;
            long absoluteBaseOffset = deltaObject.Offset - negativeOffset;

            if (_packObjectsByOffset.TryGetValue(absoluteBaseOffset, out PackObject baseObj))
            {
                return baseObj;
            }
            else
            {
                foreach (var kvp in _packObjectsByHash)
                {
                    if (kvp.Value.Offset == absoluteBaseOffset && kvp.Value.Offset != -1)
                    {
                        return kvp.Value;
                    }
                }
                throw new InvalidOperationException($"Base object not found at offset {absoluteBaseOffset} for delta at {deltaObject.Offset}");
            }
        }
        else if (deltaObject.Type == "ref_delta")
        {
            string baseHash = deltaObject.BaseHash!;
            if (_packObjectsByHash.TryGetValue(baseHash, out PackObject baseObjByHash))
            {
                return baseObjByHash;
            }
            if (ObjectExists(baseHash))
            {
                byte[] rawData = ReadObject(baseHash);
                int nullByteIndex = Array.IndexOf(rawData, (byte)0);
                string header = Encoding.UTF8.GetString(rawData, 0, nullByteIndex);
                string[] headerParts = header.Split(' ');
                string baseType = headerParts[0];
                byte[] baseContent = rawData.Skip(nullByteIndex + 1).ToArray();

                var diskBase = new PackObject(baseType, baseContent, -2, -1, baseHash);
                _packObjectsByHash[baseHash] = diskBase;
                return diskBase;
            }
            else
            {
                foreach (var kvp in _packObjectsByOffset)
                {
                    var potentialBase = kvp.Value;
                    if (potentialBase.Type != "ofs_delta" && potentialBase.Type != "ref_delta")
                    {
                        string potentialHash = CalculateObjectHash(potentialBase.Type, potentialBase.Data);
                        if (potentialHash == baseHash)
                        {
                            return potentialBase;
                        }
                    }
                }
                throw new InvalidOperationException($"Base object with hash {baseHash} not found for delta at {deltaObject.Offset}");
            }
        }
        else
        {
            throw new ArgumentException("Object is not a delta object.");
        }
    }

    static bool ObjectExists(string hash)
    {
        string path = Path.Combine(".git", "objects", hash.Substring(0, 2), hash.Substring(2));
        return File.Exists(path);
    }

    static byte[] ReadObjectDataFromAnywhere(string hash)
    {
        if (_packObjectsByHash.TryGetValue(hash, out PackObject cachedObj))
        {
            if (cachedObj.Type == "ofs_delta" || cachedObj.Type == "ref_delta")
            {
                throw new InvalidOperationException($"Attempted to read data from unresolved delta object {hash} in cache.");
            }
            return cachedObj.Data;
        }
        if (ObjectExists(hash))
        {
            byte[] rawData = ReadObject(hash);
            int nullByteIndex = Array.IndexOf(rawData, (byte)0);
            if (nullByteIndex == -1) throw new InvalidDataException($"Invalid object format on disk for {hash}");
            return rawData.Skip(nullByteIndex + 1).ToArray();
        }
        throw new FileNotFoundException($"Object {hash} not found in cache or on disk.");
    }

    static byte[] ApplyDelta(byte[] baseData, byte[] deltaInstructions)
    {
        using var deltaStream = new MemoryStream(deltaInstructions);
        using var reader = new BinaryReader(deltaStream);

        long expectedBaseSize = ReadVariableLengthInt(reader);
        if (expectedBaseSize != baseData.Length)
            throw new InvalidDataException($"Delta base size mismatch: expected {baseData.Length}, got {expectedBaseSize}");

        long targetSize = ReadVariableLengthInt(reader);

        using var targetStream = new MemoryStream((int)targetSize);
        while (deltaStream.Position < deltaStream.Length)
        {
            byte instruction = reader.ReadByte();
            if ((instruction & 0x80) != 0) // Copy
            {
                long copyOffset = 0;
                long copySize = 0;
                int shift = 0;

                if ((instruction & 0x01) != 0) { copyOffset |= (long)reader.ReadByte() << shift; shift += 8; }
                if ((instruction & 0x02) != 0) { copyOffset |= (long)reader.ReadByte() << shift; shift += 8; }
                if ((instruction & 0x04) != 0) { copyOffset |= (long)reader.ReadByte() << shift; shift += 8; }
                if ((instruction & 0x08) != 0) { copyOffset |= (long)reader.ReadByte() << shift; shift += 8; }

                shift = 0;
                if ((instruction & 0x10) != 0) { copySize |= (long)reader.ReadByte() << shift; shift += 8; }
                if ((instruction & 0x20) != 0) { copySize |= (long)reader.ReadByte() << shift; shift += 8; }
                if ((instruction & 0x40) != 0) { copySize |= (long)reader.ReadByte() << shift; shift += 8; }

                if (copySize == 0) copySize = 0x10000;

                if (copyOffset + copySize > baseData.Length)
                    throw new InvalidDataException(
                        $"Delta copy instruction exceeds base data boundaries (offset={copyOffset}, size={copySize}, baseSize={baseData.Length}).");

                targetStream.Write(baseData, (int)copyOffset, (int)copySize);
            }
            else // Add
            {
                byte addSize = (byte)(instruction & 0x7F);
                if (addSize == 0)
                    throw new InvalidDataException("Delta add instruction has zero size.");
                byte[] dataToAdd = reader.ReadBytes(addSize);
                targetStream.Write(dataToAdd, 0, dataToAdd.Length);
            }
        }

        if (targetStream.Length != targetSize)
        {
            Console.Error.WriteLine($"Warning: Delta application result size mismatch: expected {targetSize}, got {targetStream.Length}");
        }

        return targetStream.ToArray();
    }

    static long ReadVariableLengthInt(BinaryReader reader)
    {
        long value = 0;
        byte currentByte;
        int shift = 0;
        do
        {
            currentByte = reader.ReadByte();
            value |= (long)(currentByte & 0x7F) << shift;
            shift += 7;
        } while ((currentByte & 0x80) != 0);
        return value;
    }

    static void CheckoutHead(string commitHash)
    {
        try
        {
            byte[] commitRawData = ReadObject(commitHash);
            int nullByteIndex = Array.IndexOf(commitRawData, (byte)0);
            if (nullByteIndex == -1) 
                throw new InvalidDataException($"Invalid commit object format: {commitHash}");
            string commitContent = Encoding.UTF8.GetString(commitRawData, nullByteIndex + 1, commitRawData.Length - (nullByteIndex + 1));
            string? treeHash = null;

            using (var reader = new StringReader(commitContent))
            {
                string? line;
                while ((line = reader.ReadLine()) != null)
                {
                    if (line.StartsWith("tree "))
                    {
                        treeHash = line.Substring(5).Trim();
                        break;
                    }
                }
            }
            if (string.IsNullOrEmpty(treeHash))
                throw new InvalidDataException($"Could not find tree hash in commit object: {commitHash}");

            string headRefPath = Path.Combine(".git", "HEAD");
            string headContent = File.ReadAllText(headRefPath).Trim();
            if (headContent.StartsWith("ref: "))
            {
                string refName = headContent.Substring(5).Trim();
                string refPath = Path.Combine(".git", refName);
                Directory.CreateDirectory(Path.GetDirectoryName(refPath)!);
                File.WriteAllText(refPath, commitHash + "\n");
            }
            else
            {
                File.WriteAllText(headRefPath, commitHash + "\n");
            }

            Console.WriteLine($"Checking out tree {treeHash}");
            ClearWorkingDirectory();
            CheckoutTree(treeHash, Directory.GetCurrentDirectory());
        }
        catch (FileNotFoundException)
        {
            Console.Error.WriteLine($"Error: Commit object {commitHash} not found.");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error during checkout: {ex.Message}\n{ex.StackTrace}");
        }
    }

    static void ClearWorkingDirectory()
    {
        string currentDir = Directory.GetCurrentDirectory();
        foreach (string file in Directory.GetFiles(currentDir))
        {
            if (Path.GetFileName(file) == ".git") continue;
            try
            {
                File.Delete(file);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Could not delete file {file}: {ex.Message}");
            }
        }
        foreach (string dir in Directory.GetDirectories(currentDir))
        {
            if (Path.GetFileName(dir) == ".git") continue;
            try
            {
                Directory.Delete(dir, true);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Could not delete directory {dir}: {ex.Message}");
            }
        }
    }

    static void CheckoutTree(string treeHash, string basePath)
    {
        byte[] treeRawData = ReadObject(treeHash);
        int headerEnd = Array.IndexOf(treeRawData, (byte)0);
        if (headerEnd == -1)
            throw new InvalidDataException($"Invalid tree object format: {treeHash}");

        int currentPos = headerEnd + 1;
        while (currentPos < treeRawData.Length)
        {
            int spaceIndex = Array.IndexOf(treeRawData, (byte)' ', currentPos);
            if (spaceIndex == -1) break;
            string mode = Encoding.UTF8.GetString(treeRawData, currentPos, spaceIndex - currentPos);

            int nullIndex = Array.IndexOf(treeRawData, (byte)0, spaceIndex + 1);
            if (nullIndex == -1) break;
            string name = Encoding.UTF8.GetString(treeRawData, spaceIndex + 1, nullIndex - (spaceIndex + 1));

            byte[] hashBytes = new byte[20];
            Buffer.BlockCopy(treeRawData, nullIndex + 1, hashBytes, 0, 20);
            string entryHash = Convert.ToHexString(hashBytes).ToLower();

            string fullPath = Path.Combine(basePath, name);

            if (mode == "40000") // Directory
            {
                Directory.CreateDirectory(fullPath);
                CheckoutTree(entryHash, fullPath);
            }
            else if (mode == "120000") // Symbolic Link
            {
                try
                {
                    byte[] blobRawData = ReadObject(entryHash);
                    int blobHeaderEnd = Array.IndexOf(blobRawData, (byte)0);
                    if (blobHeaderEnd == -1)
                        throw new InvalidDataException($"Invalid blob object format for symlink: {entryHash}");

                    byte[] targetPathBytes = new byte[blobRawData.Length - (blobHeaderEnd + 1)];
                    Buffer.BlockCopy(blobRawData, blobHeaderEnd + 1, targetPathBytes, 0, targetPathBytes.Length);
                    string targetPath = Encoding.UTF8.GetString(targetPathBytes);

                    File.CreateSymbolicLink(fullPath, targetPath);
                }
                catch (FileNotFoundException)
                {
                    Console.Error.WriteLine($"Error: Blob object {entryHash} for symlink '{name}' not found.");
                }
                catch (UnauthorizedAccessException)
                {
                    Console.Error.WriteLine($"Error: Insufficient permissions to create symbolic link '{fullPath}'.");
                }
                catch (IOException ioEx) when (ioEx.Message.Contains("symbolic link"))
                {
                    Console.Error.WriteLine($"Error: Could not create symbolic link '{fullPath}'. OS support/privileges? {ioEx.Message}");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Error creating symlink {fullPath}: {ex.Message}");
                }
            }
            else // Regular File (100644, 100755)
            {
                try
                {
                    byte[] blobRawData = ReadObject(entryHash);
                    int blobHeaderEnd = Array.IndexOf(blobRawData, (byte)0);
                    if (blobHeaderEnd == -1)
                        throw new InvalidDataException($"Invalid blob object format: {entryHash}");

                    byte[] blobContent = new byte[blobRawData.Length - (blobHeaderEnd + 1)];
                    Buffer.BlockCopy(blobRawData, blobHeaderEnd + 1, blobContent, 0, blobContent.Length);

                    File.WriteAllBytes(fullPath, blobContent);

                    if (mode == "100755" && (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || 
                                             RuntimeInformation.IsOSPlatform(OSPlatform.OSX)))
                    {
                        try
                        {
                            File.SetUnixFileMode(fullPath,
                                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                                UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                                UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
                        }
                        catch (Exception ex)
                        {
                            Console.Error.WriteLine($"Warning: Could not set executable permissions for {fullPath}: {ex.Message}");
                        }
                    }
                }
                catch (FileNotFoundException)
                {
                    Console.Error.WriteLine($"Error: Blob object {entryHash} for file '{name}' not found.");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Error writing file {fullPath}: {ex.Message}");
                }
            }
            currentPos = nullIndex + 1 + 20;
        }
    }
}