using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic; // Added for Dictionary/List
using System.Linq; // Added for LINQ methods like ToDictionary, Skip
using System.Net.Http; // Added for HttpClient
using System; // Added for Array, Math, etc.
using System.Threading.Tasks; // Added for Task
using System.IO; // Added for Path, File, Directory, Stream etc.

// Represents a Git object entry within a tree
public record TreeEntry(string Mode, string FileName, byte[] Hash);

// Represents a parsed object from a packfile (or resolved object)
// Offset: Stores the absolute offset where the object *header* started in the packfile.
//         -1 indicates not applicable (e.g., resolved object not directly from pack offset).
//         -2 indicates object was loaded from loose object store.
// BaseOffset: Stores the *relative* negative offset for ofs_delta.
public record PackObject(string Type, byte[] Data, long Offset, long BaseOffset = -1, string? BaseHash = null);

public class Program
{
    // Stores PackObject records as read initially from the packfile, keyed by their absolute starting offset.
    private static Dictionary<long, PackObject> _packObjectsByOffset = new();
    // Stores fully resolved PackObjects (base types only), keyed by their SHA-1 hash.
    // Also used as a cache during delta resolution.
    private static Dictionary<string, PackObject> _packObjectsByHash = new();

    public static async Task Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("Please provide a command.");
            return;
        }
        string command = args[0];

        // Wrap command execution in a try-catch for better top-level error handling
        try
        {
            if (command == "init")
            {
                InitRepository();
            }
            else if (command == "cat-file" && args.Length > 2 && args[1] == "-p")
            {
                CatFile(args[2]);
            }
            else if (command == "hash-object" && args.Length > 2 && args[1] == "-w")
            {
                HashObject(args[2]);
            }
            else if (command == "ls-tree" && args.Length > 2 && args[1] == "--name-only")
            {
                LsTree(args[2]);
            }
            else if (command == "write-tree")
            {
                WriteTree();
            }
            else if (command == "commit-tree")
            {
                if (args.Length < 6 || args[2] != "-p" || args[4] != "-m")
                {
                    Console.WriteLine("Usage: commit-tree <tree_sha> -p <parent_sha> -m <message>");
                    return;
                }
                CommitTree(args[1], args[3], args[5]);
            }
            else if (command == "clone")
            {
                if (args.Length < 3)
                {
                    Console.WriteLine("Usage: clone <repository_url> <target_directory>");
                    return;
                }
                await CloneRepository(args[1], args[2]);
            }
            else
            {
                Console.Error.WriteLine($"Unknown command {command}");
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"An unexpected error occurred: {ex.Message}");
            Console.Error.WriteLine(ex.StackTrace);
            // Optionally set an exit code here
        }
    }

    // --- Command Implementations ---

    static void InitRepository()
    {
        Directory.CreateDirectory(".git");
        Directory.CreateDirectory(".git/objects");
        Directory.CreateDirectory(".git/refs");
        Directory.CreateDirectory(".git/refs/heads"); // Also create heads dir
        File.WriteAllText(".git/HEAD", "ref: refs/heads/main\n");
        Console.WriteLine("Initialized git directory");
    }

    static void CatFile(string hash)
    {
        try
        {
            byte[] data = ReadObject(hash); // Reads raw object (header + content)
            int nullByteIndex = Array.IndexOf(data, (byte)0);
            if (nullByteIndex == -1)
            {
                Console.Error.WriteLine($"Error: Invalid object format for {hash}");
                return;
            }
            // Extract content after the null byte
            string content = Encoding.UTF8.GetString(data, nullByteIndex + 1, data.Length - (nullByteIndex + 1));
            Console.Write(content);
        }
        catch (FileNotFoundException)
        {
            Console.Error.WriteLine($"Error: Object {hash} not found.");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"An error occurred in cat-file: {ex.Message}");
        }
    }

    static void HashObject(string filePath)
    {
        try
        {
            byte[] fileContentBytes = File.ReadAllBytes(filePath);
            // GenerateAndWriteHash calculates hash, writes object, returns hash string
            string hash = GenerateAndWriteHash("blob", fileContentBytes);
            Console.WriteLine(hash);
        }
        catch (FileNotFoundException)
        {
             Console.Error.WriteLine($"Error: File not found: {filePath}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"An error occurred in hash-object: {ex.Message}");
        }
    }

     static void LsTree(string treeHash)
    {
        try
        {
            byte[] treeData = ReadObject(treeHash); // Reads raw object (header + content)
            int headerEnd = Array.IndexOf(treeData, (byte)0);
             if (headerEnd == -1)
             {
                 Console.Error.WriteLine($"Error: Invalid tree object format for {treeHash}");
                 return;
             }

            int currentPos = headerEnd + 1;
            while (currentPos < treeData.Length)
            {
                // Find space separating mode and filename
                int spaceIndex = Array.IndexOf(treeData, (byte)' ', currentPos);
                if (spaceIndex == -1) break; // Malformed entry

                // Find null byte terminating filename
                int nullIndex = Array.IndexOf(treeData, (byte)0, spaceIndex + 1);
                if (nullIndex == -1) break; // Malformed entry

                // Extract filename
                string fileName = Encoding.UTF8.GetString(treeData, spaceIndex + 1, nullIndex - (spaceIndex + 1));
                Console.WriteLine(fileName);

                // Move position past the null byte and the 20-byte hash
                currentPos = nullIndex + 1 + 20;
            }
        }
        catch (FileNotFoundException)
        {
            Console.Error.WriteLine($"Error: Tree object {treeHash} not found.");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"An error occurred in ls-tree: {ex.Message}");
        }
    }

    static void WriteTree()
    {
        try
        {
            var currentPath = Directory.GetCurrentDirectory();
            // GenerateTreeObjectHash now returns string hash or null
            var hashString = GenerateTreeObjectHash(currentPath);

            if (hashString != null)
            {
                Console.Write(hashString);
            }
            else // Handle empty directory case
            {
                // Standard hash for an empty tree
                Console.Write("4b825dc642cb6eb9a060e54bf8d69288fbee4904");
                // Optionally, write the empty tree object if it doesn't exist
                GenerateAndWriteHash("tree", Array.Empty<byte>());
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"An error occurred in write-tree: {ex.Message}");
            Console.Error.WriteLine(ex.StackTrace);
        }
    }

    static void CommitTree(string treeSha, string parentSha, string message)
    {
        try
        {
            // Basic validation (could add SHA format check)
            if (string.IsNullOrWhiteSpace(treeSha) || string.IsNullOrWhiteSpace(parentSha) || string.IsNullOrWhiteSpace(message))
            {
                 Console.WriteLine("Error: Tree SHA, Parent SHA, and message cannot be empty.");
                 return;
            }

            // TODO: Get author/committer info from config or environment variables
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
            commitContent.AppendLine(); // Blank line separator
            commitContent.AppendLine(message);

            byte[] commitBytes = Encoding.UTF8.GetBytes(commitContent.ToString());
            // GenerateAndWriteHash calculates hash, writes object, returns hash string
            string hashString = GenerateAndWriteHash("commit", commitBytes);
            Console.WriteLine(hashString);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"An error occurred in commit-tree: {ex.Message}");
        }
    }

    static async Task CloneRepository(string repoUrl, string targetDir)
    {
        repoUrl = repoUrl.TrimEnd('/'); // Normalize URL

        if (Directory.Exists(targetDir))
        {
            // Check if directory is empty (safer than just Any())
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

            // Initialize the local repository structure
            InitRepository(); // Use the init function

            Console.WriteLine($"Cloning into '{Path.GetFileName(targetDir)}'...");

            using (var client = new HttpClient())
            {
                // Standard Git User-Agent helps with some servers
                client.DefaultRequestHeaders.UserAgent.ParseAdd("git/git-csharp-client-0.1");
                client.DefaultRequestHeaders.Accept.ParseAdd("application/x-git-upload-pack-result");

                // 1. Fetch refs
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
                    Console.Error.WriteLine("No refs found on remote repository.");
                    return; // Or handle empty repo case
                }

                // 2. Determine HEAD commit
                string? headCommit = null;
                string? headRefName = null;
                // Prefer finding HEAD via symref
                if (refs.TryGetValue("HEAD", out string headTargetRef) && refs.TryGetValue(headTargetRef, out string targetCommit))
                {
                    headCommit = targetCommit;
                    headRefName = headTargetRef;
                }
                else // Fallback to common branch names
                {
                     if (refs.TryGetValue("refs/heads/main", out string mainCommit)) {
                         headCommit = mainCommit;
                         headRefName = "refs/heads/main";
                     } else if (refs.TryGetValue("refs/heads/master", out string masterCommit)) {
                         headCommit = masterCommit;
                         headRefName = "refs/heads/master";
                     }
                }


                if (string.IsNullOrEmpty(headCommit) || string.IsNullOrEmpty(headRefName))
                {
                    Console.Error.WriteLine("Could not determine HEAD commit or ref name from available refs:");
                    foreach (var kvp in refs) Console.WriteLine($"- {kvp.Value} {kvp.Key}");
                    return;
                }

                Console.WriteLine($"Determined HEAD commit: {headCommit} ({headRefName})");
                // Update local HEAD to point to the determined remote HEAD ref
                File.WriteAllText(".git/HEAD", $"ref: {headRefName}\n");
                // Optionally, write the ref file itself immediately (e.g., .git/refs/heads/main)
                // string headRefPath = Path.Combine(".git", headRefName);
                // Directory.CreateDirectory(Path.GetDirectoryName(headRefPath)!);
                // File.WriteAllText(headRefPath, headCommit + "\n");
                // Note: CheckoutHead will also update this ref file later.

                // 3. Request packfile for the HEAD commit
                string uploadPackUrl = $"{repoUrl}/git-upload-pack";
                Console.WriteLine($"Requesting packfile from {uploadPackUrl}");

                // Construct pkt-line request body
                StringBuilder sb = new StringBuilder();
                string wantLine = $"want {headCommit}\n";
                // Format: "XXXXwant <hash>\n" where XXXX is hex length
                sb.Append($"{wantLine.Length + 4:x4}{wantLine}");
                // Add capabilities if needed (e.g., multi_ack, side-band-64k) - omitted for simplicity
                sb.Append("0000"); // Flush packet
                sb.Append("0009done\n"); // Done command

                string requestBody = sb.ToString();
                // Console.WriteLine($"DEBUG: Sending request body (pkt-line):{requestBody.Replace("\n", "\\n")}"); // Keep for debugging if needed

                var content = new StringContent(requestBody, Encoding.UTF8, "application/x-git-upload-pack-request");
                HttpResponseMessage packResponse = await client.PostAsync(uploadPackUrl, content);

                if (!packResponse.IsSuccessStatusCode)
                {
                    Console.Error.WriteLine($"Failed to fetch pack: {packResponse.StatusCode}");
                    string errorContent = await packResponse.Content.ReadAsStringAsync();
                    Console.Error.WriteLine($"Server response: {errorContent}");
                    return;
                }

                Console.WriteLine("Receiving packfile...");
                using var packStream = await packResponse.Content.ReadAsStreamAsync();

                // 4. Process the packfile response
                // Skip initial pkt-line headers/messages before the "PACK" signature
                await SkipPackResponseHeaders(packStream);
                // Process the actual pack data
                await ProcessPackfile(packStream);

                // 5. Checkout the downloaded HEAD commit
                Console.WriteLine($"Checking out commit {headCommit}");
                CheckoutHead(headCommit); // This reads objects ProcessPackfile should have stored

                Console.WriteLine($"Successfully cloned repository to {targetDir}");
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"An error occurred during clone: {ex.Message}");
            Console.Error.WriteLine(ex.StackTrace);
            // Consider cleaning up the partially cloned directory
        }
        finally
        {
            // Reset caches regardless of success or failure
            _packObjectsByOffset.Clear();
            _packObjectsByHash.Clear();
            // Change back to the original directory
            Directory.SetCurrentDirectory(originalDirectory);
        }
    }

    // --- Git Object Handling ---

    // Reads a raw, compressed object from the loose object store
    static byte[] ReadObject(string hash)
    {
        string path = Path.Combine(".git", "objects", hash.Substring(0, 2), hash.Substring(2));
        if (!File.Exists(path))
        {
            // Provide more context in the exception
            throw new FileNotFoundException($"Object file not found for hash {hash}", path);
        }

        using FileStream fileStream = File.OpenRead(path);
        // Use MemoryStream for intermediate storage before decompression
        using MemoryStream compressedStream = new();
        fileStream.CopyTo(compressedStream);
        compressedStream.Position = 0; // Reset position before reading

        using MemoryStream decompressedStream = new();
        // Decompress using ZLibStream
        using ZLibStream zLibStream = new(compressedStream, CompressionMode.Decompress);
        zLibStream.CopyTo(decompressedStream);

        return decompressedStream.ToArray(); // Return the raw decompressed data (header + content)
    }

    // Creates the object header (e.g., "blob 12\0")
    static byte[] CreateObjectHeaderInBytes(string gitObjectType, long size)
    {
        return Encoding.UTF8.GetBytes($"{gitObjectType} {size}\0");
    }

    // Calculates SHA1 hash, compresses, and writes object to loose object store. Returns hash string.
    static string GenerateAndWriteHash(string gitObjectType, byte[] contentBytes)
    {
        var objectHeader = CreateObjectHeaderInBytes(gitObjectType, contentBytes.Length);
        var gitObject = new byte[objectHeader.Length + contentBytes.Length];
        Buffer.BlockCopy(objectHeader, 0, gitObject, 0, objectHeader.Length);
        Buffer.BlockCopy(contentBytes, 0, gitObject, objectHeader.Length, contentBytes.Length);

        // Calculate hash from the raw object data (header + content)
        var hashBytes = SHA1.HashData(gitObject);
        var hashString = Convert.ToHexString(hashBytes).ToLower();

        // Write the compressed object to disk
        WriteObjectToDiskInternal(hashString, gitObject);

        return hashString;
    }

    // Internal helper to compress and write object bytes using a pre-calculated hash
    static void WriteObjectToDiskInternal(string hashString, byte[] rawGitObjectBytes)
    {
         using var memoryStream = new MemoryStream();
         // Compress the raw object data (header + content)
         using (var zlibStream = new ZLibStream(memoryStream, CompressionLevel.Optimal, true)) // leaveOpen: true
         {
             zlibStream.Write(rawGitObjectBytes, 0, rawGitObjectBytes.Length);
         } // zlibStream is disposed here, flushing the data to memoryStream
         var compressedObject = memoryStream.ToArray();

         // Determine path and write to file
         var objectDir = Path.Combine(".git", "objects", hashString.Substring(0, 2));
         var objectPath = Path.Combine(objectDir, hashString.Substring(2));
         Directory.CreateDirectory(objectDir); // Ensure the subdirectory exists
         File.WriteAllBytes(objectPath, compressedObject);
    }


    // Calculates hash for an object without writing to disk
    static string CalculateObjectHash(string objectType, byte[] contentBytes)
    {
        var objectHeader = CreateObjectHeaderInBytes(objectType, contentBytes.Length);
        var gitObject = new byte[objectHeader.Length + contentBytes.Length];
        Buffer.BlockCopy(objectHeader, 0, gitObject, 0, objectHeader.Length);
        Buffer.BlockCopy(contentBytes, 0, gitObject, objectHeader.Length, contentBytes.Length);

        var hash = SHA1.HashData(gitObject);
        return Convert.ToHexString(hash).ToLower();
    }

    // Checks if a loose object exists
    static bool ObjectExists(string hash)
    {
        string path = Path.Combine(".git", "objects", hash.Substring(0, 2), hash.Substring(2));
        return File.Exists(path);
    }

    // Reads object *content* (without header) from cache or disk
    static byte[] ReadObjectDataFromAnywhere(string hash)
    {
        // Priority 1: Check resolved objects cache
        if (_packObjectsByHash.TryGetValue(hash, out PackObject cachedObj))
        {
            // Ensure it's not an unresolved delta (should be guaranteed by StorePackObject)
            if (cachedObj.Type == "ofs_delta" || cachedObj.Type == "ref_delta")
            {
                // This indicates a logic error in resolution
                throw new InvalidOperationException($"Attempted to read data from unresolved delta object {hash} in cache.");
            }
            return cachedObj.Data; // Return the cached, resolved data
        }

        // Priority 2: Check loose objects on disk
        if (ObjectExists(hash))
        {
            byte[] rawData = ReadObject(hash); // Reads and decompresses raw object (header + content)
            int nullByteIndex = Array.IndexOf(rawData, (byte)0);
            if (nullByteIndex == -1) throw new InvalidDataException($"Invalid object format on disk for {hash}");
            // Return only the content part after the null byte
            return rawData.Skip(nullByteIndex + 1).ToArray();
        }

        // If not found, the object is missing
        throw new FileNotFoundException($"Object {hash} not found in cache or on disk.");
    }


    // --- Tree Object Generation ---

    // Recursively generates tree objects and returns the root tree hash string
    static string? GenerateTreeObjectHash(string currentPath)
    {
        // Ignore .git directory itself
        if (Path.GetFileName(currentPath).Equals(".git", StringComparison.OrdinalIgnoreCase)) return null;

        var entries = new List<TreeEntry>();

        // Process files
        foreach (var file in Directory.GetFiles(currentPath))
        {
            string fileName = Path.GetFileName(file);
            // Basic ignore (can be expanded)
            if (fileName.Equals(".git", StringComparison.OrdinalIgnoreCase)) continue;

            var fileContentInBytes = File.ReadAllBytes(file);
            // Generate hash for the blob and write the blob object
            var fileHashString = GenerateAndWriteHash("blob", fileContentInBytes);
            var fileHashBytes = Convert.FromHexString(fileHashString); // Convert hash string back to bytes for TreeEntry

            // Determine mode (basic implementation)
            string mode = "100644"; // Default mode for non-executable files
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                try
                {
                    // Check execute permission on Unix-like systems
                    if ((File.GetUnixFileMode(file) & UnixFileMode.UserExecute) != 0)
                    {
                        mode = "100755"; // Executable file mode
                    }
                }
                catch (Exception ex) {
                    Console.Error.WriteLine($"Warning: Could not get Unix file mode for {file}: {ex.Message}");
                    // Keep default mode if check fails
                 }
            }
            entries.Add(new TreeEntry(mode, fileName, fileHashBytes));
        }

        // Process directories recursively
        foreach (var directory in Directory.GetDirectories(currentPath))
        {
            var directoryName = Path.GetFileName(directory);
            if (directoryName.Equals(".git", StringComparison.OrdinalIgnoreCase)) continue;

            // Recursively generate hash for the subdirectory
            var directoryHashString = GenerateTreeObjectHash(directory);
            if (directoryHashString != null)
            {
                var directoryHashBytes = Convert.FromHexString(directoryHashString);
                entries.Add(new TreeEntry("040000", directoryName, directoryHashBytes)); // Mode for directory
            }
            // If directoryHashString is null, the directory was empty or only contained .git, so skip it.
        }

        // If no entries (empty directory), return null
        if (!entries.Any()) return null;

        // Create tree content and generate/write the tree object
        var treeContent = CreateTreeObjectContent(entries);
        return GenerateAndWriteHash("tree", treeContent);
    }

    // Creates the byte content for a tree object from its entries
    static byte[] CreateTreeObjectContent(List<TreeEntry> treeEntries)
    {
        // Sort entries according to Git's rules (byte order of filenames)
        treeEntries.Sort((x, y) =>
        {
            // Git sorts directories as if they have a trailing slash for comparison purposes,
            // but the actual entry doesn't store the slash. We simulate this by comparing
            // name bytes directly.
            byte[] xBytes = Encoding.UTF8.GetBytes(x.FileName);
            byte[] yBytes = Encoding.UTF8.GetBytes(y.FileName);

            int minLen = Math.Min(xBytes.Length, yBytes.Length);
            for (int i = 0; i < minLen; i++)
            {
                if (xBytes[i] != yBytes[i])
                    return xBytes[i].CompareTo(yBytes[i]);
            }
            // If one is a prefix of the other, the shorter one comes first
            return xBytes.Length.CompareTo(yBytes.Length);

            // Note: A more precise Git sort treats directory names as "name/"
            // for sorting comparison against files named "name". This simple byte sort
            // is usually sufficient but might differ in edge cases.
        });

        // Build the byte array for the tree content
        using var memoryStream = new MemoryStream();
        foreach (var entry in treeEntries)
        {
            byte[] modeBytes = Encoding.UTF8.GetBytes(entry.Mode + " ");
            byte[] nameBytes = Encoding.UTF8.GetBytes(entry.FileName);
            byte[] nullByte = { 0 };

            memoryStream.Write(modeBytes, 0, modeBytes.Length);
            memoryStream.Write(nameBytes, 0, nameBytes.Length);
            memoryStream.Write(nullByte, 0, 1);
            memoryStream.Write(entry.Hash, 0, entry.Hash.Length); // Hash is already byte[]
        }
        return memoryStream.ToArray();
    }

    // --- Packfile Handling ---

    // Skips pkt-line headers until "PACK" or end of headers
    static async Task SkipPackResponseHeaders(Stream stream)
    {
        byte[] lengthBuffer = new byte[4];
        while (true)
        {
            int totalRead = 0;
            while (totalRead < 4)
            {
                int read = await stream.ReadAsync(lengthBuffer, totalRead, 4 - totalRead);
                if (read == 0) throw new EndOfStreamException("Unexpected end of stream while reading pkt-line header before PACK data");
                totalRead += read;
            }

            string lengthHex = Encoding.ASCII.GetString(lengthBuffer);

            // Check for PACK signature (special case, not a standard pkt-line)
            if (lengthHex == "PACK")
            {
                // Found PACK, need to rewind the stream 4 bytes so ProcessPackfile can read it
                if (stream.CanSeek)
                {
                    stream.Seek(-4, SeekOrigin.Current);
                }
                else
                {
                    // This is problematic for non-seekable streams (like network streams)
                    // A potential workaround is to read the PACK header here and pass it to ProcessPackfile
                    throw new NotSupportedException("Stream must be seekable to process packfile response after skipping headers.");
                }
                return; // Exit the loop, ready for ProcessPackfile
            }

            // Parse the hex length
            if (!int.TryParse(lengthHex, System.Globalization.NumberStyles.HexNumber, null, out int length))
            {
                throw new InvalidDataException($"Invalid pkt-line length hex: {lengthHex}");
            }

            // 0000 is the flush packet, often indicating end of headers/messages section
            // However, sideband data might follow, so we continue until PACK is found.
            // If length is 4, it's an empty line (e.g., "0004"), just skip it.
            if (length == 0) // Flush packet "0000"
            {
                 // Continue searching for PACK, could be messages after flush
                 continue;
            }
             if (length < 4) // Invalid length
            {
                 throw new InvalidDataException($"Invalid pkt-line length value: {length}");
            }


            // Read and discard the line content (length includes the 4 bytes we read)
            int bytesToSkip = length - 4;
            if (bytesToSkip > 0)
            {
                await SkipBytes(stream, bytesToSkip);
            }
             // If length was 4, we skip 0 bytes, effectively just consuming the header.
        }
    }

    // Helper to skip a specific number of bytes from a stream
    static async Task SkipBytes(Stream stream, int bytesToSkip)
    {
        if (bytesToSkip <= 0) return;

        // Use a buffer for potentially large skips
        byte[] buffer = new byte[Math.Min(4096, bytesToSkip)];
        while (bytesToSkip > 0)
        {
            int bytesToRead = Math.Min(buffer.Length, bytesToSkip);
            int bytesRead = await stream.ReadAsync(buffer, 0, bytesToRead);
            if (bytesRead == 0) throw new EndOfStreamException("Unexpected end of stream while skipping bytes");
            bytesToSkip -= bytesRead;
        }
    }

    // Reads pkt-line formatted lines (used for info/refs)
    static async Task<string> ReadPktLine(Stream stream)
    {
        byte[] lengthBytes = new byte[4];
        int totalRead = 0;
        while (totalRead < 4)
        {
            int read = await stream.ReadAsync(lengthBytes, totalRead, 4 - totalRead);
            // If stream ends cleanly after last line, return empty string
            if (read == 0 && totalRead == 0) return "";
            if (read == 0) throw new EndOfStreamException("Unexpected end of stream while reading pkt-line length.");
            totalRead += read;
        }

        string lengthHex = Encoding.ASCII.GetString(lengthBytes);
        if (lengthHex == "0000") return "0000"; // Flush packet signifies end

        if (!int.TryParse(lengthHex, System.Globalization.NumberStyles.HexNumber, null, out int length))
            throw new InvalidDataException($"Invalid pkt-line length: {lengthHex}");

        // Length includes the 4 bytes of the length itself.
        if (length < 4) throw new InvalidDataException($"Invalid pkt-line length value: {length}");
        if (length == 4) return ""; // Empty line payload

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

    // Parses the response from /info/refs
    static async Task<Dictionary<string, string>> ParseInfoRefs(Stream stream)
    {
        var refs = new Dictionary<string, string>();
        string? headSymRefTarget = null; // Store the target of the symbolic ref HEAD

        // First line usually contains service info and capabilities
        string firstLine = await ReadPktLine(stream);
        if (!firstLine.StartsWith("# service=git-upload-pack"))
        {
            // This might not be fatal, but log a warning
            Console.Error.WriteLine($"Warning: Expected '# service=git-upload-pack', got '{firstLine}'");
        }
        // The first line might also contain capabilities and the first ref after a null byte.
        // A robust parser would handle this. This simple one assumes refs start after.

        // Read the first ref line (often separated by a null byte in the first line,
        // handled here by assuming ReadPktLine reads past it or it's on a new line).
        // A simple approach is to just read the next line, assuming the first line was just header.
        string firstRefLine = await ReadPktLine(stream);
        if (firstRefLine == "0000") return refs; // Empty repo?

        // Process the first ref line manually before the loop
        ParseRefLine(firstRefLine, refs, ref headSymRefTarget);


        // Process remaining ref lines
        while (true)
        {
            string line = await ReadPktLine(stream);
            if (line == "0000") break; // End of refs marker
             if (string.IsNullOrEmpty(line)) continue; // Skip empty lines if any

            ParseRefLine(line, refs, ref headSymRefTarget);
        }

        // Resolve symbolic HEAD if possible
        if (headSymRefTarget != null && refs.TryGetValue(headSymRefTarget, out string targetHash))
        {
            refs["HEAD"] = targetHash; // Add resolved HEAD hash
        }
        else if (headSymRefTarget != null)
        {
             Console.Error.WriteLine($"Warning: HEAD is symref to '{headSymRefTarget}' but target ref was not found.");
        }
        else if (!refs.ContainsKey("HEAD")) // If HEAD wasn't a symref and wasn't listed directly
        {
            Console.Error.WriteLine("Warning: Could not resolve HEAD commit hash from info/refs.");
        }


        return refs;
    }

    // Helper to parse a single line from info/refs output
    static void ParseRefLine(string line, Dictionary<string, string> refs, ref string? headSymRefTarget)
    {
         string[] parts = line.Split(' ', 2); // Split into hash and rest
         if (parts.Length < 2) return; // Invalid line format

         string hash = parts[0];
         string namePart = parts[1];

         // Check for capabilities attached to the ref name (separated by null byte)
         string refName;
         string[] capabilities = Array.Empty<string>();
         int nullIndex = namePart.IndexOf('\0');
         if (nullIndex != -1)
         {
             refName = namePart.Substring(0, nullIndex);
             capabilities = namePart.Substring(nullIndex + 1).Split(' ');
         }
         else
         {
             refName = namePart;
         }


         // Store the ref
         if (refName.EndsWith("^{}"))
         {
             // This is a peeled tag, points directly to commit. Store the base tag name.
             string baseTagName = refName.Substring(0, refName.Length - 3);
             // Only store if the base tag isn't already pointing to the tag object itself
             if (!refs.ContainsKey(baseTagName))
             {
                 refs[baseTagName] = hash;
             }
         }
         else
         {
             refs[refName] = hash;
         }

         // Check capabilities for symref=HEAD:target
         foreach (string capability in capabilities)
         {
             if (capability.StartsWith("symref=HEAD:"))
             {
                 headSymRefTarget = capability.Substring("symref=HEAD:".Length);
             }
         }
         // Also check if the refName *is* HEAD (for non-symref HEAD)
         if(refName == "HEAD" && headSymRefTarget == null) // If HEAD is listed directly
         {
             refs["HEAD"] = hash;
         }
    }


    // Processes the packfile stream, reading objects and storing them
    static async Task ProcessPackfile(Stream packStream)
    {
        // Clear caches before processing
        _packObjectsByOffset.Clear();
        _packObjectsByHash.Clear();
        List<PackObject> readObjects = new(); // Temporarily store objects as read

        // Use BinaryReader directly on the network stream (removed BufferedStream)
        // Ensure ASCII encoding for headers and keep stream open
        using var reader = new BinaryReader(packStream, Encoding.ASCII, true);

        // 1. Read Packfile Header
        byte[] signature = reader.ReadBytes(4);
        if (Encoding.ASCII.GetString(signature) != "PACK")
            throw new InvalidDataException("Invalid packfile signature.");

        uint version = ReadNetworkUInt32(reader);
        if (version != 2)
            throw new NotSupportedException($"Unsupported packfile version: {version}");

        uint objectCount = ReadNetworkUInt32(reader);
        Console.WriteLine($"Packfile contains {objectCount} objects.");

        // 2. Read all object headers and data sequentially
        for (uint i = 0; i < objectCount; i++)
        {
            long currentOffset = -1;
             try
             {
                 // Get the offset *before* reading any data for this object
                 // Note: BaseStream might not be accurately seekable/report position on network stream
                 // This relies on BinaryReader tracking position correctly.
                 currentOffset = reader.BaseStream.Position;

                 var packObject = await ReadPackObjectFromReader(reader, currentOffset);
                 if (packObject != null)
                 {
                     readObjects.Add(packObject);
                 }
                 else
                 {
                     // If ReadPackObject returns null, it means decompression failed.
                     Console.Error.WriteLine($"Warning: Failed to read or decompress object #{i + 1} at offset ~{currentOffset}. Skipping rest of packfile.");
                     // Depending on error, might try to skip or abort. Aborting is safer.
                     break;
                 }
             }
             catch (EndOfStreamException ex)
             {
                 Console.Error.WriteLine($"Error reading object #{i + 1} at offset ~{currentOffset}: Unexpected end of stream. {ex.Message}");
                 // This often means the previous object's decompression read too far.
                 break; // Stop processing the packfile
             }
             catch (Exception ex)
             {
                 Console.Error.WriteLine($"Error reading object #{i + 1} at offset ~{currentOffset}: {ex.Message}\n{ex.StackTrace}");
                 break; // Stop processing on other errors too
             }
        }

        // 3. Build offset map from successfully read objects
        // Use the Offset field stored in the PackObject record
         _packObjectsByOffset = readObjects
             .Where(o => o.Offset >= 0) // Filter out any with invalid offsets
             .GroupBy(o => o.Offset) // Handle potential duplicate offsets? (Shouldn't happen)
             .ToDictionary(g => g.Key, g => g.First());


        // 4. Resolve deltas and store objects
        Console.WriteLine($"Finished reading raw objects ({readObjects.Count} read). Resolving deltas and storing...");
        int storedCount = 0;
        foreach (var obj in readObjects)
        {
            try
            {
                // StorePackObject resolves, calculates hash, writes to disk, and caches in _packObjectsByHash
                StorePackObject(obj);
                storedCount++;
            }
            catch (Exception ex)
            {
                // Log detailed error including object type and offset/hash if available
                string objIdentifier = obj.Type;
                if(obj.Offset >= 0) objIdentifier += $" at offset {obj.Offset}";
                if(!string.IsNullOrEmpty(obj.BaseHash)) objIdentifier += $" (ref_delta base {obj.BaseHash})";

                Console.Error.WriteLine($"Error storing object {objIdentifier}: {ex.Message}");
                // Optionally print stack trace for debugging: Console.Error.WriteLine(ex.StackTrace);
                // Decide whether to continue or abort; continuing might leave repo inconsistent.
            }
        }
        Console.WriteLine($"Finished processing packfile. Stored {storedCount} objects.");

        // 5. Verify Packfile Checksum (Optional but recommended)
        // byte[] expectedChecksum = reader.ReadBytes(20);
        // TODO: Calculate checksum of the received pack data and compare
    }


    // Reads a single object's header and compressed data from the packfile stream
    static async Task<PackObject?> ReadPackObjectFromReader(BinaryReader reader, long actualObjectOffset)
    {
        // Read Type and Size
        byte firstByte = reader.ReadByte();
        int typeNum = (firstByte >> 4) & 7; // 3 bits for type
        long size = firstByte & 0x0F; // Lower 4 bits of size
        int shift = 4;
        bool moreBytes = (firstByte & 0x80) != 0; // MSB indicates more size bytes follow

        while (moreBytes)
        {
            byte sizeByte = reader.ReadByte();
            size |= (long)(sizeByte & 0x7F) << shift;
            shift += 7;
            moreBytes = (sizeByte & 0x80) != 0;
        }

        // Determine object type string
        string type = typeNum switch
        {
            1 => "commit",
            2 => "tree",
            3 => "blob",
            4 => "tag",
            6 => "ofs_delta", // Offset delta
            7 => "ref_delta", // Reference delta (hash)
            _ => throw new NotSupportedException($"Unsupported pack object type number: {typeNum} at offset {actualObjectOffset}")
        };

        // Read delta-specific information if applicable
        long baseRelativeOffset = -1; // For ofs_delta
        string? baseHash = null;      // For ref_delta

        if (type == "ofs_delta")
        {
            // Read variable-length negative offset relative to current object's start
            baseRelativeOffset = ReadVariableLengthOffset(reader);
        }
        else if (type == "ref_delta")
        {
            // Read the 20-byte SHA-1 hash of the base object
            byte[] hashBytes = reader.ReadBytes(20);
            baseHash = Convert.ToHexString(hashBytes).ToLower();
        }

        // Decompress the object data
        // The ZLibStream reads directly from the BinaryReader's BaseStream
        using var decompressedStream = new MemoryStream();
        try
        {
            // Important: ZLibStream reads until it finds the zlib stream end marker.
            // It does NOT know the expected *uncompressed* size beforehand.
            // If it reads past the end of this object's data into the next object,
            // it will corrupt the main stream position.
            using (var zlibStream = new ZLibStream(reader.BaseStream, CompressionMode.Decompress, true)) // leaveOpen = true
            {
                // CopyToAsync reads until the end of the zlib stream is detected.
                await zlibStream.CopyToAsync(decompressedStream);
            }
        }
        catch (Exception ex) // Catch specific exceptions like InvalidDataException if needed
        {
            Console.Error.WriteLine($"Error during ZLib decompression for object type {type} at offset {actualObjectOffset}: {ex.Message}");
            // Return null to indicate failure to read this object
            return null;
        }

        byte[] data = decompressedStream.ToArray();

        // Sanity check: Decompressed size should match the size from the header for non-delta types
        if (typeNum >= 1 && typeNum <= 4 && data.Length != (int)size)
        {
            // This is a warning because sometimes zlib might add padding? Though usually indicates corruption.
            Console.Error.WriteLine($"Warning: Decompressed size mismatch for {type} at offset {actualObjectOffset}. Expected {size}, got {data.Length}.");
        }
        // For deltas, 'size' is the size of the *delta instructions*, not the final object.

        // Return the PackObject with the correct absolute offset and relative offset/base hash
        return new PackObject(type, data, actualObjectOffset, baseRelativeOffset, baseHash);
    }


    // Reads Git's variable-length encoding for offsets (used in ofs_delta and index files)
    static long ReadVariableLengthOffset(BinaryReader reader)
    {
        long offset = 0;
        byte currentByte;
        int shift = 0;
        long byteValue;

        currentByte = reader.ReadByte();
        offset = currentByte & 0x7F; // First byte uses lower 7 bits

        while ((currentByte & 0x80) != 0) // While MSB is set
        {
            currentByte = reader.ReadByte();
            // Add 1 to the offset before shifting, effectively adding powers of 128
            offset += 1;
            offset <<= 7; // Make space for the next 7 bits
            offset |= (currentByte & 0x7F); // Add the lower 7 bits of the new byte
        }
        return offset;
    }

     // Reads Git's variable-length encoding for sizes (used in delta instructions)
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
        } while ((currentByte & 0x80) != 0); // Continue while MSB is set
        return value;
    }


    // Reads a 32-bit unsigned integer in network byte order (big-endian)
    static uint ReadNetworkUInt32(BinaryReader reader)
    {
        byte[] bytes = reader.ReadBytes(4);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes); // Convert big-endian to little-endian if necessary
        }
        return BitConverter.ToUInt32(bytes, 0);
    }

    // Resolves delta objects, stores final object, returns hash. (Recursive)
    static string StorePackObject(PackObject packObject)
    {
        string finalHash;
        string finalType;
        byte[] finalData;
        long originalOffset = packObject.Offset; // Keep for logging

        if (packObject.Type == "ofs_delta" || packObject.Type == "ref_delta")
        {
            // --- Delta Object ---
            // 1. Find the base object record (might be delta itself)
            PackObject baseObjectRecord = FindBaseObject(packObject);

            // 2. Recursively ensure the base object is stored and get its hash
            string baseHash = StorePackObject(baseObjectRecord); // Recursive call

            // 3. Get the *resolved* data of the base object
            byte[] baseData = ReadObjectDataFromAnywhere(baseHash); // Should now exist in cache or disk

            // 4. Apply the delta instructions
            finalData = ApplyDelta(baseData, packObject.Data);
            // The final type is the type of the base object
            finalType = _packObjectsByHash[baseHash].Type; // Get type from resolved base in cache

            // 5. Calculate hash of the resolved object
            finalHash = CalculateObjectHash(finalType, finalData);

            // 6. Store the *resolved* object if not already present
            if (!_packObjectsByHash.ContainsKey(finalHash))
            {
                // Create a new PackObject representing the resolved state
                var resolvedObject = new PackObject(finalType, finalData, -1); // Offset -1 = resolved
                _packObjectsByHash[finalHash] = resolvedObject;
                // Write the resolved object to the loose object store
                WriteObjectToDiskInternal(finalHash, CreateObjectBytes(finalType, finalData));
                 // Console.WriteLine($"DEBUG: Stored resolved delta {finalType} {finalHash} (from offset {originalOffset})");
            }
        }
        else
        {
            // --- Base Object Type (commit, tree, blob, tag) ---
            finalType = packObject.Type;
            finalData = packObject.Data; // Data is already the final content

            // 1. Calculate hash
            finalHash = CalculateObjectHash(finalType, finalData);

            // 2. Store if not already present
            if (!_packObjectsByHash.ContainsKey(finalHash))
            {
                 // Use the original packObject read from the file
                _packObjectsByHash[finalHash] = packObject;
                // Write object to disk
                WriteObjectToDiskInternal(finalHash, CreateObjectBytes(finalType, finalData));
                 // Console.WriteLine($"DEBUG: Stored base object {finalType} {finalHash} (from offset {originalOffset})");
            }
        }

        return finalHash;
    }

    // Helper to combine type, size, null byte, and content
    static byte[] CreateObjectBytes(string type, byte[] content)
    {
        byte[] header = CreateObjectHeaderInBytes(type, content.Length);
        byte[] combined = new byte[header.Length + content.Length];
        Buffer.BlockCopy(header, 0, combined, 0, header.Length);
        Buffer.BlockCopy(content, 0, combined, header.Length, content.Length);
        return combined;
    }


    // Finds the base PackObject record for a given delta object
    static PackObject FindBaseObject(PackObject deltaObject)
    {
        if (deltaObject.Type == "ofs_delta")
        {
            // BaseOffset is the *relative* negative offset
            long relativeNegativeOffset = deltaObject.BaseOffset;
            // Offset is the *absolute* offset where the delta object started
            long absoluteBaseOffset = deltaObject.Offset - relativeNegativeOffset;

            // Look up the base object info using its absolute offset in the map built from pass 1
            if (_packObjectsByOffset.TryGetValue(absoluteBaseOffset, out PackObject baseObjRecord))
            {
                // Return the record read from the packfile; StorePackObject will handle resolving it if needed.
                return baseObjRecord;
            }
            else
            {
                // This indicates the base object wasn't found at the calculated offset in the packfile.
                // This could be a packfile corruption or a bug in offset calculation/reading.
                string knownOffsets = string.Join(", ", _packObjectsByOffset.Keys.OrderBy(k => k));
                Console.Error.WriteLine($"DEBUG: Known offsets: {knownOffsets}");
                throw new InvalidOperationException($"ofs_delta base object not found at calculated absolute offset {absoluteBaseOffset} (delta started at {deltaObject.Offset}, relative offset {relativeNegativeOffset})");
            }
        }
        else if (deltaObject.Type == "ref_delta")
        {
            string baseHash = deltaObject.BaseHash!;
            // Priority 1: Check if the *resolved* base object is already in the hash map
            if (_packObjectsByHash.TryGetValue(baseHash, out PackObject baseObjByHash))
            {
                 // Ensure it's not an unresolved delta itself (shouldn't happen if StorePackObject works)
                 if (baseObjByHash.Type == "ofs_delta" || baseObjByHash.Type == "ref_delta") {
                     throw new InvalidOperationException($"Found unresolved delta object {baseHash} in hash cache while looking for base.");
                 }
                return baseObjByHash; // Return the resolved object directly
            }

            // Priority 2: Check if the object exists loose on disk
            if (ObjectExists(baseHash))
            {
                // Read from disk, create a temporary PackObject, and cache it
                byte[] rawData = ReadObject(baseHash); // Reads and decompresses (header + content)
                int nullByteIndex = Array.IndexOf(rawData, (byte)0);
                 if (nullByteIndex == -1) throw new InvalidDataException($"Invalid object format on disk for {baseHash}");
                string header = Encoding.UTF8.GetString(rawData, 0, nullByteIndex);
                string[] headerParts = header.Split(' ');
                string baseType = headerParts[0];
                byte[] baseContent = rawData.Skip(nullByteIndex + 1).ToArray();

                // Create a PackObject representing this disk object. Offset -2 indicates 'from disk'.
                var diskBase = new PackObject(baseType, baseContent, -2, -1, baseHash);
                _packObjectsByHash[baseHash] = diskBase; // Cache it immediately
                return diskBase;
            }

            // Priority 3: Check if the base object exists in the packfile objects we read but haven't resolved/hashed yet.
            // We need to find the PackObject record corresponding to this hash.
            // This requires iterating through _packObjectsByOffset and calculating potential hashes,
            // OR relying on the StorePackObject recursion to eventually process it.
            // Let's search the _packObjectsByOffset values.
            foreach(var kvp in _packObjectsByOffset)
            {
                PackObject potentialBaseRecord = kvp.Value;
                // Avoid calculating hash for deltas directly
                if (potentialBaseRecord.Type != "ofs_delta" && potentialBaseRecord.Type != "ref_delta")
                {
                    string potentialHash = CalculateObjectHash(potentialBaseRecord.Type, potentialBaseRecord.Data);
                    if (potentialHash == baseHash)
                    {
                        // Found the record in the packfile list. Return it.
                        // StorePackObject will handle resolving/storing it.
                        return potentialBaseRecord;
                    }
                }
                // If the potential base is itself a delta, StorePackObject will handle resolving it when its turn comes.
            }


            // If we reach here, the base object is truly missing.
            throw new InvalidOperationException($"ref_delta base object with hash {baseHash} not found for delta at {deltaObject.Offset}. Not in cache, pack, or disk.");
        }
        else
        {
            throw new ArgumentException("Object is not a delta object.");
        }
    }


    // Applies Git delta instructions to a base object's data
    static byte[] ApplyDelta(byte[] baseData, byte[] deltaInstructions)
    {
        using var deltaStream = new MemoryStream(deltaInstructions);
        // Use BinaryReader for easier byte/int reading
        using var reader = new BinaryReader(deltaStream);

        // Read source (base) size - variable length encoded
        long expectedBaseSize = ReadVariableLengthInt(reader);
        if (expectedBaseSize != baseData.Length)
            throw new InvalidDataException($"Delta base size mismatch: expected {baseData.Length}, got {expectedBaseSize}");

        // Read target (result) size - variable length encoded
        long targetSize = ReadVariableLengthInt(reader);

        // Use a MemoryStream to build the result
        using var targetStream = new MemoryStream((int)targetSize); // Pre-allocate capacity

        while (deltaStream.Position < deltaStream.Length)
        {
            byte instruction = reader.ReadByte();

            if ((instruction & 0x80) != 0) // Copy instruction (MSB is 1)
            {
                long copyOffset = 0;
                long copySize = 0;

                // Read offset bytes based on flags
                int shift = 0;
                if ((instruction & 0x01) != 0) { copyOffset |= (long)reader.ReadByte() << shift; shift += 8; }
                if ((instruction & 0x02) != 0) { copyOffset |= (long)reader.ReadByte() << shift; shift += 8; }
                if ((instruction & 0x04) != 0) { copyOffset |= (long)reader.ReadByte() << shift; shift += 8; }
                if ((instruction & 0x08) != 0) { copyOffset |= (long)reader.ReadByte() << shift; shift += 8; }

                // Read size bytes based on flags
                shift = 0;
                if ((instruction & 0x10) != 0) { copySize |= (long)reader.ReadByte() << shift; shift += 8; }
                if ((instruction & 0x20) != 0) { copySize |= (long)reader.ReadByte() << shift; shift += 8; }
                if ((instruction & 0x40) != 0) { copySize |= (long)reader.ReadByte() << shift; shift += 8; }

                // Size 0 means 0x10000 (65536) bytes
                if (copySize == 0) copySize = 0x10000;

                // Validate copy operation boundaries
                if (copyOffset < 0 || copySize < 0 || copyOffset + copySize > baseData.Length)
                    throw new InvalidDataException(
                        $"Delta copy instruction exceeds base data boundaries (offset={copyOffset}, size={copySize}, baseSize={baseData.Length}). Delta stream pos: {deltaStream.Position}");

                // Perform the copy from baseData to targetStream
                targetStream.Write(baseData, (int)copyOffset, (int)copySize);
            }
            else // Add instruction (MSB is 0)
            {
                // The instruction byte itself contains the size (1-127)
                byte addSize = instruction;
                if (addSize == 0)
                    throw new InvalidDataException("Delta add instruction has zero size."); // Size 0 is invalid

                // Read the data to add
                byte[] dataToAdd = reader.ReadBytes(addSize);
                if(dataToAdd.Length != addSize)
                    throw new EndOfStreamException("Unexpected end of stream reading data for delta add instruction.");

                // Write the added data to targetStream
                targetStream.Write(dataToAdd, 0, dataToAdd.Length);
            }
        }

        // Final check: ensure the resulting stream matches the expected target size
        if (targetStream.Length != targetSize)
        {
            // This usually indicates corrupted delta instructions or incorrect application
            Console.Error.WriteLine($"Warning: Delta application result size mismatch: expected {targetSize}, got {targetStream.Length}");
        }

        return targetStream.ToArray();
    }


    // --- Checkout Logic ---

    // Checks out the specified commit hash into the working directory
    static void CheckoutHead(string commitHash)
    {
        try
        {
            // 1. Read the commit object data
            byte[] commitRawData = ReadObjectDataFromAnywhere(commitHash); // Read content only

            // 2. Parse the commit object to find the tree hash
            string? treeHash = null;
            string commitContent = Encoding.UTF8.GetString(commitRawData);
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

            // 3. Update the current branch ref file (e.g., .git/refs/heads/main)
            string headRefPath = Path.Combine(".git", "HEAD");
            if (File.Exists(headRefPath))
            {
                 string headContent = File.ReadAllText(headRefPath).Trim();
                 if (headContent.StartsWith("ref: "))
                 {
                     string refName = headContent.Substring(5).Trim();
                     string refPath = Path.Combine(".git", refName);
                     try
                     {
                         Directory.CreateDirectory(Path.GetDirectoryName(refPath)!);
                         File.WriteAllText(refPath, commitHash + "\n");
                     }
                     catch (Exception ex)
                     {
                         Console.Error.WriteLine($"Warning: Could not update ref file {refPath}: {ex.Message}");
                     }
                 }
                 else // Detached HEAD state (points directly to commit)
                 {
                     try
                     {
                        File.WriteAllText(headRefPath, commitHash + "\n");
                     }
                      catch (Exception ex)
                     {
                         Console.Error.WriteLine($"Warning: Could not update HEAD file: {ex.Message}");
                     }
                 }
            } else {
                 Console.Error.WriteLine($"Warning: .git/HEAD file not found.");
            }


            // 4. Clear the working directory (excluding .git)
            Console.WriteLine($"Checking out tree {treeHash}");
            ClearWorkingDirectory();

            // 5. Recursively checkout the tree
            CheckoutTree(treeHash, Directory.GetCurrentDirectory());
        }
        catch (FileNotFoundException ex)
        {
            // Make error more specific
            Console.Error.WriteLine($"Error: Required object not found during checkout: {ex.Message}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error during checkout: {ex.Message}\n{ex.StackTrace}");
        }
    }

    // Clears the working directory, ignoring the .git folder
    static void ClearWorkingDirectory()
    {
        string currentDir = Directory.GetCurrentDirectory();
        string gitDirName = ".git";

        // Delete files
        foreach (string file in Directory.GetFiles(currentDir))
        {
            // Important: Use OrdinalIgnoreCase for cross-platform compatibility with ".git"
            if (Path.GetFileName(file).Equals(gitDirName, StringComparison.OrdinalIgnoreCase)) continue;
            try
            {
                File.Delete(file);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Warning: Could not delete file {file}: {ex.Message}");
            }
        }

        // Delete directories
        foreach (string dir in Directory.GetDirectories(currentDir))
        {
            if (Path.GetFileName(dir).Equals(gitDirName, StringComparison.OrdinalIgnoreCase)) continue;
            try
            {
                Directory.Delete(dir, true); // Recursive delete
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Warning: Could not delete directory {dir}: {ex.Message}");
            }
        }
    }

    // Recursively checks out a tree object into the specified base path
    static void CheckoutTree(string treeHash, string basePath)
    {
        byte[] treeRawData;
        try
        {
             // Read the tree object *content*
             treeRawData = ReadObjectDataFromAnywhere(treeHash);
        }
        catch (FileNotFoundException)
        {
             Console.Error.WriteLine($"Error: Tree object {treeHash} not found during checkout.");
             return;
        }
        catch (Exception ex)
        {
             Console.Error.WriteLine($"Error reading tree object {treeHash}: {ex.Message}");
             return;
        }


        int currentPos = 0;
        while (currentPos < treeRawData.Length)
        {
            // Find space separating mode and filename
            int spaceIndex = Array.IndexOf(treeRawData, (byte)' ', currentPos);
            if (spaceIndex == -1 || spaceIndex == currentPos) break; // Malformed entry or empty mode

            string mode = Encoding.UTF8.GetString(treeRawData, currentPos, spaceIndex - currentPos);

            // Find null byte terminating filename
            int nullIndex = Array.IndexOf(treeRawData, (byte)0, spaceIndex + 1);
            if (nullIndex == -1 || nullIndex == spaceIndex + 1) break; // Malformed entry or empty name

            string name = Encoding.UTF8.GetString(treeRawData, spaceIndex + 1, nullIndex - (spaceIndex + 1));

            // Extract the 20-byte hash
            if (nullIndex + 1 + 20 > treeRawData.Length) break; // Not enough bytes left for hash
            byte[] hashBytes = new byte[20];
            Buffer.BlockCopy(treeRawData, nullIndex + 1, hashBytes, 0, 20);
            string entryHash = Convert.ToHexString(hashBytes).ToLower();

            // Calculate the full path for the entry
            string fullPath = Path.Combine(basePath, name);

            try
            {
                if (mode == "040000") // Directory
                {
                    Directory.CreateDirectory(fullPath);
                    CheckoutTree(entryHash, fullPath); // Recurse
                }
                else if (mode == "120000") // Symbolic Link
                {
                    byte[] blobContent = ReadObjectDataFromAnywhere(entryHash);
                    string targetPath = Encoding.UTF8.GetString(blobContent);

                    // Create the symbolic link
                    // Note: Requires appropriate permissions, especially on Windows.
                    try {
                         File.CreateSymbolicLink(fullPath, targetPath);
                    } catch (UnauthorizedAccessException) {
                         Console.Error.WriteLine($"Error: Insufficient permissions to create symbolic link '{fullPath}'. Try running as administrator or enabling developer mode (Windows).");
                    } catch (IOException ioEx) when (ioEx.Message.Contains("symbolic link")) {
                         Console.Error.WriteLine($"Error: Could not create symbolic link '{fullPath}'. OS support/privileges? {ioEx.Message}");
                    }
                }
                else if (mode == "100644" || mode == "100755") // Regular file (executable or not)
                {
                    byte[] blobContent = ReadObjectDataFromAnywhere(entryHash);
                    File.WriteAllBytes(fullPath, blobContent);

                    // Set executable permission if needed (non-Windows)
                    if (mode == "100755" && !RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        try
                        {
                            File.SetUnixFileMode(fullPath,
                                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                                UnixFileMode.GroupRead | UnixFileMode.GroupExecute | // Common executable permissions
                                UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
                        }
                        catch (Exception ex)
                        {
                            Console.Error.WriteLine($"Warning: Could not set executable permissions for {fullPath}: {ex.Message}");
                        }
                    }
                }
                 else if (mode == "160000") // Gitlink (submodule commit hash) - Ignored for now
                 {
                     Console.WriteLine($"Ignoring submodule (gitlink) at {name}");
                 }
                else
                {
                    Console.Error.WriteLine($"Warning: Unknown tree entry mode '{mode}' for entry '{name}' with hash {entryHash}. Skipping.");
                }
            }
            catch (FileNotFoundException)
            {
                Console.Error.WriteLine($"Error: Object {entryHash} for tree entry '{name}' (mode {mode}) not found.");
                // Continue to next entry? Or abort? Continuing might leave inconsistent state.
            }
             catch (IOException ioEx)
             {
                 Console.Error.WriteLine($"Error writing file/directory {fullPath}: {ioEx.Message}");
             }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error processing tree entry {name} (mode {mode}, hash {entryHash}): {ex.Message}");
            }


            // Move position past the null byte and the 20-byte hash for the next entry
            currentPos = nullIndex + 1 + 20;
        }
    }
}
