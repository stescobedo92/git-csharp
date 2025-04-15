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
        // (Keep your existing implementations for these commands)
        if (command == "init")
        {
            // ... (your existing init code) ...
             Directory.CreateDirectory(".git");
            Directory.CreateDirectory(".git/objects");
            Directory.CreateDirectory(".git/refs");
            File.WriteAllText(".git/HEAD", "ref: refs/heads/main\n");
            Console.WriteLine("Initialized git directory");
        }
        else if (command == "cat-file" && args.Length > 2 && args[1] == "-p")
        {
            // ... (your existing cat-file code, potentially improved error handling) ...
            try
            {
                string hash = args[2];
                byte[] data = ReadObject(hash); // Use helper to read/decompress
                // Find the null byte separating header from content
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
                Console.Error.WriteLine($"Error: Object {args[2]} not found.");
            }
            catch (Exception ex)
            {
                 Console.Error.WriteLine($"An error occurred: {ex.Message}");
            }
        }
        else if (command == "hash-object" && args.Length > 2 && args[1] == "-w")
        {
            // ... (your existing hash-object code, using GenerateHashByte) ...
             string filePath = args[2];
            byte[] fileContentBytes = File.ReadAllBytes(filePath); // Read as bytes
            byte[] hashBytes = GenerateHashByte("blob", fileContentBytes); // Pass bytes
            string hash = Convert.ToHexString(hashBytes).ToLower();
            Console.WriteLine(hash);
        }
        else if (command == "ls-tree" && args.Length > 2 && args[1] == "--name-only") // Adjusted for common usage
        {
            // ... (your existing ls-tree code, potentially improved parsing) ...
             try
            {
                string treeHash = args[2];
                byte[] treeData = ReadObject(treeHash); // Use helper

                // Basic parsing (can be made more robust)
                int currentPos = Array.IndexOf(treeData, (byte)0) + 1; // Skip header
                while (currentPos < treeData.Length)
                {
                    // Find space after mode
                    int spaceIndex = Array.IndexOf(treeData, (byte)' ', currentPos);
                    if (spaceIndex == -1) break;
                    // Find null byte after filename
                    int nullIndex = Array.IndexOf(treeData, (byte)0, spaceIndex + 1);
                    if (nullIndex == -1) break;

                    string fileName = Encoding.UTF8.GetString(treeData, spaceIndex + 1, nullIndex - (spaceIndex + 1));
                    Console.WriteLine(fileName);

                    // Move to the start of the next entry (skip 20-byte hash)
                    currentPos = nullIndex + 1 + 20;
                }
            }
            catch (FileNotFoundException)
            {
                 Console.Error.WriteLine($"Error: Tree object {args[2]} not found.");
            }
            catch (Exception ex)
            {
                 Console.Error.WriteLine($"An error occurred: {ex.Message}");
            }
        }
        else if (command == "write-tree")
        {
            // ... (your existing write-tree code, using GenerateTreeObjectFileHash) ...
            var currentPath = Directory.GetCurrentDirectory();
            var currentFilePathHash = GenerateTreeObjectFileHash(currentPath);
            if (currentFilePathHash != null)
            {
                var hashString = Convert.ToHexString(currentFilePathHash).ToLower();
                Console.Write(hashString);
            }
            else
            {
                Console.Error.WriteLine("Error generating tree object.");
            }
        }
        else if (command == "commit-tree")
        {
             // ... (your existing commit-tree code, using GenerateHashByte) ...
             if (args.Length < 6 || args[2] != "-p" || args[4] != "-m")
            {
                Console.WriteLine("Usage: commit-tree <tree_sha> -p <parent_sha> -m <message>");
                return;
            }

            string treeSha = args[1];
            string parentSha = args[3];
            string message = args[5];

            // Hardcoded author/committer info for simplicity
            string author = "Author Name <author@example.com>";
            string committer = "Committer Name <committer@example.com>";

            // Get current timestamp in Git format (Unix timestamp + timezone)
            long unixTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            // Get local timezone offset
            TimeSpan offset = TimeZoneInfo.Local.GetUtcOffset(DateTimeOffset.UtcNow);
            string timezone = $"{(offset < TimeSpan.Zero ? "-" : "+")}{offset:hhmm}"; // Format as +/-HHmm

            // Construct the commit content
            StringBuilder commitContent = new StringBuilder();
            commitContent.AppendLine($"tree {treeSha}");
            commitContent.AppendLine($"parent {parentSha}");
            commitContent.AppendLine($"author {author} {unixTimestamp} {timezone}");
            commitContent.AppendLine($"committer {committer} {unixTimestamp} {timezone}");
            commitContent.AppendLine(); // Empty line before message
            commitContent.AppendLine(message);

            // Convert to bytes
            byte[] commitBytes = Encoding.UTF8.GetBytes(commitContent.ToString());

            // Use existing GenerateHashByte method to create the commit object
            byte[] commitHash = GenerateHashByte("commit", commitBytes);
            string hashString = Convert.ToHexString(commitHash).ToLower();

            // Output the commit hash
            Console.WriteLine(hashString);
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

            // Ensure target directory doesn't exist or is empty
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

            // Change to target directory *before* initializing git structure
            string originalDirectory = Directory.GetCurrentDirectory();
            try
            {
                Directory.SetCurrentDirectory(targetDir);

                // Initialize basic Git structure
                Directory.CreateDirectory(".git");
                Directory.CreateDirectory(".git/objects");
                Directory.CreateDirectory(".git/refs");
                Directory.CreateDirectory(".git/refs/heads"); // Create heads dir
                File.WriteAllText(".git/HEAD", "ref: refs/heads/main\n"); // Default to main

                Console.WriteLine($"Cloning into '{Path.GetFileName(targetDir)}'...");

                using (var client = new HttpClient())
                {
                    // Add User-Agent, required by some servers like GitHub
                    client.DefaultRequestHeaders.UserAgent.ParseAdd("csharp-git-client/1.0");
                    // Add headers required by Git Smart HTTP protocol
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
                    var refs = await ParseInfoRefs(infoRefsStream); // Use async stream parsing

                    if (!refs.Any())
                    {
                         Console.Error.WriteLine("No refs found.");
                         return;
                    }

                    // Find HEAD commit hash and the ref name (e.g., refs/heads/main)
                    string? headCommit = null;
                    string? headRefName = null;
                    if (refs.TryGetValue("HEAD", out string headTargetRef))
                    {
                        if (refs.TryGetValue(headTargetRef, out string targetCommit))
                        {
                            headCommit = targetCommit;
                            headRefName = headTargetRef;
                        }
                    }
                    // Fallback if HEAD symbolic ref isn't present (less common for clones)
                    if (headCommit == null && refs.TryGetValue("refs/heads/main", out string mainCommit))
                    {
                        headCommit = mainCommit;
                        headRefName = "refs/heads/main";
                    }
                    // Further fallback (e.g., master) - adapt as needed
                    if (headCommit == null && refs.TryGetValue("refs/heads/master", out string masterCommit))
                    {
                        headCommit = masterCommit;
                        headRefName = "refs/heads/master";
                    }


                    if (string.IsNullOrEmpty(headCommit) || string.IsNullOrEmpty(headRefName))
                    {
                        Console.Error.WriteLine("Could not determine HEAD commit or ref name.");
                        Console.WriteLine("Available refs:");
                        foreach(var kvp in refs) Console.WriteLine($"{kvp.Value} {kvp.Key}");
                        return;
                    }

                    Console.WriteLine($"Determined HEAD commit: {headCommit} ({headRefName})");
                    File.WriteAllText(".git/HEAD", $"ref: {headRefName}\n"); // Update HEAD ref

                    // --- Step 2: Negotiate and fetch packfile ---
                    string uploadPackUrl = $"{repoUrl}/git-upload-pack";
                    Console.WriteLine($"Requesting packfile from {uploadPackUrl}");

                    // Construct the pkt-line request
                    // Format: "want <hash> <capabilities>\n" ... "done\n"
                    // Basic capabilities: multi_ack_detailed no-done side-band-64k thin-pack ofs-delta agent=csharp-git-client/1.0
                    // 0032 = 50 bytes hex length for "want <40-char-hash>\n"
                    // 0000 = flush packet
                    // 0009 = 9 bytes hex length for "done\n"
                    string wantLine = $"want {headCommit} multi_ack_detailed no-done side-band-64k thin-pack ofs-delta agent=csharp-git-client/1.0\n";
                    string requestBody = $"{wantLine.Length + 4:x4}{wantLine}00000009done\n"; // pkt-line format

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
                    CheckoutHead(headCommit); // Use the determined HEAD commit

                    Console.WriteLine($"Successfully cloned repository to {targetDir}");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"An error occurred during clone: {ex.Message}");
                Console.Error.WriteLine(ex.StackTrace); // Include stack trace for debugging
            }
            finally
            {
                 // Ensure we change back to the original directory even if errors occur
                 Directory.SetCurrentDirectory(originalDirectory);
                 // Clear caches for next potential clone
                 _packObjectsByOffset.Clear();
                 _packObjectsByHash.Clear();
            }
        }
        else
        {
            Console.Error.WriteLine($"Unknown command {command}"); // Use Error stream for errors
        }
    }

    // --- Helper Methods ---

    // Reads an object file, decompresses it, and returns raw data (header + content)
    static byte[] ReadObject(string hash)
    {
        string path = Path.Combine(".git", "objects", hash.Substring(0, 2), hash.Substring(2));
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Object file not found: {path}", path);
        }

        using FileStream fileStream = File.OpenRead(path);
        // Read the compressed data first
        using MemoryStream compressedStream = new MemoryStream();
        fileStream.CopyTo(compressedStream);
        compressedStream.Position = 0; // Reset position before decompression

        // Now decompress
        using MemoryStream decompressedStream = new MemoryStream();
        using ZLibStream zLibStream = new ZLibStream(compressedStream, CompressionMode.Decompress);
        zLibStream.CopyTo(decompressedStream);

        return decompressedStream.ToArray();
    }


    // Creates the Git object header (e.g., "blob 12\0")
    static byte[] CreateObjectHeaderInBytes(string gitObjectType, long size) // Use long for size
    {
        return Encoding.UTF8.GetBytes($"{gitObjectType} {size}\0");
    }

    // Generates hash, compresses, and writes object to .git/objects
    // Returns the SHA-1 hash bytes
    static byte[] GenerateHashByte(string gitObjectType, byte[] contentBytes)
    {
        // 1. Create the header
        var objectHeader = CreateObjectHeaderInBytes(gitObjectType, contentBytes.Length);

        // 2. Combine header and content
        var gitObject = new byte[objectHeader.Length + contentBytes.Length];
        Buffer.BlockCopy(objectHeader, 0, gitObject, 0, objectHeader.Length);
        Buffer.BlockCopy(contentBytes, 0, gitObject, objectHeader.Length, contentBytes.Length);

        // 3. Compute SHA-1 hash of the combined data
        var hash = SHA1.HashData(gitObject);
        var hashString = Convert.ToHexString(hash).ToLower();

        // 4. Compress the combined data (header + content) using ZLib
        using var memoryStream = new MemoryStream();
        using (var zlibStream = new ZLibStream(memoryStream, CompressionLevel.Optimal, true)) // Use 'true' to leave stream open
        {
            zlibStream.Write(gitObject, 0, gitObject.Length);
        } // ZlibStream is disposed here, flushing the data

        var compressedObject = memoryStream.ToArray(); // Get compressed bytes

        // 5. Write the *compressed* data to the object store
        var objectDir = Path.Combine(".git", "objects", hashString.Substring(0, 2));
        var objectPath = Path.Combine(objectDir, hashString.Substring(2));
        Directory.CreateDirectory(objectDir); // Ensure directory exists
        File.WriteAllBytes(objectPath, compressedObject); // Write compressed bytes

        return hash; // Return the hash bytes
    }


    // Recursively generates tree objects and returns the hash bytes
    static byte[]? GenerateTreeObjectFileHash(string currentPath)
    {
        // Ignore .git directory itself
        if (Path.GetFileName(currentPath) == ".git")
            return null;

        var entries = new List<TreeEntry>();

        // Process files
        foreach (var file in Directory.GetFiles(currentPath))
        {
            string fileName = Path.GetFileName(file);
            // Skip .git files if somehow encountered (shouldn't happen with above check)
            if (fileName == ".git") continue;

            var fileContentInBytes = File.ReadAllBytes(file);
            var fileHash = GenerateHashByte("blob", fileContentInBytes);
            // Determine mode (basic check for executable, otherwise default 100644)
            // This is a simplification; real Git checks execute permissions.
            string mode = "100644"; // Default file mode
            // Add more sophisticated mode detection if needed (e.g., check FileAttributes)
            entries.Add(new TreeEntry(mode, fileName, fileHash));
        }

        // Process directories recursively
        foreach (var directory in Directory.GetDirectories(currentPath))
        {
            var directoryName = Path.GetFileName(directory);
            // Skip .git directory
            if (directoryName == ".git") continue;

            var directoryHash = GenerateTreeObjectFileHash(directory); // Recursive call
            if (directoryHash != null)
            {
                // Mode for directory is always 40000
                entries.Add(new TreeEntry("40000", directoryName, directoryHash));
            }
        }

        // If no entries, return null (or handle as empty tree if needed)
        if (!entries.Any())
            return null; // Or generate hash for an empty tree if required by spec

        // Create the tree object content from sorted entries
        var treeContent = CreateTreeObjectContent(entries);
        // Generate hash for the tree object itself
        return GenerateHashByte("tree", treeContent);
    }


    // Creates the byte content for a tree object from a list of entries
    static byte[] CreateTreeObjectContent(List<TreeEntry> treeEntries)
    {
        // Entries must be sorted by filename according to Git specification
        // Note: Git's sort is bytewise on the filename.
        treeEntries.Sort((x, y) =>
        {
             // Custom byte comparison for filenames to match Git's sorting
             byte[] xBytes = Encoding.UTF8.GetBytes(x.FileName);
             byte[] yBytes = Encoding.UTF8.GetBytes(y.FileName);
             int len = Math.Min(xBytes.Length, yBytes.Length);
             for (int i = 0; i < len; i++)
             {
                 if (xBytes[i] != yBytes[i])
                 {
                     return xBytes[i].CompareTo(yBytes[i]);
                 }
             }
             return xBytes.Length.CompareTo(yBytes.Length);
        });

        using var memoryStream = new MemoryStream();
        foreach (var entry in treeEntries)
        {
            // Format: "<mode> <filename>\0<hash_bytes>"
            byte[] modeBytes = Encoding.UTF8.GetBytes(entry.Mode + " ");
            byte[] nameBytes = Encoding.UTF8.GetBytes(entry.FileName);
            byte[] nullByte = { 0 };

            memoryStream.Write(modeBytes, 0, modeBytes.Length);
            memoryStream.Write(nameBytes, 0, nameBytes.Length);
            memoryStream.Write(nullByte, 0, 1);
            memoryStream.Write(entry.Hash, 0, entry.Hash.Length); // Write raw hash bytes
        }
        return memoryStream.ToArray();
    }

    // --- Clone Specific Helpers ---

    // Reads pkt-line formatted data from a stream
    static async Task<string> ReadPktLine(Stream stream)
    {
        byte[] lengthBytes = new byte[4];
        int bytesRead = await stream.ReadAsync(lengthBytes, 0, 4);
        if (bytesRead < 4) return ""; // End of stream or error

        string lengthHex = Encoding.ASCII.GetString(lengthBytes);
        if (lengthHex == "0000") return "0000"; // Flush packet

        if (!int.TryParse(lengthHex, System.Globalization.NumberStyles.HexNumber, null, out int length))
        {
            throw new InvalidDataException($"Invalid pkt-line length: {lengthHex}");
        }

        if (length <= 4) return ""; // Empty line or error

        int dataLength = length - 4;
        byte[] dataBytes = new byte[dataLength];
        bytesRead = 0;
        while(bytesRead < dataLength) // Ensure all data is read
        {
            int read = await stream.ReadAsync(dataBytes, bytesRead, dataLength - bytesRead);
            if (read == 0) throw new EndOfStreamException("Unexpected end of stream while reading pkt-line data.");
            bytesRead += read;
        }


        // Check for newline at the end for some pkt-line formats
        if (dataBytes.LastOrDefault() == '\n')
        {
            return Encoding.UTF8.GetString(dataBytes, 0, dataBytes.Length - 1);
        }
        else
        {
            return Encoding.UTF8.GetString(dataBytes);
        }
    }

    // Parses the info/refs response (pkt-line format)
    static async Task<Dictionary<string, string>> ParseInfoRefs(Stream stream)
    {
        var refs = new Dictionary<string, string>();
        bool firstLine = true;

        while (true)
        {
            string line = await ReadPktLine(stream);
            if (line == "0000" || string.IsNullOrEmpty(line)) break; // Flush packet or end of stream

            if (firstLine)
            {
                // First line format: <hash> HEAD\0<capabilities>
                string[] parts = line.Split('\0');
                if (parts.Length > 0)
                {
                    string[] headParts = parts[0].Split(' ');
                    if (headParts.Length == 2 && headParts[1] == "HEAD")
                    {
                        // This hash might be for the symbolic ref target, not HEAD itself yet
                    }
                }
                // Ignore capabilities for now
                firstLine = false;
                continue; // Process remaining lines normally
            }

            // Subsequent lines format: <hash> <ref_name>
            string[] refParts = line.Split(' ');
            if (refParts.Length >= 2)
            {
                string hash = refParts[0];
                string refName = refParts[1];

                // Handle symbolic refs like HEAD pointing to refs/heads/main
                if (refName == "HEAD" && refParts.Length > 2 && refParts[2].StartsWith("symref=HEAD:"))
                {
                     // Store the target ref name for HEAD
                     refs["HEAD"] = refParts[2].Substring("symref=HEAD:".Length);
                }
                else if (refName.EndsWith("^{}"))
                {
                    // This is a peeled tag object, pointing to the commit.
                    // Store the commit hash against the base tag name.
                    string baseTagName = refName.Substring(0, refName.Length - 3);
                    // Only add if the base tag isn't already present or if needed
                    if (!refs.ContainsKey(baseTagName))
                    {
                        refs[baseTagName] = hash;
                    }
                }
                else
                {
                    refs[refName] = hash;
                }
            }
        }
        return refs;
    }

    // Processes the packfile stream received from the server
    static async Task ProcessPackfile(Stream packStream)
    {
        _packObjectsByOffset.Clear(); // Clear cache for this packfile
        _packObjectsByHash.Clear();

        using var reader = new BinaryReader(packStream, Encoding.ASCII, true); // Keep stream open

        // Check PACK signature and version
        byte[] signature = reader.ReadBytes(4);
        if (Encoding.ASCII.GetString(signature) != "PACK")
        {
            throw new InvalidDataException("Invalid packfile signature.");
        }
        uint version = ReadNetworkUInt32(reader); // Read big-endian version
        if (version != 2)
        {
            throw new NotSupportedException($"Unsupported packfile version: {version}");
        }

        uint objectCount = ReadNetworkUInt32(reader); // Read big-endian object count
        Console.WriteLine($"Packfile contains {objectCount} objects.");

        // Read objects one by one
        for (uint i = 0; i < objectCount; i++)
        {
            long currentOffset = packStream.Position; // Record offset *before* reading object
            try
            {
                var packObject = await ReadPackObject(reader, packStream, currentOffset);
                if (packObject != null)
                {
                    _packObjectsByOffset[currentOffset] = packObject; // Cache by offset
                    // We'll calculate and cache by hash after potential delta resolution
                }
                else
                {
                     Console.Error.WriteLine($"Warning: Failed to read object #{i + 1} at offset {currentOffset}. Skipping.");
                     // Attempt to recover or fail? For now, we skip.
                     // This might indicate an issue with ReadPackObject or corrupt data.
                     break; // Stop processing if an object read fails critically
                }
            }
            catch (EndOfStreamException ex)
            {
                Console.Error.WriteLine($"Error reading object #{i + 1}: Unexpected end of stream. {ex.Message}");
                break; // Stop if stream ends prematurely
            }
             catch (Exception ex) // Catch broader exceptions during object read
            {
                Console.Error.WriteLine($"Error reading object #{i + 1} at offset {currentOffset}: {ex.Message}");
                Console.Error.WriteLine(ex.StackTrace);
                break; // Stop on other errors
            }
        }

        Console.WriteLine($"Finished reading raw objects. Resolving deltas and storing...");

        // Resolve deltas and store objects
        foreach (var kvp in _packObjectsByOffset)
        {
            try
            {
                StorePackObject(kvp.Value); // This will handle delta resolution recursively
            }
            catch (Exception ex)
            {
                 Console.Error.WriteLine($"Error storing object originally at offset {kvp.Key}: {ex.Message}");
                 // Decide if you want to continue or stop on storage errors
            }
        }

        Console.WriteLine("Finished processing packfile.");

        // Final checksum (optional but good practice)
        // byte[] expectedChecksum = reader.ReadBytes(20);
        // Verify checksum if needed
    }

    // Reads a single object entry from the packfile stream
    static async Task<PackObject?> ReadPackObject(BinaryReader reader, Stream packStream, long objectOffset)
    {
        // Read type and size
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
            6 => "ofs_delta", // Offset delta
            7 => "ref_delta", // Reference delta (hash)
            _ => throw new NotSupportedException($"Unsupported pack object type: {typeNum} at offset {objectOffset}")
        };

        long baseOffset = -1;
        string? baseHash = null;

        if (type == "ofs_delta")
        {
            // Read negative offset for base object
            long negativeOffset = ReadVariableLengthOffset(reader);
            baseOffset = objectOffset - negativeOffset; // Calculate absolute base offset
        }
        else if (type == "ref_delta")
        {
            // Read 20-byte hash for base object
            byte[] hashBytes = reader.ReadBytes(20);
            baseHash = Convert.ToHexString(hashBytes).ToLower();
        }

        // Read the compressed object data (or delta instructions)
        // The data is ZLib compressed *after* the type/size/offset/hash info
        using var compressedDataStream = new MemoryStream();
        // We need to read the rest of the object data from the main stream
        // This is tricky because ZLibStream needs to know when to stop reading
        // We copy the *remaining* part of the packStream into a temporary stream
        // then decompress that. This is inefficient but simpler than complex stream wrapping.

        // A better approach would be a custom stream wrapper that limits reads.
        // For now, let's try reading into a MemoryStream and decompressing that.

        // Estimate remaining data (could be large!) - This part is hard without knowing the compressed size
        // Let's read the compressed data directly and decompress
        using var decompressedStream = new MemoryStream();
        using (var zlibStream = new ZLibStream(packStream, CompressionMode.Decompress, true)) // Keep packStream open!
        {
            // Read until ZLibStream finishes decompression for this object
            // This relies on ZLibStream correctly identifying the end of the compressed data block.
            await zlibStream.CopyToAsync(decompressedStream);
        }
        byte[] data = decompressedStream.ToArray();

        // Sanity check: Decompressed size should match the size read earlier for non-delta objects
        if (typeNum >= 1 && typeNum <= 4 && data.Length != (int)size)
        {
             Console.Error.WriteLine($"Warning: Decompressed size mismatch for {type} at offset {objectOffset}. Expected {size}, got {data.Length}.");
             // This might indicate an issue with reading compressed data length or decompression itself.
        }


        return new PackObject(type, data, objectOffset, baseOffset, baseHash);
    }

    // Reads Git's variable-length encoded offset
    static long ReadVariableLengthOffset(BinaryReader reader)
    {
        long offset = 0;
        byte currentByte;
        int shift = 0;
        do
        {
            currentByte = reader.ReadByte();
            offset |= (long)(currentByte & 0x7F) << shift;
            shift += 7;
        } while ((currentByte & 0x80) != 0);
        return offset;
    }

     // Reads a network byte order (big-endian) uint32
    static uint ReadNetworkUInt32(BinaryReader reader)
    {
        byte[] bytes = reader.ReadBytes(4);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes);
        }
        return BitConverter.ToUInt32(bytes, 0);
    }


    // Stores a pack object, resolving deltas if necessary
    // Returns the SHA-1 hash of the stored object
    static string StorePackObject(PackObject packObject)
    {
        // Check if already processed and stored (e.g., as a base for another delta)
        string existingHash = FindExistingHash(packObject);
        if (!string.IsNullOrEmpty(existingHash))
        {
            return existingHash;
        }

        byte[] finalData;
        string objectType = packObject.Type;

        if (packObject.Type == "ofs_delta" || packObject.Type == "ref_delta")
        {
            // Resolve delta
            PackObject baseObject = FindBaseObject(packObject);
            if (baseObject == null)
            {
                throw new InvalidOperationException($"Could not find base object for delta at offset {packObject.Offset}");
            }

            // Ensure the base object is fully resolved first (recursive call)
            StorePackObject(baseObject);

            // Apply the delta patch
            byte[] baseData = ReadObjectData(baseObject); // Get raw data of the resolved base object
            finalData = ApplyDelta(baseData, packObject.Data); // Apply patch instructions

            // The type of the resolved object is the type of the base object
            objectType = baseObject.Type; // Type comes from the base
        }
        else
        {
            // Not a delta object, use its data directly
            finalData = packObject.Data;
        }

        // Now we have the final, reconstructed object data (header + content)
        // Generate hash, compress, and write to object store
        byte[] hashBytes = GenerateHashByte(objectType, finalData);
        string hashString = Convert.ToHexString(hashBytes).ToLower();

        // Cache the resolved object by hash for future lookups
        // Note: We might need a more robust cache if objects are huge
        _packObjectsByHash[hashString] = new PackObject(objectType, finalData, packObject.Offset); // Store resolved object

        return hashString;
    }

    // Helper to find the hash if an object equivalent to packObject was already stored
    static string FindExistingHash(PackObject packObject)
    {
        // Simple check: if we stored something by hash, see if its original offset matches
        // This is basic; a content-based check would be more robust but expensive.
        foreach (var kvp in _packObjectsByHash)
        {
            if (kvp.Value.Offset == packObject.Offset && kvp.Value.Type == packObject.Type)
            {
                // Potentially the same object, assuming offset is unique enough identifier *before* hashing
                // We need a better way if multiple packfiles are processed without clearing cache
                // For a single clone operation, this might suffice if StorePackObject is called correctly.

                // A more robust check: hash the *raw* data if it's not a delta
                 if (packObject.Type != "ofs_delta" && packObject.Type != "ref_delta")
                 {
                     byte[] header = CreateObjectHeaderInBytes(packObject.Type, packObject.Data.Length);
                     byte[] fullData = header.Concat(packObject.Data).ToArray();
                     using SHA1 sha1 = SHA1.Create();
                     byte[] tempHashBytes = sha1.ComputeHash(fullData);
                     string tempHash = BitConverter.ToString(tempHashBytes).Replace("-", "").ToLower();
                     if (_packObjectsByHash.ContainsKey(tempHash))
                     {
                         return tempHash; // Found existing object by hashing raw data
                     }
                 }
                 // Can't easily check deltas without resolving them first
            }
        }
        return null; // Not found in hash cache
    }


    // Finds the base object for a delta object
    static PackObject FindBaseObject(PackObject deltaObject)
    {
        if (deltaObject.Type == "ofs_delta")
        {
            if (_packObjectsByOffset.TryGetValue(deltaObject.BaseOffset, out PackObject baseObj))
            {
                return baseObj;
            }
            else
            {
                // Base object might be outside the current packfile (thin pack)
                // Or it's an error in the packfile/parsing
                throw new InvalidOperationException($"Base object not found in packfile at offset {deltaObject.BaseOffset} for delta at {deltaObject.Offset}");
                // In a real client, you might need to check the existing object store
            }
        }
        else if (deltaObject.Type == "ref_delta")
        {
            // Try finding by hash in the packfile cache first
            if (_packObjectsByHash.TryGetValue(deltaObject.BaseHash!, out PackObject baseObjByHash))
            {
                return baseObjByHash;
            }
            // If not in pack cache, check the existing object store on disk
            if (ObjectExists(deltaObject.BaseHash!))
            {
                 // Read the existing object and represent it as a PackObject for consistency
                 // This is a simplification; we just need its type and data
                 byte[] rawData = ReadObject(deltaObject.BaseHash!);
                 // Parse type and content
                 int nullByteIndex = Array.IndexOf(rawData, (byte)0);
                 string header = Encoding.UTF8.GetString(rawData, 0, nullByteIndex);
                 string[] headerParts = header.Split(' ');
                 string baseType = headerParts[0];
                 byte[] baseContent = rawData.Skip(nullByteIndex + 1).ToArray();
                 // Create a temporary PackObject representation
                 return new PackObject(baseType, baseContent, -1); // Offset -1 indicates it came from disk
            }
            else
            {
                 throw new InvalidOperationException($"Base object with hash {deltaObject.BaseHash} not found for delta at {deltaObject.Offset}");
            }
        }
        else
        {
            throw new ArgumentException("Object is not a delta object.");
        }
    }

    // Checks if an object exists in the local .git/objects store
    static bool ObjectExists(string hash)
    {
        string path = Path.Combine(".git", "objects", hash.Substring(0, 2), hash.Substring(2));
        return File.Exists(path);
    }

     // Reads the raw data (content only) of a resolved object
     // Assumes the object has been stored or resolved already
    static byte[] ReadObjectData(PackObject resolvedObject)
    {
        if (resolvedObject.Type == "ofs_delta" || resolvedObject.Type == "ref_delta")
        {
            throw new ArgumentException("Cannot directly read data from an unresolved delta object.");
        }

        // If the object came from disk (offset -1 in FindBaseObject), we need to read it again
        if (resolvedObject.Offset == -1 && !string.IsNullOrEmpty(resolvedObject.BaseHash)) // BaseHash might hold the actual hash if read from disk
        {
             byte[] rawData = ReadObject(resolvedObject.BaseHash);
             int nullByteIndex = Array.IndexOf(rawData, (byte)0);
             return rawData.Skip(nullByteIndex + 1).ToArray();
        }
        // If it was resolved and stored in _packObjectsByHash
        else if (_packObjectsByHash.Values.FirstOrDefault(po => po.Offset == resolvedObject.Offset) is PackObject cachedResolved)
        {
             // Return the data stored in the cache (which should be the resolved data)
             return cachedResolved.Data;
        }
        // Fallback: Try reading from disk using calculated hash (if StorePackObject was called)
        else
        {
             byte[] header = CreateObjectHeaderInBytes(resolvedObject.Type, resolvedObject.Data.Length);
             byte[] fullData = header.Concat(resolvedObject.Data).ToArray();
             using SHA1 sha1 = SHA1.Create();
             byte[] hashBytes = sha1.ComputeHash(fullData);
             string hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

             if (ObjectExists(hash))
             {
                 byte[] rawData = ReadObject(hash);
                 int nullByteIndex = Array.IndexOf(rawData, (byte)0);
                 return rawData.Skip(nullByteIndex + 1).ToArray();
             }
        }

        // If we reach here, we couldn't get the data
        throw new InvalidOperationException($"Could not retrieve data for resolved object originally at offset {resolvedObject.Offset}");
    }


    // Applies Git delta patch instructions
    static byte[] ApplyDelta(byte[] baseData, byte[] deltaInstructions)
    {
        using var deltaStream = new MemoryStream(deltaInstructions);
        using var reader = new BinaryReader(deltaStream);

        // Read base and target size (variable length)
        long baseSize = ReadVariableLengthInt(reader);
        if (baseSize != baseData.Length)
        {
            throw new InvalidDataException($"Delta base size mismatch: expected {baseData.Length}, got {baseSize}");
        }
        long targetSize = ReadVariableLengthInt(reader);

        using var targetStream = new MemoryStream((int)targetSize);

        while (deltaStream.Position < deltaStream.Length)
        {
            byte instruction = reader.ReadByte();
            if ((instruction & 0x80) != 0) // Copy instruction
            {
                long copyOffset = 0;
                long copySize = 0;
                int shift = 0;

                // Read offset
                if ((instruction & 0x01) != 0) copyOffset |= (long)reader.ReadByte() << shift; shift += 8;
                if ((instruction & 0x02) != 0) copyOffset |= (long)reader.ReadByte() << shift; shift += 8;
                if ((instruction & 0x04) != 0) copyOffset |= (long)reader.ReadByte() << shift; shift += 8;
                if ((instruction & 0x08) != 0) copyOffset |= (long)reader.ReadByte() << shift; shift += 8; // Max 32-bit offset

                shift = 0;
                // Read size
                if ((instruction & 0x10) != 0) copySize |= (long)reader.ReadByte() << shift; shift += 8;
                if ((instruction & 0x20) != 0) copySize |= (long)reader.ReadByte() << shift; shift += 8;
                if ((instruction & 0x40) != 0) copySize |= (long)reader.ReadByte() << shift; shift += 8; // Max 24-bit size

                if (copySize == 0) copySize = 0x10000; // 0 means 65536 bytes

                // Perform the copy from baseData
                if (copyOffset + copySize > baseData.Length)
                {
                     throw new InvalidDataException("Delta copy instruction exceeds base data boundaries.");
                }
                targetStream.Write(baseData, (int)copyOffset, (int)copySize);
            }
            else // Add instruction
            {
                byte addSize = (byte)(instruction & 0x7F);
                if (addSize == 0)
                {
                     throw new InvalidDataException("Delta add instruction has zero size.");
                }
                byte[] dataToAdd = reader.ReadBytes(addSize);
                targetStream.Write(dataToAdd, 0, dataToAdd.Length);
            }
        }

        if (targetStream.Length != targetSize)
        {
            throw new InvalidDataException($"Delta application result size mismatch: expected {targetSize}, got {targetStream.Length}");
        }

        return targetStream.ToArray();
    }

    // Reads Git's variable-length integer (used in delta instructions)
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


    // Checkout the specified commit hash into the working directory
    static void CheckoutHead(string commitHash)
    {
        try
        {
            byte[] commitRawData = ReadObject(commitHash);
            // Find header end
            int nullByteIndex = Array.IndexOf(commitRawData, (byte)0);
            if (nullByteIndex == -1) throw new InvalidDataException($"Invalid commit object format: {commitHash}");

            string commitContent = Encoding.UTF8.GetString(commitRawData, nullByteIndex + 1, commitRawData.Length - (nullByteIndex + 1));
            string? treeHash = null;

            // Find the tree line
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
            {
                throw new InvalidDataException($"Could not find tree hash in commit object: {commitHash}");
            }

            // Update the ref (e.g., refs/heads/main) to point to this commit
            string headRefPath = Path.Combine(".git", "HEAD");
            string headContent = File.ReadAllText(headRefPath).Trim();
            if (headContent.StartsWith("ref: "))
            {
                string refName = headContent.Substring(5).Trim();
                string refPath = Path.Combine(".git", refName);
                Directory.CreateDirectory(Path.GetDirectoryName(refPath)); // Ensure ref directory exists
                File.WriteAllText(refPath, commitHash + "\n");
            } else {
                // Handle detached HEAD state if necessary, though clone usually sets a ref
                 File.WriteAllText(headRefPath, commitHash + "\n"); // Overwrite HEAD directly if not a ref
            }


            // Start checkout process from the root of the working directory
            Console.WriteLine($"Checking out tree {treeHash}");
            // Clear existing files/dirs (except .git) before checkout
            ClearWorkingDirectory();
            CheckoutTree(treeHash, Directory.GetCurrentDirectory());
        }
        catch (FileNotFoundException)
        {
             Console.Error.WriteLine($"Error: Commit object {commitHash} not found.");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error during checkout: {ex.Message}");
            Console.Error.WriteLine(ex.StackTrace);
        }
    }

    // Clears the working directory, ignoring the .git folder
    static void ClearWorkingDirectory()
    {
        string currentDir = Directory.GetCurrentDirectory();
        foreach (string file in Directory.GetFiles(currentDir))
        {
            // Avoid deleting the .git directory itself if it's somehow listed as a file (unlikely)
            if (Path.GetFileName(file) == ".git") continue;
             try { File.Delete(file); } catch (Exception ex) { Console.Error.WriteLine($"Could not delete file {file}: {ex.Message}"); }
        }
        foreach (string dir in Directory.GetDirectories(currentDir))
        {
            if (Path.GetFileName(dir) == ".git") continue; // Explicitly skip .git directory
            try { Directory.Delete(dir, true); } catch (Exception ex) { Console.Error.WriteLine($"Could not delete directory {dir}: {ex.Message}"); }
        }
    }


    // Recursively checks out a tree object into the specified base path
    static void CheckoutTree(string treeHash, string basePath)
    {
        byte[] treeRawData = ReadObject(treeHash);
        int headerEnd = Array.IndexOf(treeRawData, (byte)0);
        if (headerEnd == -1) throw new InvalidDataException($"Invalid tree object format: {treeHash}");

        int currentPos = headerEnd + 1;
        while (currentPos < treeRawData.Length)
        {
            // Find space after mode
            int spaceIndex = Array.IndexOf(treeRawData, (byte)' ', currentPos);
            if (spaceIndex == -1) break;
            string mode = Encoding.UTF8.GetString(treeRawData, currentPos, spaceIndex - currentPos);

            // Find null byte after filename
            int nullIndex = Array.IndexOf(treeRawData, (byte)0, spaceIndex + 1);
            if (nullIndex == -1) break;
            string name = Encoding.UTF8.GetString(treeRawData, spaceIndex + 1, nullIndex - (spaceIndex + 1));

            // Read the 20-byte hash
            byte[] hashBytes = new byte[20];
            Buffer.BlockCopy(treeRawData, nullIndex + 1, hashBytes, 0, 20);
            string entryHash = Convert.ToHexString(hashBytes).ToLower();

            string fullPath = Path.Combine(basePath, name);

            if (mode == "40000") // Directory
            {
                Console.WriteLine($"Creating directory: {fullPath}");
                Directory.CreateDirectory(fullPath);
                CheckoutTree(entryHash, fullPath); // Recurse
            }
            else if (mode == "120000") // Symbolic Link
            {
                Console.WriteLine($"Creating symbolic link: {fullPath} (from blob {entryHash})");
                try
                {
                    byte[] blobRawData = ReadObject(entryHash);
                    int blobHeaderEnd = Array.IndexOf(blobRawData, (byte)0);
                    if (blobHeaderEnd == -1) throw new InvalidDataException($"Invalid blob object format for symlink: {entryHash}");

                    // Extract target path *after* the header
                    byte[] targetPathBytes = new byte[blobRawData.Length - (blobHeaderEnd + 1)];
                    Buffer.BlockCopy(blobRawData, blobHeaderEnd + 1, targetPathBytes, 0, targetPathBytes.Length);
                    string targetPath = Encoding.UTF8.GetString(targetPathBytes);

                    // Create the symbolic link
                    File.CreateSymbolicLink(fullPath, targetPath);
                    Console.WriteLine($"Created symlink: {fullPath} -> {targetPath}");

                }
                catch (FileNotFoundException)
                {
                     Console.Error.WriteLine($"Error: Blob object {entryHash} for symlink '{name}' not found.");
                }
                catch (UnauthorizedAccessException)
                {
                    Console.Error.WriteLine($"Error: Insufficient permissions to create symbolic link '{fullPath}'. Try running with elevated privileges (e.g., as Administrator or using sudo) or enabling Developer Mode on Windows.");
                }
                catch (IOException ioEx) when (ioEx.Message.Contains("symbolic link")) // Catch specific IO exceptions related to symlinks
                {
                     Console.Error.WriteLine($"Error: Could not create symbolic link '{fullPath}'. The operating system may not support it or requires specific privileges. {ioEx.Message}");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Error creating symlink {fullPath}: {ex.Message}");
                }
            }
            else // Regular File (modes like 100644, 100755)
            {
                Console.WriteLine($"Writing file: {fullPath} (from blob {entryHash})");
                try
                {
                    byte[] blobRawData = ReadObject(entryHash);
                    int blobHeaderEnd = Array.IndexOf(blobRawData, (byte)0);
                    if (blobHeaderEnd == -1) throw new InvalidDataException($"Invalid blob object format: {entryHash}");

                    // Extract content *after* the header
                    byte[] blobContent = new byte[blobRawData.Length - (blobHeaderEnd + 1)];
                    Buffer.BlockCopy(blobRawData, blobHeaderEnd + 1, blobContent, 0, blobContent.Length);

                    File.WriteAllBytes(fullPath, blobContent);

                    // --- Handle file modes ---
                    if (mode == "100755" &&
                       (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX)))
                    {
                        try
                        {
                            // Set permissions to rwxr-xr-x (755)
                            File.SetUnixFileMode(fullPath,
                                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                                UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                                UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
                            Console.WriteLine($"Set executable permissions for: {fullPath}");
                        }
                        catch (Exception ex)
                        {
                            // Log error if setting permissions fails, but continue checkout
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

            // Move to the start of the next entry
            currentPos = nullIndex + 1 + 20;
        }
    }
}