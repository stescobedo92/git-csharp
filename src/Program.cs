using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

namespace GitCloneImplementation
{
    class Program
    {
        static void Main(string[] args)
        {
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
                string timezone = "+0000"; // Using UTC for simplicity

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
            else if (command == "clone")
            {
                if (args.Length < 3)
                {
                    Console.WriteLine("Usage: clone <repository_url> <target_directory>");
                    return;
                }

                string repoUrl = args[1];
                string targetDir = args[2];

                if (Directory.Exists(targetDir))
                {
                    if (Directory.GetFiles(targetDir).Length > 0 || Directory.GetDirectories(targetDir).Length > 0)
                    {
                        Console.WriteLine("Target directory must be empty");
                        return;
                    }
                }
                else
                {
                    Directory.CreateDirectory(targetDir);
                }

                Directory.SetCurrentDirectory(targetDir);

                Directory.CreateDirectory(".git");
                Directory.CreateDirectory(".git/objects");
                Directory.CreateDirectory(".git/refs");
                File.WriteAllText(".git/HEAD", "ref: refs/heads/main\n");

                using (var client = new HttpClient())
                {
                    client.DefaultRequestHeaders.Add("User-Agent", "Custom-Git-Client");

                    string infoRefsUrl = $"{repoUrl}/info/refs?service=git-upload-pack";
                    var infoRefsResponse = client.GetAsync(infoRefsUrl).Result;
                    if (!infoRefsResponse.IsSuccessStatusCode)
                    {
                        Console.WriteLine($"Failed to fetch refs: {infoRefsResponse.StatusCode}");
                        return;
                    }

                    string infoRefsContent = infoRefsResponse.Content.ReadAsStringAsync().Result;
                    var refs = ParseInfoRefs(infoRefsContent);

                    string? headRef = refs.FirstOrDefault(r => r.Contains("HEAD"))?.Split(' ')[0];
                    string headCommit = headRef ?? refs.FirstOrDefault(r => r.Contains("refs/heads/main"))?.Split(' ')[0];
                    if (string.IsNullOrEmpty(headCommit))
                    {
                        Console.WriteLine("Could not determine HEAD commit");
                        return;
                    }

                    string uploadPackUrl = $"{repoUrl}/git-upload-pack";
                    string wantRequest = $"0032want {headCommit}\n0000\n0009done\n";
                    var content = new StringContent(wantRequest, Encoding.UTF8, "application/x-git-upload-pack-request");
                    var packResponse = client.PostAsync(uploadPackUrl, content).Result;
                    if (!packResponse.IsSuccessStatusCode)
                    {
                        Console.WriteLine($"Failed to fetch pack: {packResponse.StatusCode}");
                        return;
                    }

                    byte[] packData = packResponse.Content.ReadAsByteArrayAsync().Result;
                    ProcessPackfile(packData);
                    CheckoutHead(headCommit);
                }

                Console.WriteLine($"Cloned repository to {targetDir}");
            }
            else
            {
                throw new ArgumentException($"Unknown command {command}");
            }
        }

        static byte[] CreateObjectHeaderInBytes(string gitObjectType, byte[] input) => Encoding.UTF8.GetBytes($"{gitObjectType} {input.Length}\0");

        static byte[] GenerateHashByte(string gitObjectType, byte[] input)
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
            File.WriteAllBytes($".git/objects/{hashString[..2]}/{hashString[2..]}", compressedObject);

            return hash;
        }

        static byte[]? GenerateTreeObjectFileHash(string currentPath)
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

        static byte[] CreateTreeObject(List<TreeEntry> treeEntries)
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

        // Clone Helper Methods

        static List<string> ParseInfoRefs(string content)
        {
            var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            var refs = new List<string>();
            foreach (var line in lines)
            {
                if (line.StartsWith("#") || line.Length < 40) continue;
                string hashAndRef = line.Substring(4); // Skip pkt-line length prefix
                if (hashAndRef.Length >= 40)
                {
                    refs.Add(hashAndRef);
                }
            }
            return refs;
        }

        static void ProcessPackfile(byte[] packData)
        {
            using var memoryStream = new MemoryStream(packData);
            using var zLibStream = new ZLibStream(memoryStream, CompressionMode.Decompress);
            using var outputStream = new MemoryStream();
            zLibStream.CopyTo(outputStream);
            byte[] unpackedData = outputStream.ToArray();

            int offset = 0;
            if (unpackedData.Length < 12 || Encoding.ASCII.GetString(unpackedData, 0, 4) != "PACK")
            {
                Console.WriteLine("Invalid packfile format");
                return;
            }
            offset += 8; // Skip "PACK" and version
            int objectCount = BitConverter.ToInt32(unpackedData.Skip(offset).Take(4).Reverse().ToArray(), 0);
            offset += 4;

            var offsetToHash = new Dictionary<int, string>();
            var hashToData = new Dictionary<string, (string type, byte[] content)>();

            for (int i = 0; i < objectCount; i++)
            {
                int currentOffset = offset;
                var (type, data, baseHash, isDelta, newOffset) = ReadPackObject(unpackedData, offset, offsetToHash);
                offset = newOffset;

                string objType;
                byte[] content;

                if (!isDelta)
                {
                    // Full object
                    objType = type;
                    content = data;
                }
                else
                {
                    // Delta object
                    if (!hashToData.TryGetValue(baseHash, out var baseData))
                    {
                        throw new Exception($"Base object {baseHash} not found for delta");
                    }
                    objType = baseData.type; // Assume same type as base
                    content = ApplyDelta(baseData.content, data);
                }

                string hash = StoreObject(objType, content);
                offsetToHash[currentOffset] = hash;
                hashToData[hash] = (objType, content);
            }
        }

        static (string type, byte[] data, string baseHash, bool isDelta, int offset) ReadPackObject(byte[] packData, int offset, Dictionary<int, string> offsetToHash)
        {
            int objectStartOffset = offset;
            byte firstByte = packData[offset];
            int typeNum = (firstByte >> 4) & 7;

            // Map packfile type numbers to object types or delta indicators
            string type = typeNum switch
            {
                1 => "commit",
                2 => "tree",
                3 => "blob",
                4 => "tag",
                6 => "ofs-delta",
                7 => "ref-delta",
                _ => throw new Exception($"Unsupported object type: {typeNum}")
            };

            // Decode variable-length size
            long size = firstByte & 0x0F;
            int shift = 4;
            offset++;
            while ((packData[offset - 1] & 0x80) != 0)
            {
                size |= (long)(packData[offset] & 0x7F) << shift;
                shift += 7;
                offset++;
            }

            if (typeNum == 6 || typeNum == 7)
            {
                // Delta object
                string baseHash;
                if (typeNum == 6) // ofs-delta
                {
                    long baseOffset = ReadVariableLengthInteger(packData, ref offset);
                    long baseObjectOffset = objectStartOffset - baseOffset;
                    if (!offsetToHash.TryGetValue((int)baseObjectOffset, out baseHash))
                    {
                        throw new Exception($"Base object offset {baseObjectOffset} not found for ofs-delta");
                    }
                }
                else // ref-delta
                {
                    baseHash = BitConverter.ToString(packData, offset, 20).Replace("-", "").ToLower();
                    offset += 20;
                }

                // Decompress delta data
                using var inputStream = new MemoryStream(packData, offset, packData.Length - offset);
                using var zLibStream = new ZLibStream(inputStream, CompressionMode.Decompress);
                using var outputStream = new MemoryStream();
                zLibStream.CopyTo(outputStream);
                byte[] deltaData = outputStream.ToArray();
                offset += (int)inputStream.Position;

                return (type, deltaData, baseHash, true, offset);
            }
            else
            {
                // Full object
                using var inputStream = new MemoryStream(packData, offset, packData.Length - offset);
                using var zLibStream = new ZLibStream(inputStream, CompressionMode.Decompress);
                using var outputStream = new MemoryStream();
                zLibStream.CopyTo(outputStream);
                byte[] content = outputStream.ToArray();
                offset += (int)inputStream.Position;

                return (type, content, null, false, offset);
            }
        }

        static long ReadVariableLengthInteger(byte[] data, ref int offset)
        {
            long value = 0;
            int shift = 0;
            byte b;
            do


            {
                b = data[offset];
                value |= (long)(b & 0x7F) << shift;
                shift += 7;
                offset++;
            } while ((b & 0x80) != 0);
            return value;
        }

        static byte[] ApplyDelta(byte[] baseContent, byte[] deltaData)
        {
            using var stream = new MemoryStream(deltaData);
            using var reader = new BinaryReader(stream);

            // Read base and result sizes
            long baseSize = ReadVariableLengthInteger(reader);
            long resultSize = ReadVariableLengthInteger(reader);
            if (baseSize != baseContent.Length)
            {
                throw new Exception("Base size mismatch in delta");
            }

            byte[] result = new byte[resultSize];
            int pos = 0;

            while (stream.Position < stream.Length)
            {
                byte cmd = reader.ReadByte();
                if ((cmd & 0x80) != 0) // Copy command
                {
                    int offset = 0;
                    int size = 0;
                    if ((cmd & 0x01) != 0) offset |= reader.ReadByte();
                    if ((cmd & 0x02) != 0) offset |= reader.ReadByte() << 8;
                    if ((cmd & 0x04) != 0) offset |= reader.ReadByte() << 16;
                    if ((cmd & 0x08) != 0) offset |= reader.ReadByte() << 24;
                    if ((cmd & 0x10) != 0) size |= reader.ReadByte();
                    if ((cmd & 0x20) != 0) size |= reader.ReadByte() << 8;
                    if ((cmd & 0x40) != 0) size |= reader.ReadByte() << 16;
                    if (size == 0) size = 0x10000; // Default size if not specified
                    Array.Copy(baseContent, offset, result, pos, size);
                    pos += size;
                }
                else if (cmd > 0) // Insert command
                {
                    int length = cmd & 0x7F;
                    byte[] insertData = reader.ReadBytes(length);
                    Array.Copy(insertData, 0, result, pos, length);
                    pos += length;
                }
                else
                {
                    throw new Exception("Invalid delta command");
                }
            }

            if (pos != resultSize)
            {
                throw new Exception("Delta application did not produce expected size");
            }
            return result;
        }

        static long ReadVariableLengthInteger(BinaryReader reader)
        {
            long value = 0;
            int shift = 0;
            byte b;
            do
            {
                b = reader.ReadByte();
                value |= (long)(b & 0x7F) << shift;
                shift += 7;
            } while ((b & 0x80) != 0);
            return value;
        }

        static string StoreObject(string type, byte[] content)
        {
            byte[] header = Encoding.UTF8.GetBytes($"{type} {content.Length}\0");
            byte[] fullData = header.Concat(content).ToArray();

            using SHA1 sha1 = SHA1.Create();
            byte[] hashBytes = sha1.ComputeHash(fullData);
            string hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

            string objectDir = Path.Combine(".git", "objects", hash[..2]);
            string objectPath = Path.Combine(objectDir, hash[2..]);
            Directory.CreateDirectory(objectDir);
            File.WriteAllBytes(objectPath, fullData);
            return hash;
        }

        static void CheckoutHead(string commitHash)
        {
            string commitPath = Path.Combine(".git", "objects", commitHash[..2], commitHash[2..]);
            byte[] commitData = File.ReadAllBytes(commitPath);
            string commitContent = Encoding.UTF8.GetString(commitData);
            string treeHash = commitContent.Split('\n')[0].Split(' ')[1];

            // Update HEAD reference
            File.WriteAllText(".git/refs/heads/main", commitHash + "\n");

            // Checkout tree
            CheckoutTree(treeHash, Directory.GetCurrentDirectory());
        }

        static void CheckoutTree(string treeHash, string basePath)
        {
            string treePath = Path.Combine(".git", "objects", treeHash[..2], treeHash[2..]);
            byte[] treeData = File.ReadAllBytes(treePath);
            string treeContent = Encoding.UTF8.GetString(treeData);
            var entries = treeContent.Split('\0', StringSplitOptions.RemoveEmptyEntries).Skip(1);

            foreach (var entry in entries)
            {
                var parts = entry.Split(' ');
                string mode = parts[0];
                string name = parts[1];
                string hash = parts[2].TrimEnd('\n');
                string fullPath = Path.Combine(basePath, name);

                if (mode == "40000") // Directory
                {
                    Directory.CreateDirectory(fullPath);
                    CheckoutTree(hash, fullPath);
                }
                else // File
                {
                    string blobPath = Path.Combine(".git", "objects", hash[..2], hash[2..]);
                    byte[] blobData = File.ReadAllBytes(blobPath);
                    string blobContent = Encoding.UTF8.GetString(blobData);
                    File.WriteAllText(fullPath, blobContent.Split('\0')[1]); // Skip header
                }
            }
        }

        public record TreeEntry(string Mode, string FileName, byte[] Hash);
    }
}