using System.IO;
using System.IO.Compression;
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
  
  if (int.TryParse(Encoding.UTF8.GetString(memory[5..].Span[..nullByteIndex]),out int blobLength) && blobLength != blobStr.Length) 
  {
    Console.WriteLine("Bad blob length");
    return;
  }

  Console.Write(Encoding.UTF8.GetString(blobStr.Span));
} 
else 
{
  throw new ArgumentException($"Unknown command {command}");
}