using System.IO;
using System.Security.Cryptography;
using System.Text;
namespace Crypto
{
	/// <summary>
	/// Encrypts and decrypts files using AES-256.
	/// String keys are encoded using UTF8.
	/// </summary>
	public static class FileEncryptor
	{
		private const int AesKeySize = 256;
		private const int AesBlockSize = 128;

		public const int KeySizeInBytes = AesKeySize / 8;

		private const int HashSize = 256;
		private const int HashSizeInBytes = 32;

		//For fixed key size
		public static byte[] HashKey(string key)
		{
			byte[] keyBytes = Encoding.UTF8.GetBytes(key);
			byte[] keyHash = SHA256.Create().ComputeHash(keyBytes);
			return keyHash;
		}

		/// <summary>
		/// Encrypts a file using a 32 character key.
		/// </summary>
		/// 
		public static Task EncryptAsync(string inputFilePath, string outputFilePath, string key)
		{
			if (string.IsNullOrWhiteSpace(key))
				throw new ArgumentException("Key cannot be empty!", nameof(key));

			byte[] keyBytes = Encoding.UTF8.GetBytes(key);
			return EncryptAsync(inputFilePath, outputFilePath, keyBytes);
		}

		public static async Task EncryptAsync(string inputFilePath, string outputFilePath, byte[] keyBytes)
		{
			if (!File.Exists(inputFilePath))
				throw new ArgumentException("Input file does not exist!", nameof(inputFilePath));

			if (keyBytes.Length != KeySizeInBytes)
				throw new ArgumentException("Key must be 32 bytes (256 bits) in length!", nameof(keyBytes));

			var sha256 = SHA256.Create();

			await using var inputFileStream = new FileStream(inputFilePath, FileMode.Open);
			await using var outFileStream = new FileStream(outputFilePath, FileMode.Create);

			// Write the hash of the key to beginning of file
			var keyHash = sha256.ComputeHash(keyBytes);
			await outFileStream.WriteAsync(keyHash.AsMemory(0, keyHash.Length));

			// Write the hash of the file to beginning of file
			var inputFileHash = await sha256.ComputeHashAsync(inputFileStream);
			await outFileStream.WriteAsync(inputFileHash.AsMemory(0, inputFileHash.Length));

			using var aes = Aes.Create();
			aes.BlockSize = AesBlockSize;
			aes.KeySize = AesKeySize;
			aes.Key = keyBytes;

			// Write initialization vector to beginning of file
			await outFileStream.WriteAsync(aes.IV.AsMemory(0, aes.IV.Length));

			inputFileStream.Seek(0, SeekOrigin.Begin);
			ICryptoTransform encryptor = aes.CreateEncryptor();
			await using CryptoStream cryptoStream = new(
				outFileStream,
				encryptor,
				CryptoStreamMode.Write);

			await inputFileStream.CopyToAsync(cryptoStream);
		}

		/// <summary>
		/// Decrypts a file using a 32 character key.
		/// </summary>
		public static Task DecryptAsync(string inputFilePath, string outputFilePath, string key)
		{
			if (string.IsNullOrWhiteSpace(key))
				throw new ArgumentException("Key cannot be empty!", nameof(key));

			byte[] keyBytes = Encoding.UTF8.GetBytes(key);
			return DecryptAsync(inputFilePath, outputFilePath, keyBytes);
		}

		public static async Task DecryptAsync(string inputFilePath, string outputFilePath, byte[] keyBytes)
		{
			if (!File.Exists(inputFilePath))
				throw new ArgumentException("Input file does not exist!", nameof(inputFilePath));

			if (keyBytes.Length != KeySizeInBytes)
				throw new ArgumentException("Key must be 32 bytes (256 bits) in length!", nameof(keyBytes));

			var sha256 = SHA256.Create();

			await using var inputFileStream = new FileStream(inputFilePath, FileMode.Open);

			//Read the hash of the key from beginning of the file
			var keyHash = new byte[HashSizeInBytes];
			int khReadBytes = await inputFileStream.ReadAsync(keyHash.AsMemory(0, HashSizeInBytes));
			if (khReadBytes != keyHash.Length)
				throw new ArgumentException("Failed to read hash of the key from input file!", nameof(inputFilePath));
			if(!keyHash.SequenceEqual(sha256.ComputeHash(keyBytes)))
				throw new ArgumentException("Wrong password!");

			//Read the hash of the file from beginning of the file
			var inputFileHash = new byte[HashSizeInBytes];
			int ifhReadBytes = await inputFileStream.ReadAsync(inputFileHash.AsMemory(0, HashSizeInBytes));
			if (ifhReadBytes != inputFileHash.Length)
				throw new ArgumentException("Failed to read hash of the file from input file!", nameof(inputFilePath));

			// Read IV from beginning of file
			const int blockSizeInBytes = AesBlockSize / 8;
			var initializationVector = new byte[blockSizeInBytes];
			int ivBytesRead = await inputFileStream.ReadAsync(initializationVector.AsMemory(0, blockSizeInBytes));
			if (ivBytesRead != initializationVector.Length)
				throw new ArgumentException("Failed to read initialization vector from input file!", nameof(inputFilePath));

			using var aes = Aes.Create();
			aes.BlockSize = AesBlockSize;
			aes.IV = initializationVector;
			aes.KeySize = AesKeySize;
			aes.Key = keyBytes;

			ICryptoTransform decryptor = aes.CreateDecryptor();
			await using CryptoStream cryptoStream = new(
				inputFileStream,
				decryptor,
				CryptoStreamMode.Read);

			using var stream = new MemoryStream();
			await cryptoStream.CopyToAsync(stream);
			stream.Seek(0, SeekOrigin.Begin);
			var outputHash = await sha256.ComputeHashAsync(stream);

			if (!inputFileHash.SequenceEqual(outputHash))
				throw new ArgumentException("The file is corrupt.");

			stream.Seek(0, SeekOrigin.Begin);
			await using var outFileStream = new FileStream(outputFilePath, FileMode.Create);
			await stream.CopyToAsync(outFileStream);

		}
	}
}
