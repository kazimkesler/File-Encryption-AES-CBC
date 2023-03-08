namespace Crypto
{
	internal class Program
	{
		public static async Task Main(string[] args)
		{
			//Test Program
			//args = new string[2] { "encrypt", @"C:\Users\Kazım Kesler\Desktop\test.txt" };
			//args = new string[2] { "decrypt", @"C:\Users\Kazım Kesler\Desktop\test_encrypted.txt" };
			try
			{
				if (args[0] == "help")
				{
					await Console.Out.WriteLineAsync("[encrypt|decrypt] [file]");
					return;
				}

				string configFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "password.cfg");
				byte[]? key = null;
				if (File.Exists(configFile))
					key = FileEncryptor.HashKey(File.ReadAllText(configFile));
				else
				{
					if (args[0] == "encrypt")
						Console.WriteLine("Decrypt the file after encryption to check the file (will be checked with SHA256)");
					Console.Write($"Password for {args[0]}: ");
					
					var pass = Console.ReadLine();
					
					if(string.IsNullOrEmpty(pass))
						throw new ArgumentNullException(nameof(pass));

					key = FileEncryptor.HashKey(pass);
				}

				var file = args[1].Split(".");
				if (args[0] == "encrypt")
				{
					var fileName = $"{file[0]}_encrypted.{file[1]}";
					await FileEncryptor.EncryptAsync(args[1], fileName, key);
				}
				else if (args[0] == "decrypt")
				{
					var fileName = $"{file[0]}_decrypted.{file[1]}";
					await FileEncryptor.DecryptAsync(args[1], fileName, key);
				}
				else
					throw new ArgumentNullException();
				Console.ForegroundColor = ConsoleColor.Green;
				Console.WriteLine("Successful");
			}
			catch (Exception ex)
			{
				Console.ForegroundColor = ConsoleColor.Red;
				Console.WriteLine(ex.Message);
			}
			Console.ReadKey();
		}
	}
}