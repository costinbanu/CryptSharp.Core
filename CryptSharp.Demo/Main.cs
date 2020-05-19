#region License
/*
CryptSharp
Copyright (c) 2010-2014 James F. Bellinger <http://www.zer7.com/software/cryptsharp>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
#endregion

using System;

namespace CryptSharp.Demo
{
	class MainClass
	{
		public static void Main(string[] args)
		{
            BaseEncoding.TestVectors.Test();
            BlowfishTest.TestVectors.Test();
            Pbkdf2Test.TestVectors.Test();
            SCryptTest.TestVectors.Test();
            CrypterTest.TestVectors.Test();

            Console.WriteLine();

            Console.WriteLine("Now a simple BCrypt demo.");
			string crypt = CryptSharp.Crypter.Blowfish.GenerateSalt();
			Console.WriteLine("Our salt is: {0}", crypt);

            for (int i = 0; i < 10; i ++) 
			{
                // Try this against PHP's crypt('password', 'output of this function').
				crypt = CryptSharp.Crypter.Blowfish.Crypt("Hello World!", crypt);
				Console.WriteLine(crypt);
			}

            Console.WriteLine();
            
            Console.WriteLine("CryptSharp can also generate Apache-compatible htpasswd MD5...");
            Console.WriteLine("   (it does require an additional parameter)");
            Console.WriteLine("The password HelloWorld crypts to: {0}",
                Crypter.MD5.Crypt("HelloWorld", new CrypterOptions
                    {
                        { CrypterOption.Variant, MD5CrypterVariant.Apache }
                    }));

            Console.WriteLine();

            Console.WriteLine("WordPress uses portable PHPass passwords.");
            string wpPassword = Crypter.Phpass.Crypt("HelloWorld");
            Console.WriteLine("The password HelloWorld crypts to: {0}", wpPassword);
            Console.WriteLine("The above statement is {0}.", Crypter.CheckPassword("HelloWorld", wpPassword));
            Console.WriteLine("It is {0} that the password is OpenSesame.", Crypter.CheckPassword("OpenSesame", wpPassword));

            Console.WriteLine();

            Console.WriteLine("Press Enter to exit.");
            Console.ReadLine();
		}
	}
}
