using System;
using System.IO;

namespace RSAv2
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Введите путь к файлу: ");
            var pathToFile = Console.ReadLine();
            var stream = new StreamReader(pathToFile ?? string.Empty);
            var text = stream.ReadToEnd();
            Console.WriteLine("Текст: ");
            Console.WriteLine(text);
            Console.WriteLine("Шифрование");
            var rsa = new RSACrypt(new BigInteger(47), new BigInteger(31));
            var (publicKey, privateKey) = rsa.GenerateKeys();
            var encryptMessage = rsa.EncryptMessage(publicKey, text);
            Console.WriteLine("Шифрование закончено");
            Console.WriteLine("Дешифрование");
            var decryptMessage = rsa.DecryptMessage(privateKey, encryptMessage);
            Console.WriteLine("Конец дешифрования");
            Console.WriteLine("Расшифрованный текст:");
            Console.WriteLine(decryptMessage);
        }
    }
}