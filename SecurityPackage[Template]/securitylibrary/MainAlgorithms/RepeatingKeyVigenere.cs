using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {

        int charIndex(char c)
        {
            char[] chars = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            for (int i = 0; i < chars.Length; i++)
                if (chars[i] == c)
                    return i; // return the Index of the char. 

            return 0; // if it isnot exist return 0.
        }
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int diff, count = 0;
            string keyStream = "", key = "";
            char[] chars = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            for (int i = 0; i < cipherText.Length; i++)
            {
                diff = (charIndex(cipherText[i]) - charIndex(plainText[i])) % 26; // make the diff between 0 & 25
                if (diff < 0) // if the diff become 0 => add 26 untill be (0 & 25)
                {
                    diff += 26;
                }
                keyStream = keyStream + chars[diff]; // add the char to the key stream.
            }
            // Console.WriteLine(keyStream);
            char first = keyStream[0], secound = keyStream[1];
            key += first;
            for (int j = 1; j < keyStream.Length; j++)
            {
                if (first != keyStream[j])
                {
                    key += keyStream[j];

                }
                else if (secound != keyStream[j + 1])
                {
                    key += keyStream[j];
                }
                else
                {
                    break;
                }
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            for (int i = 0; i < cipherText.Length; i++)
            {

                if (key.Length == cipherText.Length)
                {
                    break;
                }

                key += key[i];

            }
            string plainText = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                if ((cipherText[i] >= 'a' && cipherText[i] <= 'z'))
                {

                    int number1 = cipherText[i] - 65;
                    int number2 = key[i] - 97;
                    plainText += (char)((((number1 - number2) + 26) % 26) + 65);

                }
                if ((cipherText[i] >= 'A' && cipherText[i] <= 'Z'))
                {

                    int number1 = cipherText[i] - 65;
                    int number2 = key[i] - 97;
                    plainText += (char)((((number1 - number2) + 26) % 26) + 65);

                }


            }
            return plainText;

        }


        public string Encrypt(string plainText, string key)
        {

            //throw new NotImplementedException();
            //int size = plainText.Length;
            for (int i = 0; i < plainText.Length; i++)
            {

                if (key.Length == plainText.Length)
                {
                    break;
                }

                key += key[i];

            }
            string cipherText = "";
            for (int i = 0, j = 0; i < plainText.Length; i++, j++)
            {

                if ((plainText[i] >= 'a' && plainText[i] <= 'z'))
                {

                    int number1 = plainText[i] - 97;
                    int number2 = key[j] - 97;
                    cipherText += (char)((number1 + number2) % 26 + 97);

                }

                if ((plainText[i] >= 'A' && plainText[i] <= 'Z'))
                {

                    int number1 = plainText[i] - 65;
                    int number2 = key[j] - 65;
                    cipherText += (char)((number1 + number2) % 26 + 65);

                }
            }
            return cipherText;

        }
    }
}