using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {

        public string Analyse(string plainText, string cipherText)
        {
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


            while (keyStream.Length != 0) // i am stop at the end of the right index to build key.
            {
                if (plainText[0] == keyStream[count])
                {
                    break;
                }
                count++;
            }

            // generate the key..
            for (int j = 0; j < count; j++)
            {
                key = key + keyStream[j];
            }
            return key;
        }

        int charIndex(char c)
        {
            char[] chars = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            for (int i = 0; i < chars.Length; i++)
                if (chars[i] == c)
                    return i; // return the Index of the char. 

            return 0; // if it isnot exist return 0.
        }

        public string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            List<char> decrypted = new List<char>();
            int diff = cipherText.Length - key.Length;
            Console.WriteLine(diff);

            string keyStream = key;
            var table = tableau();
            for (int i = 0; i < cipherText.Length; i++)
            {
                var miniDic = table[keyStream[i]];
                foreach (var c in miniDic)
                {
                    if (c.Value == cipherText[i])
                    {
                        keyStream += c.Key;
                        decrypted.Add(c.Key);
                    }
                }
            }
            string decryptedTxt = new string(decrypted.ToArray());
            return decryptedTxt;
        }
        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            int diff = plainText.Length - key.Length; // diffrence 
            string keyStream = key;
            for (int i = 0; i < diff; i++)
            {
                keyStream += plainText[i];
            }
            Dictionary<char, Dictionary<char, char>> table = tableau();
            List<char> encrypted = new List<char>();

            for (int i = 0; i < plainText.Length; i++)
            {
                char plain, keyStr;
                plain = plainText[i];
                keyStr = keyStream[i];
                encrypted.Add(table[keyStr][plain]);

            }
            string encryptedTxt = new string(encrypted.ToArray());
            return encryptedTxt;

        }
        public Dictionary<char, Dictionary<char, char>> tableau()
        {
            Dictionary<char, Dictionary<char, char>> rows = new Dictionary<char, Dictionary<char, char>>();

            for (int i = 0; i < 26; i++)
            {
                char c = (char)(i + 97);

                Dictionary<char, char> colums = new Dictionary<char, char>();
                for (int j = 0; j < 26 - i; j++)
                {
                    colums[(char)(j + 97)] = (char)(j + i + 97);

                }
                int count = 0;
                for (int k = 26 - i; k < 26; k++)
                {
                    colums[(char)(k + 97)] = (char)(count + 97);
                    count++;
                }
                rows.Add(c, colums);

            }
            return rows;
        }
    }

}