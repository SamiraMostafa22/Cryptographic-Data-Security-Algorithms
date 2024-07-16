using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        static void IntializeSAndT(ref int[] S, ref int[] T, string key)
        {
            for (int i = 0; i < 256; i++)
            {
                S[i] = i;
                T[i] = key[i % key.Length];
            }
        }

        static void IntialPermutation(ref int[] S, ref int[] T)
        {
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                Swap(ref S[i], ref S[j]);
            }
        }

        static void Swap(ref int First, ref int Second)
        {
            int temp;
            temp = First;
            First = Second;
            Second = temp;
        }

        static string GenerateKeyStreamAndGetCipherText(ref int[] S, ref int[] T, string plainText)
        {
            int a = 0, l = 0, k = 0;

            int t;

            string cipherText = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                a = (a + 1) % 256;
                l = (l + S[a]) % 256;
                Swap(ref S[a], ref S[l]);
                t = (S[a] + S[l]) % 256;
                k = S[t];

                cipherText += char.ConvertFromUtf32((plainText[i] ^ k));
            }
            return cipherText;
        }

        public override string Encrypt(string plainText, string key)
        {
            bool Hexadecimal = false;
            if (plainText.Substring(0, 2) == "0x")
            {
                Hexadecimal = true;
                string tmpPlainText = "";
                for (int i = 2; i < plainText.Length; i += 2)
                {
                    tmpPlainText += char.ConvertFromUtf32(Convert.ToInt32(plainText[i].ToString() + plainText[i + 1].ToString(), 16));
                }
                plainText = tmpPlainText;
            }

            if (key.Substring(0, 2) == "0x")
            {
                string tmpKey = "";
                for (int i = 2; i < key.Length; i += 2)
                {
                    tmpKey += char.ConvertFromUtf32(Convert.ToInt32(key[i].ToString() + key[i + 1].ToString(), 16));
                }
                key = tmpKey;
            }

            int[] S = new int[256];
            int[] T = new int[256];

            IntializeSAndT(ref S, ref T, key);

            IntialPermutation(ref S, ref T);

            string cipherText = GenerateKeyStreamAndGetCipherText(ref S, ref T, plainText);

            if (Hexadecimal)
            {
                cipherText = string.Join("", cipherText.Select(c => ((int)c).ToString("x2")));
                cipherText = "0x" + cipherText;
            }

            return cipherText;
        }
        public override string Decrypt(string cipherText, string key)
        {
            return Encrypt(cipherText, key);
        }
    }
}