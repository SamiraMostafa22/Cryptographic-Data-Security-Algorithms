using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            bool isUpperCase = Char.IsUpper(cipherText, 0);
            if (isUpperCase)
            {
                cipherText = cipherText.ToLower();
            }
            char Secound = cipherText[1];
            int k = 0;
            int[] Keys = new int[50];
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] == Secound)
                {
                    Keys[k] = i;
                    k++;
                }
            }
            int result = 0;
            for (int i = 0; i < k; i++)
            {
                string check = Encrypt(plainText, Keys[i]);
                if (check == cipherText)
                {
                    result = Keys[i];
                    break;
                }
            }
            return result;
            //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, int key)
        {
            bool isUpperCase = Char.IsUpper(cipherText, 0);
            if (isUpperCase)
            {
                cipherText = cipherText.ToLower();
            }
            int size = cipherText.Length, Length;
            if (size % key != 0)
            {
                Length = size / key;
                Length++;
            }
            else
            {
                Length = size / key;
            }
            string plainText = null;
            int index = 0;
            bool Stop = false;
            char[,] Matrix = new char[key, Length];
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < Length; j++)
                {
                    if (cipherText.Length == index)
                    {
                        Stop = true;
                        break;
                    }
                    Matrix[i, j] = cipherText[index];
                    index++;
                }
                if (Stop == true)
                {
                    break;
                }
            }
            index = 0;
            Stop = false;
            for (int i = 0; i < Length; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if ((cipherText.Length) == index)
                    {
                        Stop = true;
                        break;
                    }
                    //Console.WriteLine (Matrix[j,i]);
                    plainText += Matrix[j, i];
                    index++;
                }
                if (Stop == true)
                {
                    break;
                }
            }
            return plainText;
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, int key)
        {
            bool isUpperCase = Char.IsUpper(plainText, 0);
            if (isUpperCase)
            {
                plainText = plainText.ToLower();
            }
            int size = plainText.Length, Length;
            if (size % key != 0)
            {
                Length = size / key;
                Length++;
            }
            else
            {
                Length = size / key;
            }
            char[,] Matrix = new char[key, Length];
            int index = 0;
            bool Stop = false;
            string cipherText = null;
            for (int i = 0; i < Length; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if ((plainText.Length) == index)
                    {
                        Stop = true;
                        break;
                    }
                    Matrix[j, i] = plainText[index];
                    //Console.WriteLine (Matrix[j,i]);
                    index++;
                }
                if (Stop == true)
                {
                    break;
                }
            }
            index = 0;
            Stop = false;
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < Length; j++)
                {
                    if (Matrix[i, j] == '\0')
                    {
                        break;
                    }
                    if (plainText.Length == index)
                    {
                        Stop = true;
                        break;
                    }
                    cipherText += Matrix[i, j];
                    index++;
                }
                if (Stop == true)
                {
                    break;
                }
            }
            return cipherText;
            //throw new NotImplementedException();
        }
    }
}
