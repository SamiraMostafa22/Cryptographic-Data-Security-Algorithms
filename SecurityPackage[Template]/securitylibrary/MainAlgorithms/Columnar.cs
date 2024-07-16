using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        int[] KnowRC(string word, List<int> key)
        {
            int col = key.Count, row = 0;
            if (word.Length % col != 0)
            {
                row = word.Length / col;
                row++;
            }
            else
            {
                row = word.Length / col;
            }
            int[] arr1 = new int[2];
            arr1[0] = row;
            arr1[1] = col;
            return arr1;
            //throw new NotImplementedException();
        }
        int[] ChangeKey(List<int> key, int col)
        {
            int[] arr = new int[col];
            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    if (key[j] == (i + 1))
                    {
                        arr[i] = j;
                    }
                }
            }
            return arr;
        }
        public List<int> Analyse(string plainText, string cipherText)
        {
            bool isUpperCase = Char.IsUpper(cipherText, 0);
            if (isUpperCase)
            {
                cipherText = cipherText.ToLower();
            }
            bool isUpperCase2 = Char.IsUpper(plainText, 0);
            if (isUpperCase2)
            {
                plainText = plainText.ToLower();
            }
            int row = 0, col = 0, size = 0;
            for (int i = 1; i < 8; i++)
            {
                if (plainText.Length % i == 0)
                {
                    col = i;
                }
            }
            int index = 0;
            bool Stop = false;
            row = plainText.Length / col;
            char[,] Matrix = new char[row, col];
            List<int> key = new List<int>(col);
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    if ((plainText.Length) == index)
                    {
                        Stop = true;
                        break;
                    }
                    Matrix[i, j] = plainText[index];
                    index++;
                }
                if (Stop == true)
                {
                    break;
                }
            }
            index = 0;
            string[] substringplain = new string[50];
            string snew = null;
            Stop = false;
            int c = 0;
            for (int i = 0; i < col; i++)
            {
                snew = null;
                for (int j = 0; j < row; j++)
                {
                    if ((plainText.Length) == index)
                    {
                        Stop = true;
                        break;
                    }
                    snew += Matrix[j, i];
                    index++;
                }
                substringplain[c] = snew;
                c++;
                if (Stop == true)
                {
                    break;
                }
            }
            string[] substringchipher = new string[50];
            index = 0;
            int x = 0;
            while (index != plainText.Length)
            {
                snew = null;
                for (int i = 0; i < row; i++)
                {
                    snew += cipherText[index];
                    index++;
                }
                substringchipher[x] = snew;
                x++;
            }
            int[] keys = new int[50];
            for (int i = 0; i < x; i++)
            {
                for (int j = 0; j < c; j++)
                {
                    if (substringchipher[i] == substringplain[j])
                    {
                        keys[j] = i + 1;
                        size++;
                        break;
                    }
                }
            }
            if (size == 0)
            {
                size = col + 2;
            }
            for (int i = 0; i < size; i++)
            {
                key.Add(keys[i]);
            }
            //throw new NotImplementedException();
            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            string PlainText = null;
            int[] rc = KnowRC(cipherText, key);
            int row = rc[0], col = rc[1];
            int[] arr = ChangeKey(key, col);
            int index = 0;
            bool Stop = false;
            char[,] Matrix = new char[row, col];
            for (int i = 0; i < col; i++)
            {
                int x = arr[i];
                for (int j = 0; j < row; j++)
                {
                    if ((cipherText.Length) == index)
                    {
                        Stop = true;
                        break;
                    }
                    Matrix[j, x] = cipherText[index];
                    // Console.WriteLine(Matrix[j, x]);
                    index++;
                }
                //Console.WriteLine("----------------------\n");
                if (Stop == true)
                {
                    break;
                }
            }
            index = 0;
            Stop = false;
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    if (Matrix[i, j] == '\0')
                    {
                        continue;
                    }
                    if (cipherText.Length == index)
                    {
                        Stop = true;
                        break;
                    }
                    PlainText += Matrix[i, j];
                    index++;
                }
                if (Stop == true)
                {
                    break;
                }
            }
            return PlainText;
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int[] rc = KnowRC(plainText, key);
            int row = rc[0], col = rc[1];
            int[] arr = ChangeKey(key, col);
            int index = 0;
            bool Stop = false;
            char[,] Matrix = new char[row, col];
            string cipherText = null;
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    if (plainText.Length == index)
                    {
                        Stop = true;
                        break;
                    }
                    Matrix[i, j] = plainText[index];
                    index++;
                }
                if (Stop == true)
                {
                    break;
                }
            }
            index = 0;
            Stop = false;
            for (int i = 0; i < col; i++)
            {
                int x = arr[i];
                for (int j = 0; j < row; j++)
                {
                    if (Matrix[j, x] == '\0')
                    {
                        continue;
                    }
                    if (plainText.Length == index)
                    {
                        Stop = true;
                        break;
                    }
                    cipherText += Matrix[j, x];
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
