using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        //alpha 
        char[,] alpha = new char[5, 5] {{ 'a', 'b', 'c', 'd', 'e' },
                                        { 'f', 'g', 'h', 'i', 'k' },
                                        { 'l', 'm', 'n', 'o', 'p' },
                                        { 'q', 'r', 's', 't', 'u' },
                                        { 'v', 'w', 'x', 'y', 'z' }};
        char[,] Matrix = new char[5, 5];
        //Generate Matrix
        char[,] GenerateMatrix(string key)
        {
            //enter key to matrix
            int[] freq = new int[26];
            int indexStr2 = 0, indexStr = 0;
            bool finish = false;
            int ii = 0, jj = 0;
            while (indexStr2 != key.Length)
            {
                if (freq[key[indexStr2] - 'a'] == 0)
                {
                    Matrix[ii, jj] = key[indexStr2];
                    freq[key[indexStr2] - 'a']++;
                    jj++;
                    jj %= 5;
                    if (jj == 0)
                    {
                        ii++;
                    }
                    indexStr++;
                }
                indexStr2++;
            }
            //complete the matrix 
            int ROW = indexStr / 5, COL = indexStr % 5;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (freq[alpha[i, j] - 'a'] == 0)
                    {
                        Matrix[ROW, COL] = alpha[i, j];
                        COL++;
                        COL %= 5;
                        if (COL == 0)
                        {
                            ROW++;
                        }
                        freq[alpha[i, j] - 'a']++;
                    }
                }
            }
            return Matrix;
        }
        //Add 
        string ADDStringDecrypt(string PlainText, int i1, int j1, int i2, int j2)
        {
            //in the same row
            if (i1 == i2)
            {
                j1--; j2--;
                if (j1 == -1)
                {
                    j1 = 4;
                }
                if (j2 == -1)
                {
                    j2 = 4;
                }
                PlainText += Matrix[i1, j1];
                PlainText += Matrix[i2, j2];
            }
            //in the same coloumn
            else if (j1 == j2)
            {
                i1--; i2--;
                if (i1 == -1)
                {
                    i1 = 4;
                }
                if (i2 == -1)
                {
                    i2 = 4;
                }
                PlainText += Matrix[i1, j1];
                PlainText += Matrix[i2, j2];
            }
            else
            {
                PlainText += Matrix[i1, j2];
                PlainText += Matrix[i2, j1];
            }
            return PlainText;
        }
        string ADDStringEncrypt(string cipherText, int i1, int j1, int i2, int j2)
        {
            //in the same row
            if (i1 == i2)
            {
                j1++; j2++;
                if (j1 == 5)
                {
                    j1 = 0;
                }
                if (j2 == 5)
                {
                    j2 = 0;
                }
                cipherText += Matrix[i1, j1];
                cipherText += Matrix[i2, j2];
            }
            //in the same coloumn
            else if (j1 == j2)
            {
                i1++; i2++;
                if (i1 == 5)
                {
                    i1 = 0;
                }
                if (i2 == 5)
                {
                    i2 = 0;
                }
                cipherText += Matrix[i1, j1];
                cipherText += Matrix[i2, j2];
            }
            else
            {
                cipherText += Matrix[i1, j2];
                cipherText += Matrix[i2, j1];
            }
            return cipherText;
        }

        string NewWordAfter(string Word, int WhichCase)
        {
            string NewWord = "";
            char NOW = ' ', NEXT = ' ';
            int index = 0, i1 = 0, i2 = 0, j1 = 0, j2 = 0;
            while (Word.Length != index)
            {
                bool first = false, secound = false, AddX = false;
                ;
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (WhichCase == 1)
                        {
                            NOW = Word[index];
                            NEXT = Word[index + 1];
                        }
                        else if (WhichCase == 0)
                        {
                            if (index == (Word.Length - 1))
                            {
                                NOW = Word[index];
                                NEXT = 'x';
                                AddX = true;
                            }
                            else if (Word[index] == Word[index + 1])
                            {
                                NOW = Word[index];
                                NEXT = 'x';
                                AddX = true;
                            }
                            else
                            {
                                NOW = Word[index];
                                NEXT = Word[index + 1];
                            }
                        }
                        if (NOW == Matrix[i, j])
                        {
                            i1 = i;
                            j1 = j;
                            first = true;
                        }
                        if (NEXT == Matrix[i, j])
                        {
                            i2 = i;
                            j2 = j;
                            secound = true;
                        }
                    }
                    if (first && secound)
                    {
                        break;
                    }
                }
                if (WhichCase == 1)
                {
                    NewWord = ADDStringDecrypt(NewWord, i1, j1, i2, j2);
                    index += 2;
                }
                else
                {
                    NewWord = ADDStringEncrypt(NewWord, i1, j1, i2, j2);
                    if (AddX)
                    {
                        index += 1;
                    }
                    else
                    {
                        index += 2;
                    }
                }
            }
            return NewWord;
        }
        public string Decrypt(string cipherText, string key)
        {
            //check upper or lower
            string PlainText = "";
            int DecryptCase = 1;
            bool isUpperCase = Char.IsUpper(cipherText, 0);
            if (isUpperCase)
            {
                cipherText = cipherText.ToLower();
            }
            cipherText = cipherText.Replace('j', 'i');
            bool isUpperCase2 = Char.IsUpper(key, 0);
            if (isUpperCase2)
            {
                key = key.ToLower();
            }
            key = key.Replace('j', 'i');
            GenerateMatrix(key);
            PlainText = NewWordAfter(cipherText, DecryptCase);
            int size = PlainText.Length;
            for (int index2 = size - 1; index2 >= 0; index2 -= 2)
            {
                if (PlainText[index2] == 'x' && index2 > 0)
                {
                    if (index2 == (size - 1))
                    {
                        PlainText = PlainText.Remove(index2, 1);
                    }
                    else if (PlainText[index2 - 1] == PlainText[index2 + 1])
                    {
                        PlainText = PlainText.Remove(index2, 1);
                    }
                }
            }
            return PlainText;
            //throw new NotImplementedException();
        }
        public string Encrypt(string plainText, string key)
        {
            //check upper or lower
            string cipherText = "";
            int DecryptCase = 0;
            bool isUpperCase = Char.IsUpper(plainText, 0);
            if (isUpperCase)
            {
                plainText = plainText.ToLower();
            }
            plainText = plainText.Replace('j', 'i');
            bool isUpperCase2 = Char.IsUpper(key, 0);
            if (isUpperCase2)
            {
                key = key.ToLower();
            }
            key = key.Replace('j', 'i');
            GenerateMatrix(key);
            cipherText = NewWordAfter(plainText, DecryptCase);
            // throw new NotImplementedException();
            return cipherText;
        }
    }
}