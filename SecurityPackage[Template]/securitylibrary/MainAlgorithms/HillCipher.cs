using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

class Program
{
    static void Main()
    {

    }
}

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText) //2x2
        {
            //throw new NotImplementedException();

            // key            // plain                    cipher { 19, 16, 18, 18, 24, 15, 10, 14, 16, 21, 8, 22 }
            // 3  2         //15 24 14 4 14 4               
            // 8  5         //0 12 17 12 13 24                                  // 19       10
            // 16       14
            // 18       16
            // 18       21
            // 24       8
            // 15       22

            // cipher = key * plain ==> key = inversePlain * cipher
            /*
             int[,] plainMatrix = GetMatrix(2, plainText);

             int[,] cipherMatrix = GetMatrix(cipherText.Count / 2, cipherText);
             */

            List<int> cipherTextTest = new List<int>();

            List<int> randomKey = new List<int>();

            bool isEqual = false;

            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        for (int l = 0; l < 26; l++)
                        {
                            randomKey = new List<int> { l, k, j, i };

                            cipherTextTest = Encrypt(plainText, randomKey);    // to get cipherTextTest

                            isEqual = Enumerable.SequenceEqual(cipherTextTest, cipherText);  //bool isEqual = Enumerable.SequenceEqual(x, y); ==>  Compare two List

                            if (isEqual)
                            {
                                return randomKey;
                            }
                        }
                    }
                }
            }

            throw new InvalidAnlysisException();   //  isEqual = false ==> invalid Key

        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            //throw new NotImplementedException();

            int keySize = (int)Math.Sqrt(key.Count);

            int[,] keyMatrix = GetKeyMatrix(key, keySize);

            int[,] cipherMatrix = GetTextAsMatrix(keySize, cipherText);

            int determinant = CalculateDeterminant(keyMatrix, key);

            int[,] inverseMatrix = CalculateInverse(keyMatrix, key, determinant);

            int[,] transpose = CalculateTranspose(inverseMatrix, key);

            int[,] plainMatrix = CalcTextMatrix(keySize, cipherText, transpose, cipherMatrix);

            return GetTextAsList(key, cipherText, plainMatrix);
        }
        public int[,] CalculateTranspose(int[,] inverseMatrix, List<int> key)
        {
            int m = (int)Math.Sqrt(key.Count);

            int[,] transposMatrixRes = new int[m, m];

            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    transposMatrixRes[i, j] = inverseMatrix[j, i];
                }
            }

            return transposMatrixRes;
        }
        public int[,] CalculateInverse(int[,] keyMatrix, List<int> key, int det)
        {
            int[,] inverseMatrix = new int[(int)Math.Sqrt(key.Count), (int)Math.Sqrt(key.Count)];


            if ((int)Math.Sqrt(key.Count) == 2)   // 2x2
            {
                if (det != 1)
                {
                    if (det != -1)
                        throw new Exception();
                }
                // inverseMatrix[0, 0] = 21;
                //inverseMatrix[1, 1] = 23;
                //inverseMatrix[0, 1] = 8;
                // inverseMatrix[1, 0] =2;

                int invDet = 1 / det;

                inverseMatrix[0, 0] = ( keyMatrix[1, 1] * invDet + 26) % 26;
                inverseMatrix[0, 1] = (-keyMatrix[1, 0] * invDet + 26) % 26;
                inverseMatrix[1, 0] = (-keyMatrix[0, 1] * invDet + 26) % 26;
                inverseMatrix[1, 1] = ( keyMatrix[0, 0] * invDet + 26) % 26;

                //Console.WriteLine("The inverse of the matrix is:");
                // Console.WriteLine(inverseMatrix[0, 0] + " " + inverseMatrix[0, 1]);
                // Console.WriteLine(inverseMatrix[1, 0] + " " + inverseMatrix[1, 1]);
            }
            else if ((int)Math.Sqrt(key.Count) == 3)  // 3x3
            {
                int b = 0;

                for (int i = 1; i < 26; i++)
                {
                    if (((i * det) % 26) == 1)
                    {
                        b = i;
                        break;
                    }
                }

                inverseMatrix[0, 0] = ((( (keyMatrix[1, 1] * keyMatrix[2, 2] - keyMatrix[2, 1] * keyMatrix[1, 2]) * b) % 26) + 26) % 26;
                inverseMatrix[1, 0] = (((-(keyMatrix[0, 1] * keyMatrix[2, 2] - keyMatrix[0, 2] * keyMatrix[2, 1]) * b) % 26) + 26) % 26;
                inverseMatrix[2, 0] = ((( (keyMatrix[0, 1] * keyMatrix[1, 2] - keyMatrix[0, 2] * keyMatrix[1, 1]) * b) % 26) + 26) % 26;
                inverseMatrix[0, 1] = (((-(keyMatrix[1, 0] * keyMatrix[2, 2] - keyMatrix[1, 2] * keyMatrix[2, 0]) * b) % 26) + 26) % 26;
                inverseMatrix[1, 1] = ((( (keyMatrix[0, 0] * keyMatrix[2, 2] - keyMatrix[0, 2] * keyMatrix[2, 0]) * b) % 26) + 26) % 26;
                inverseMatrix[2, 1] = (((-(keyMatrix[0, 0] * keyMatrix[1, 2] - keyMatrix[1, 0] * keyMatrix[0, 2]) * b) % 26) + 26) % 26;
                inverseMatrix[0, 2] = ((( (keyMatrix[1, 0] * keyMatrix[2, 1] - keyMatrix[2, 0] * keyMatrix[1, 1]) * b) % 26) + 26) % 26;
                inverseMatrix[1, 2] = (((-(keyMatrix[0, 0] * keyMatrix[2, 1] - keyMatrix[2, 0] * keyMatrix[0, 1]) * b) % 26) + 26) % 26;
                inverseMatrix[2, 2] = ((( (keyMatrix[0, 0] * keyMatrix[1, 1] - keyMatrix[1, 0] * keyMatrix[0, 1]) * b) % 26) + 26) % 26;
            }
            return inverseMatrix;
        }
        public int CalculateDeterminant(int[,] keyMatrix, List<int> key)
        {
            int determinant = 0;
            if ((int)Math.Sqrt(key.Count) == 3)   // 3x3
            {
                determinant = (keyMatrix[0, 0] * keyMatrix[1, 1] * keyMatrix[2, 2]
                               + keyMatrix[0, 1] * keyMatrix[1, 2] * keyMatrix[2, 0]
                               + keyMatrix[0, 2] * keyMatrix[1, 0] * keyMatrix[2, 1]
                               - keyMatrix[0, 2] * keyMatrix[1, 1] * keyMatrix[2, 0]
                               - keyMatrix[0, 1] * keyMatrix[1, 0] * keyMatrix[2, 2]
                               - keyMatrix[0, 0] * keyMatrix[1, 2] * keyMatrix[2, 1]) % 26;

                if (determinant < 0)
                {
                    determinant += 26;
                }
            }
            else if ((int)Math.Sqrt(key.Count) == 2)  // 2x2
            {
                determinant = (keyMatrix[0, 0] * keyMatrix[1, 1] - keyMatrix[0, 1] * keyMatrix[1, 0]) % 26;
            }

            return determinant;
        }
        public int[,] GetKeyMatrix(List<int> key, int keySize)
        {

            int[,] keyMatrix = new int[keySize, keySize];
            int counter = 0;

            for (int i = 0; i < keySize; i++)
            {
                for (int j = 0; j < keySize; j++)
                {
                    keyMatrix[i, j] = key[counter]; // erorr !!!!!
                    counter++;
                }
            }
            return keyMatrix;
        }
        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            //throw new NotImplementedException();

            // key  ==>  length

            // 00  10  01  11
            // key            // plain               cipher { 19, 16, 18, 18, 24, 15, 10, 14, 16, 21, 8, 22 }
            // 3  2         //15 24 14 4 14 4               // 19  18  24  10  16  8
            // 8  5         //0 12 17 12 13 24              // 16  18  15  14  21  22 
            
            int keySize = (int)Math.Sqrt(key.Count);

            int[,] keyMatrix = GetKeyMatrix(key, keySize);

            int[,] PlainMatrix = GetTextAsMatrix(keySize, plainText);

            int[,] CipherMatrix = CalcTextMatrix(keySize, plainText, keyMatrix, PlainMatrix);

            return GetTextAsList(key, plainText, CipherMatrix);
            
            
        }

        // convert from list to matrix
        public int[,] GetTextAsMatrix(int keySize, List<int> Text)
        {
            int[,] Matrix = new int[keySize, Text.Count / keySize];
            int counter = 0; // plainText  || cipherText
            for (int i = 0; i < Text.Count / keySize; i++)  //  ==> cols 
            {
                for (int j = 0; j < keySize; j++) //  ==> rows
                {
                    Matrix[j, i] = Text[counter];
                    counter++;
                }
            }
            return Matrix;
        }


        //   when Text == plain      ==>   return cipher
        //   when Text == cipher      ==>   return plain
        public int[,] CalcTextMatrix(int keySize, List<int> Text, int[,] keyMatrix, int[,] Matrix)
        {
            int[,] TextMatrix = new int[keySize, Text.Count / keySize];

            for (int i = 0; i < keySize; i++)
            {
                for (int j = 0; j < Text.Count / keySize; j++)
                {
                    TextMatrix[i, j] = 0;
                    for (int k = 0; k < keySize; k++)
                    {
                        TextMatrix[i, j] += (keyMatrix[i, k] * Matrix[k, j]) % 26;
                    }
                }
            }

            return TextMatrix;
        }

        public List<int> GetTextAsList(List<int> key, List<int> Text, int[,] Matrix)
        {
            List<int> TextAsList = new List<int>();
            int m = (int)Math.Sqrt(key.Count);
            for (int i = 0; i < Text.Count / m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    TextAsList.Add(Matrix[j, i] % 26);
                }
            }
            return TextAsList;
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            //throw new NotImplementedException();

            // cipher = key * plain ==> key = inversePlain * cipher
            
            int[,] plainMatrix = GetTextAsMatrix(3, plain3);

            int[,] cipherMatrix = GetTextAsMatrix(3, cipher3);

            int plainDeterminant = CalculateDeterminant(plainMatrix, plain3);                      // plain3.Count == 9   ==>  sqrt(9)  ==> matrix 3x3

            int[,] inversePlainMatrix = CalculateInverse(plainMatrix, plain3, plainDeterminant);   // plain3.Count == 9   ==>  sqrt(9)  ==> matrix 3x3

            int[,] transposePlainMatrix = CalculateTranspose(inversePlainMatrix, plain3);          // plain3.Count == 9   ==>  sqrt(9)  ==> matrix 3x3

            int[,] keyMatrix = CalcTextMatrix(3, plain3, cipherMatrix, transposePlainMatrix);     // plain3.Count == 9   ==>  sqrt(9)  ==> matrix 3x3

            keyMatrix = CalculateTranspose(keyMatrix, plain3);                                     // plain3.Count == 9   ==>  sqrt(9)  ==> matrix 3x3

            return GetTextAsList(plain3, plain3, keyMatrix);

        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}
