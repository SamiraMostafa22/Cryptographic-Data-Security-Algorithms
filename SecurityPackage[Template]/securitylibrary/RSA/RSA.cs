using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int PowerMod(int number1, int number2, int N)
        {

            long Result, finalResult;

            if (number2 == 0)
            {
                return 1;
            }

            Result = PowerMod(number1, number2 / 2, N);
            finalResult = Result % N;
            finalResult = (finalResult * finalResult) % N;


            if (number2 % 2 == 0)
            {
                return (int)finalResult;
            }
            else
            {
                return (int)((number1 * finalResult) % N);
            }
        }

        public int Encrypt(int p, int q, int M, int e)
        {
            int cipherText;           // p = 3 , q = 11
            int multPrimeNumber = p * q;       // 3 * 11 = 33

            cipherText = PowerMod(M, e, multPrimeNumber);
            return cipherText;

            //throw new NotImplementedException();
        }

        public int Decrypt(int p, int q, int C, int publicKey)
        {
            //throw new NotImplementedException();	
            int BigN = p * q;
            int fayN = (p - 1) * (q - 1);
            // privateKey= inverse of publicKey mod fayN
            int privateKey = ExtendedEuclidAlgo(publicKey, fayN);
            //plainText = C power privateKey mod BigN
            int plainText = 1;//sum
            for (int i = 0; i < privateKey; i++)
            {
                // c : cipher text
                plainText = (plainText * C) % BigN;
            }
            return plainText;
        }
        private int ExtendedEuclidAlgo(int b, int m)
        {
            int A1 = 1;
            int A2 = 0;
            int A3 = m;
            int B1 = 0;
            int B2 = 1;
            int B3 = b;

            while (true)
            {
                if (B3 == 0)
                {
                    return 0;
                }
                if (B3 == 1)

                {
                    return (B2 + m) % m;
                }
                int Q = A3 / B3;
                int Temp1 = A1 - (Q * B1);
                int Temp2 = A2 - (Q * B2);
                int Temp3 = A3 - (Q * B3);

                A1 = B1;
                A2 = B2;
                A3 = B3;

                B1 = Temp1;
                B2 = Temp2;
                B3 = Temp3;
            }
        }
    }
}
