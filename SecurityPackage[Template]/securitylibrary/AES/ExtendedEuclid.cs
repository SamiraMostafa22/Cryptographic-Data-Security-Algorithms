﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            //throw new NotImplementedException();

            int A1 = 1, A2 = 0, A3 = baseN, B1 = 0, B2 = 1, B3 = number;
            int Q, firstResult, secoundResult, thirdResult;
            while (B3 != 0 && B3 != 1)
            {
                Q = A3 / B3;
                firstResult = A1 - (Q * B1);
                secoundResult = A2 - (Q * B2);
                thirdResult = A3 - (Q * B3);
                A1 = B1;
                A2 = B2;
                A3 = B3;
                B1 = firstResult;
                B2 = secoundResult;
                B3 = thirdResult;
            }
            if (B3 == 0)
            {
                return -1;
            }
            else if (B3 == 1)
            {
                if (B2 < 0)
                {
                    return B2 + baseN;
                }
                else
                {
                    return B2;
                }
            }
            return 0;
        }
    }
}