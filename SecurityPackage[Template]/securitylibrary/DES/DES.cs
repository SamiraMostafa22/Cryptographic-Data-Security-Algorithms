using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        int[,] PC_1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9},  
                                      { 1, 58, 50, 42, 34, 26, 18},
                                      { 10, 2, 59, 51, 43, 35, 27},
                                      { 19, 11, 3, 60, 52, 44, 36},
                                      { 63, 55, 47, 39, 31, 23, 15},
                                      { 7, 62, 54, 46, 38, 30, 22},
                                      { 14, 6, 61, 53, 45, 37, 29},
                                      { 21, 13, 5, 28, 20, 12, 4}};

        int[] numbOfShiftLiftBits = new int[16] { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };


        int[,] PC_2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 },
                                      { 3, 28, 15, 6, 21, 10 },
                                      { 23, 19, 12, 4, 26, 8 },
                                      { 16, 7, 27, 20, 13, 2 },
                                      { 41, 52, 31, 37, 47, 55 },
                                      { 30, 40, 51, 45, 33, 48 },
                                      { 44, 49, 39, 56, 34, 53 },
                                      { 46, 42, 50, 36, 29, 32 } };

        int[,] IP = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 },
                                    { 60, 52, 44, 36, 28, 20, 12, 4 },
                                    { 62, 54, 46, 38, 30, 22, 14, 6 },
                                    { 64, 56, 48, 40, 32, 24, 16, 8 },
                                    { 57, 49, 41, 33, 25, 17,  9, 1 },
                                    { 59, 51, 43, 35, 27, 19, 11, 3 },
                                    { 61, 53, 45, 37, 29, 21, 13, 5 },
                                    { 63, 55, 47, 39, 31, 23, 15, 7 } };

        int[,] E_Bit_Selection = new int[8, 6] { { 32, 1,  2,  3,  4,  5 },
                                                 { 4,  5,  6,  7,  8,  9 },
                                                 { 8,  9, 10,  11, 12, 13 },
                                                 { 12, 13, 14, 15, 16, 17 },
                                                 { 16, 17, 18, 19, 20, 21 },
                                                 { 20, 21, 22, 23, 24, 25 },
                                                 { 24, 25, 26, 27, 28, 29 },
                                                 { 28, 29, 30, 31, 32, 1 } };


        public static int[,] S_1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                                                    { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                                                    { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                                                    { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };

        public static int[,] S_2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                                                    { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                                                    { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                                                    { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };

        public static int[,] S_3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                                                    { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                                                    { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                                                    { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };

        public static int[,] S_4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                                                    { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                                                    { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                                                    { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };

        public static int[,] S_5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                                                    { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                                                    { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                                                    { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };

        public static int[,] S_6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                                                    { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                                                    { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                                                    { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };

        public static int[,] S_7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                                                    { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                                                    { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                                                    { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };

        public static int[,] S_8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                                                    { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                                                    { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                                                    { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

        int[,] PInverse = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 },
                                          { 39, 7, 47, 15, 55, 23, 63, 31 },
                                          { 38, 6, 46, 14, 54, 22, 62, 30 },
                                          { 37, 5, 45, 13, 53, 21, 61, 29 },
                                          { 36, 4, 44, 12, 52, 20, 60, 28 },
                                          { 35, 3, 43, 11, 51, 19, 59, 27 },
                                          { 34, 2, 42, 10, 50, 18, 58, 26 }, 
                                          { 33, 1, 41, 9, 49, 17, 57, 25 } };

        public static int[,] P = new int[8, 4] { { 16, 7, 20, 21 },
                                               { 29, 12, 28, 17 },
                                               { 1, 15, 23, 26 },
                                               { 5, 18, 31, 10 },
                                               { 2, 8, 24, 14 },
                                               { 32, 27, 3, 9 },
                                               { 19, 13, 30, 6 },
                                               { 22, 11, 4, 25 } };

        string Shift = "1122222212222221";
        public string ConvertToBinary(string TextNeedToConvert)
        {
            string ConvertedText = null;
            for (int i = 2; i < TextNeedToConvert.Length; i++)
            {
                if (TextNeedToConvert[i] == 'A')
                {
                    ConvertedText += "1010";
                }
                else if (TextNeedToConvert[i] == 'B')
                {
                    ConvertedText += "1011";
                }
                else if (TextNeedToConvert[i] == 'C')
                {
                    ConvertedText += "1100";
                }
                else if (TextNeedToConvert[i] == 'D')
                {
                    ConvertedText += "1101";
                }
                else if (TextNeedToConvert[i] == 'E')
                {
                    ConvertedText += "1110";
                }
                else if (TextNeedToConvert[i] == 'F')
                {
                    ConvertedText += "1111";
                }
                else if (TextNeedToConvert[i] == '0')
                {
                    ConvertedText += "0000";
                }
                else if (TextNeedToConvert[i] == '1')
                {
                    ConvertedText += "0001";
                }
                else if (TextNeedToConvert[i] == '2')
                {
                    ConvertedText += "0010";
                }
                else if (TextNeedToConvert[i] == '3')
                {
                    ConvertedText += "0011";
                }
                else if (TextNeedToConvert[i] == '4')
                {
                    ConvertedText += "0100";
                }
                else if (TextNeedToConvert[i] == '5')
                {
                    ConvertedText += "0101";
                }
                else if (TextNeedToConvert[i] == '6')
                {
                    ConvertedText += "0110";
                }
                else if (TextNeedToConvert[i] == '7')
                {
                    ConvertedText += "0111";
                }
                else if (TextNeedToConvert[i] == '8')
                {
                    ConvertedText += "1000";
                }
                else if (TextNeedToConvert[i] == '9')
                {
                    ConvertedText += "1001";
                }
            }
            return ConvertedText;
            ;
        }
        public string Permutaion(int[,] TableForP, string txt, int row, int col)
        {
            string NewText = "";
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    NewText += txt[TableForP[i, j] - 1];
                }
            }
            return NewText;
        }
        public void SHIFTLeft(string RightText, string LeftText, List<string> SHIFTleft, List<string> SHIFTright)
        {
            for (int i = 0; i < Shift.Length; i++)
            {
                int s = Shift[i] - '0';
                // Console.WriteLine(s);

                string tmp = null;
                if (i == 0 || i == 1 || i == 8 || i == 15)
                {
                    tmp = tmp + LeftText[0];
                    LeftText = LeftText.Remove(0, 1);
                    LeftText += tmp;
                    tmp = "";
                    tmp = tmp + RightText[0];
                    RightText = RightText.Remove(0, 1);
                    RightText += tmp;
                }
                else
                {
                    tmp = tmp + LeftText[0];
                    LeftText = LeftText.Remove(0, 1);
                    LeftText += tmp;
                    tmp = "";
                    tmp = tmp + LeftText[0];
                    LeftText = LeftText.Remove(0, 1);
                    LeftText += tmp;
                    tmp = "";
                    tmp = tmp + RightText[0];
                    RightText = RightText.Remove(0, 1);
                    RightText += tmp;
                    tmp = "";
                    tmp = tmp + RightText[0];
                    RightText = RightText.Remove(0, 1);
                    RightText += tmp;
                }
                SHIFTleft.Add(LeftText);
                SHIFTright.Add(RightText);
                //Console.WriteLine("C" + (i + 1) + " : " + LeftText + "\n");
                //Console.WriteLine("D" + (i + 1) + " : " + RightText + "\n");
            }
        }
        public List<string> Concatenate(List<string> SHIFTleft, List<string> SHIFTright, List<string> Concate)
        {

            for (int i = 0; i < 16; i++)
            {
                Concate.Add(SHIFTleft[i] + SHIFTright[i]);
            }
            return Concate;
        }
        public List<string> CollectSIX(string txt)
        {
            List<string> COllect = new List<string>();
            for (int i = 0; i < txt.Length; i += 6)
            {
                string Txtsix = null;
                for (int j = i; j < i + 6; j++)
                {
                    Txtsix += txt[j];
                }
                COllect.Add(Txtsix);
            }
            return COllect;
        }
        public string SBOX(List<string> COllectforSBOX)
        {
            string res = "";
            for (int i = 0; i < COllectforSBOX.Count; i++)
            {
                string t = COllectforSBOX[i];
                string tmp1 = t[0].ToString() + t[5];
                string tmp2 = t[1].ToString() + t[2] + t[3] + t[4];

                int row = Convert.ToInt32(tmp1, 2);
                int col = Convert.ToInt32(tmp2, 2);

                int result;
                switch (i)
                {
                    case 0:
                        result = S_1[row, col];
                        res += Convert.ToString(result, 2).PadLeft(4, '0');
                        break;
                    case 1:
                        result = S_2[row, col];
                        res += Convert.ToString(result, 2).PadLeft(4, '0');
                        break;
                    case 2:
                        result = S_3[row, col];
                        res += Convert.ToString(result, 2).PadLeft(4, '0');
                        break;
                    case 3:
                        result = S_4[row, col];
                        res += Convert.ToString(result, 2).PadLeft(4, '0');
                        break;
                    case 4:
                        result = S_5[row, col];
                        res += Convert.ToString(result, 2).PadLeft(4, '0');
                        break;
                    case 5:
                        result = S_6[row, col];
                        res += Convert.ToString(result, 2).PadLeft(4, '0');

                        break;
                    case 6:
                        result = S_7[row, col];
                        res += Convert.ToString(result, 2).PadLeft(4, '0');
                        break;
                    case 7:
                        result = S_8[row, col];
                        res += Convert.ToString(result, 2).PadLeft(4, '0');
                        break;
                }
            }
            return res;
        }
        public override string Decrypt(string cipherText, string key)
        {
            string Key_Conveerted = ConvertToBinary(key);
            string NewCipher = ConvertToBinary(cipherText); ;
            string Key_Reduced1 = Permutaion(PC_1, Key_Conveerted, 8, 7);
            string leftKey = Key_Reduced1.Substring(0, 28);
            string RightKey = Key_Reduced1.Substring(28, 28);
            List<string> LeftKey_shifted = new List<string>();
            List<string> RightKey_shifted = new List<string>();
            SHIFTLeft(RightKey, leftKey, LeftKey_shifted, RightKey_shifted);
            List<string> ConcatenatedKey = new List<string>();
            Concatenate(LeftKey_shifted, RightKey_shifted, ConcatenatedKey);
            List<string> Key_Reduced2 = new List<string>();
            for (int i = 0; i < 16; i++)
            {
                string PERMKEY = Permutaion(PC_2, ConcatenatedKey[i], 8, 6);
                Key_Reduced2.Add(PERMKEY);
            }
            Key_Reduced2 = Enumerable.Reverse(Key_Reduced2).ToList();
            string Cipher_Reduced1 = Permutaion(IP, NewCipher, 8, 8);
            List<string> LeftCipher_shifted = new List<string>();
            List<string> RightCipher_shifted = new List<string>();
            string leftCipher = Cipher_Reduced1.Substring(0, 32);
            string RightCipher = Cipher_Reduced1.Substring(32, 32);
            LeftCipher_shifted.Add(leftCipher);
            RightCipher_shifted.Add(RightCipher);
            List<string> COllectforSBOX = new List<string>();
            for (int i = 0; i < 16; i++)
            {
                LeftCipher_shifted.Add(RightCipher);
                COllectforSBOX.Clear();
                string NEWRIGHT = Permutaion(E_Bit_Selection, RightCipher, 8, 6);
                string XOR = XorOperation(NEWRIGHT, Key_Reduced2[i]);
                COllectforSBOX = CollectSIX(XOR);
                string sbox= SBOX(COllectforSBOX);
                string LastPermutation = Permutaion(P, sbox, 8, 4);
                XOR = null;
                XOR= XorOperation(LastPermutation, leftCipher);
                leftCipher = RightCipher;
                RightCipher = XOR;
                RightCipher_shifted.Add(RightCipher);
            }
            string LASTRESULT = RightCipher_shifted[16] + LeftCipher_shifted[16];
            string BEFORECONVERT = Permutaion(PInverse, LASTRESULT, 8, 8);
            string AfterCONVERT = Convert.ToInt64(BEFORECONVERT, 2).ToString("X").PadLeft(16, '0');
            return "0x" + AfterCONVERT;
            //return null;
            //throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();

            plainText = Convert.ToString(Convert.ToInt64(plainText, 16), 2).PadLeft(64, '0');  

            key = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');  // pads the binary string with leading zeros to ensure that it has a fixed length of 64 bits.

            key = ApplayPC_1(key);

            //Cropping C0 and D0 from the Key1
            string C0 = "";
            string D0 = "";
            GetC0AndD0(key, ref C0, ref D0);

            //Circular shift left for all D's and C's
            string[] allShiftedC = new string[16];
            string[] allShiftedD = new string[16];
            Generate16ShiftedCAndD(ref allShiftedC, ref allShiftedD, C0, D0);

            //Generating the 16 key by Apllaying PC_2
            string[] Keys = new string[16];
            ApplayPC_2(allShiftedC, allShiftedD, ref Keys);

            //Permutation of the plain text by Applaying IP table on plain text
            string Plain = ApplayIP(plainText);

            //Cropping L0,R0 from the plain
            string L0 = "";
            string R0 = "";
            GetL0AndR0(Plain, ref L0, ref R0);

            //generating all L's And R's
            string[] roundsOfL = new string[16];
            string[] roundsOfR = new string[16];
            Generate16LAndR(ref roundsOfL, ref roundsOfR, R0, L0, Keys);

            //Permuting the R16+L16 to get the cihper text
            return ApplayPInverse(roundsOfL, roundsOfR);
        }
        public string ApplayPC_1(string key)
        {
            string PK = "";
            for (int i = 0; i < 8; i++)    // pc1
            {
                for (int j = 0; j < 7; j++)
                {
                    PK += key[PC_1[i, j] - 1];
                }
            }
            return PK;
        }
        public void GetC0AndD0(string key, ref string C0, ref string D0)
        {
            for (int i = 0; i < 28; i++)
            {
                C0 += key[i];
                D0 += key[i + 28];
            }
        }
        public void Generate16ShiftedCAndD(ref string[] allShiftedC, ref string[] allShiftedD, string C0, string D0)
        {
            for (int i = 0; i < 16; i++)
            {
                if (i == 0)
                {
                    allShiftedC[i] = CircularShiftLeft(C0, numbOfShiftLiftBits[i]);
                    allShiftedD[i] = CircularShiftLeft(D0, numbOfShiftLiftBits[i]);
                }
                else
                {
                    allShiftedC[i] = CircularShiftLeft(allShiftedC[i - 1], numbOfShiftLiftBits[i]);
                    allShiftedD[i] = CircularShiftLeft(allShiftedD[i - 1], numbOfShiftLiftBits[i]);
                }

            }
        }
        public static string CircularShiftLeft(string key, int shift)
        {
            shift %= key.Length; // 010111
            return key.Substring(shift) + key.Substring(0, shift);
        }
        public void ApplayPC_2(string[] allShiftedC, string[] allShiftedD, ref string[] Keys)
        {
            for (int i = 0; i < 16; i++) //no. of rounds
            {
                string PK = "";
                for (int j = 0; j < 8; j++) // PC
                {
                    string key = "";
                    for (int k = 0; k < 6; k++)
                    {
                        key = allShiftedC[i] + allShiftedD[i];
                        PK += key[PC_2[j, k] - 1];
                    }
                }
                Keys[i] = PK;    // key is 48 bit
            }
        }
        public string ApplayIP(string plainText)
        {
            string Plain = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    Plain += plainText[IP[i, j] - 1];
                }
            }
            return Plain;
        }
        public void GetL0AndR0(string plain, ref string L0, ref string R0)
        {
            for (int i = 0; i < 32; i++)
            {
                L0 += plain[i];
                R0 += plain[i + 32];
            }
        }
        public void Generate16LAndR(ref string[] roundsOfL, ref string[] roundsOfR, string R0, string L0, string[] Keys)
        {
            for (int i = 0; i < 16; i++)
            {
                if (i == 0)
                {
                    roundsOfL[i] = R0;
                    roundsOfR[i] = XorOperation(L0, CalcFunOfRAndK(ApplayE_bit_selictionTable(R0, E_Bit_Selection), Keys[i]));
                }
                else
                {
                    roundsOfL[i] = roundsOfR[i - 1];
                    roundsOfR[i] = XorOperation(roundsOfL[i - 1], CalcFunOfRAndK(ApplayE_bit_selictionTable(roundsOfR[i - 1], E_Bit_Selection), Keys[i]));
                }
            }
        }
        public static string ApplayE_bit_selictionTable(string R, int[,] E_Bit)
        {
            string expandedRight = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 6; j++)
                {
                    expandedRight += R[E_Bit[i, j] - 1];
                }
            }
            return expandedRight;
        }
        public static string CalcFunOfRAndK(string expandedRight, string Key)
        {
            // S(K1+E(R0))   // K1+E(R0)
            return ApplayPTable(ApplaySTables(XorOperation(expandedRight, Key)));
        }
        private static string XorOperation(string expandedRight, string key)
        {
            int Length = Math.Max(expandedRight.Length, key.Length);
            string result = "";
            expandedRight = expandedRight.PadLeft(Length, '0');
            key = key.PadLeft(Length, '0');

            for (int i = 0; i < Length; i++)
            {
                if (expandedRight[i] == key[i])
                {
                    result += '0';
                }
                else
                {
                    result += '1';
                }
            }
            return result;
        }
        public static string ApplaySTables(string res)
        {
            string[] blocks = new string[8];
            int startIndex = -6;

            for (int i = 0; i < 8; i++)
            {
                startIndex += 6;
                blocks[i] = res.Substring(startIndex, 6);
            }

            string[] newBlocks = new string[8];

            ApplaySTables(blocks, 1, ref newBlocks, S_1);

            ApplaySTables(blocks, 2, ref newBlocks, S_2);

            ApplaySTables(blocks, 3, ref newBlocks, S_3);

            ApplaySTables(blocks, 4, ref newBlocks, S_4);

            ApplaySTables(blocks, 5, ref newBlocks, S_5);

            ApplaySTables(blocks, 6, ref newBlocks, S_6);

            ApplaySTables(blocks, 7, ref newBlocks, S_7);

            ApplaySTables(blocks, 8, ref newBlocks, S_8);


            string F = "";
            for (int i = 0; i < 8; i++)
            {
                F += newBlocks[i];
            }

            return F;
        }
        public static string ApplaySTables(string[] blocks, int index, ref string[] newBlocks, int[,] S)
        {
            char[] removedBits = new char[2];
            removedBits[0] = blocks[index - 1][0];
            removedBits[1] = blocks[index - 1][5];
            string roww = new string(removedBits);
            int rowNumber = Convert.ToInt32(roww, 2);
            string colsBits = blocks[index - 1].Substring(1, 4);
            int colNumber = Convert.ToInt32(colsBits, 2);
            return newBlocks[index - 1] = Convert.ToString(S[rowNumber, colNumber], 2).PadLeft(4, '0');  //public static string ToString(int value, int toBase);
        }
        public static string ApplayPTable(string F)
        {
            string result = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result += F[P[i, j] - 1];
                }
            }
            return result;
        }
        public string ApplayPInverse(string[] roundsOfL, string[] roundsOfR)
        {
            string R16L16 = roundsOfR[15] + roundsOfL[15];
            string cipherText = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    cipherText += R16L16[PInverse[i, j] - 1];
                }
            }
            cipherText = "0x" + Convert.ToInt64(cipherText, 2).ToString("X").PadLeft(16, '0');
            return cipherText;
        }
    }
}