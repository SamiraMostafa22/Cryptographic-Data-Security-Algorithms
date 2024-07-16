using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        public string[,] SBOX = new string[,] {
            {"63","7c","77","7b","f2","6b","6f","c5","30","01","67","2b","fe","d7","ab","76"},
            {"ca","82","c9","7d","fa","59","47","f0","ad","d4","a2","af","9c","a4","72","c0"},
            {"b7","fd","93","26","36","3f","f7","cc","34","a5","e5","f1","71","d8","31","15"},
            {"04","c7","23","c3","18","96","05","9a","07","12","80","e2","eb","27","b2","75"},
            {"09","83","2c","1a","1b","6e","5a","a0","52","3b","d6","b3","29","e3","2f","84"},
            {"53","d1","00","ed","20","fc","b1","5b","6a","cb","be","39","4a","4c","58","cf"},
            {"d0","ef","aa","fb","43","4d","33","85","45","f9","02","7f","50","3c","9f","a8"},
            {"51","a3","40","8f","92","9d","38","f5","bc","b6","da","21","10","ff","f3","d2"},
            {"cd","0c","13","ec","5f","97","44","17","c4","a7","7e","3d","64","5d","19","73"},
            {"60","81","4f","dc","22","2a","90","88","46","ee","b8","14","de","5e","0b","db"},
            {"e0","32","3a","0a","49","06","24","5c","c2","d3","ac","62","91","95","e4","79"},
            {"e7","c8","37","6d","8d","d5","4e","a9","6c","56","f4","ea","65","7a","ae","08"},
            {"ba","78","25","2e","1c","a6","b4","c6","e8","dd","74","1f","4b","bd","8b","8a"},
            {"70","3e","b5","66","48","03","f6","0e","61","35","57","b9","86","c1","1d","9e"},
            {"e1","f8","98","11","69","d9","8e","94","9b","1e","87","e9","ce","55","28","df"},
            {"8c","a1","89","0d","bf","e6","42","68","41","99","2d","0f","b0","54","bb","16"}};
        public string[,] InvSbox = new string[,] {
            {"52","09","6a","d5","30","36","a5","38","bf","40","a3","9e","81","f3","d7","fb"},
            {"7c","e3","39","82","9b","2f","ff","87","34","8e","43","44","c4","de","e9","cb"},
            {"54","7b","94","32","a6","c2","23","3d","ee","4c","95","0b","42","fa","c3","4e"},
            {"08","2e","a1","66","28","d9","24","b2","76","5b","a2","49","6d","8b","d1","25"},
            {"72","f8","f6","64","86","68","98","16","d4","a4","5c","cc","5d","65","b6","92"},
            {"6c","70","48","50","fd","ed","b9","da","5e","15","46","57","a7","8d","9d","84"},
            {"90","d8","ab","00","8c","bc","d3","0a","f7","e4","58","05","b8","b3","45","06"},
            {"d0","2c","1e","8f","ca","3f","0f","02","c1","af","bd","03","01","13","8a","6b"},
            {"3a","91","11","41","4f","67","dc","ea","97","f2","cf","ce","f0","b4","e6","73"},
            {"96","ac","74","22","e7","ad","35","85","e2","f9","37","e8","1c","75","df","6e"},
            {"47","f1","1a","71","1d","29","c5","89","6f","b7","62","0e","aa","18","be","1b"},
            {"fc","56","3e","4b","c6","d2","79","20","9a","db","c0","fe","78","cd","5a","f4"},
            {"1f","dd","a8","33","88","07","c7","31","b1","12","10","59","27","80","ec","5f"},
            {"60","51","7f","a9","19","b5","4a","0d","2d","e5","7a","9f","93","c9","9c","ef"},
            {"a0","e0","3b","4d","ae","2a","f5","b0","c8","eb","bb","3c","83","53","99","61"},
            {"17","2b","04","7e","ba","77","d6","26","e1","69","14","63","55","21","0c","7d"}};
        public string[,] MC = new string[,]{
            {"02","03", "01", "01"},
            {"01","02", "03", "01"},
            {"01","01", "02", "03"},
            {"03","01", "01", "02"}
            };
        public string[,] Inverse_MC = new string[,]{
            {"0E","0B", "0D", "09"},
            {"09","0E", "0B", "0D"},
            {"0D","09", "0E", "0B"},
            {"0B","0D", "09", "0E"}
            };
        public string[,] Rcon = new string[,]{
        {"01","02","04","08","10","20","40","80","1b","36"},
        {"00","00","00","00","00","00","00","00","00","00"},
        {"00","00","00","00","00","00","00","00","00","00"},
        {"00","00","00","00","00","00","00","00","00","00"}};
        public static string[,] Matrix(string Word)
        {
            string[,] matrix = new string[4, 4];
            int index = 2;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    matrix[j, i] = Word[index].ToString() + Word[index + 1].ToString();
                    index += 2;
                }
            }
            return matrix;
        }
        public string[] RotWord(string[] column)
        {
            string rcol;
            rcol = column[0];
            for (int i = 0; i < 3; i++)
            {
                column[i] = column[i + 1];
            }
            column[3] = rcol;
            return column;
        }
        public string[] SubBytes(string[] column)
        {
            for (int i = 0; i < 4; i++)
            {
                string copyCol = column[i];
                int ROW = (int)Convert.ToInt32(copyCol[0].ToString(), 16);
                int COL = (int)Convert.ToInt32(copyCol[1].ToString(), 16);
                column[i] = SBOX[ROW, COL];
            }
            return column;
        }
        public void KeySchedule(ref string[,] keySchedule)
        {
            for (int i = 4; i < 44; i++)
            {
                string[] c1 = new string[4];
                string[] c2 = new string[4];
                for (int k = 0; k < 4; k++)
                {
                    c1[k] = keySchedule[k, i - 1];
                    c2[k] = keySchedule[k, i - 4];
                }
                if (i % 4 == 0)
                {
                    c1 = RotWord(c1);
                    c1 = SubBytes(c1);
                    string[] RconCol = new string[4];
                    for (int j = 0; j < 4; j++)
                    {
                        RconCol[j] = Rcon[j, (i / 4) - 1];
                    }
                    for (int j = 0; j < 4; j++)
                    {
                        int n1 = Convert.ToInt32(c1[j], 16);
                        int n2 = Convert.ToInt32(c2[j], 16);
                        int n3 = Convert.ToInt32(RconCol[j], 16);
                        int result = n1 ^ n2 ^ n3;
                        keySchedule[j, i] = result.ToString("x");
                        if (keySchedule[j, i].Length == 1)
                        {
                            keySchedule[j, i] = "0" + keySchedule[j, i];
                        }
                    }
                }
                else
                {
                    for (int j = 0; j < 4; j++)
                    {
                        int n1 = Convert.ToInt32(c1[j], 16);
                        int n2 = Convert.ToInt32(c2[j], 16);
                        int result = n1 ^ n2;
                        keySchedule[j, i] = result.ToString("x");
                        if (keySchedule[j, i].Length == 1)
                        {
                            keySchedule[j, i] = "0" + keySchedule[j, i];
                        }
                    }
                }
            }
            //   return keySchedule;
        }
        public string[,] ShiftRowsRight(string[,] matrix)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < i; j++)
                {
                    string tmp = matrix[i, 3];
                    matrix[i, 3] = matrix[i, 2];
                    matrix[i, 2] = matrix[i, 1];
                    matrix[i, 1] = matrix[i, 0];
                    matrix[i, 0] = tmp;
                }
            }

            return matrix;
        }
        public string[,] SubByte(string[,] matrix)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string temp = matrix[i, j];
                    int row = Convert.ToInt32(temp[0].ToString(), 16);
                    int col = Convert.ToInt32(temp[1].ToString(), 16);
                    matrix[i, j] = InvSbox[row, col];
                }
            }
            return matrix;
        }
        public void Add_Round_Key(string[,] key_state, string[,] round_Key, int roundNO)
        {
            int index = roundNO * 4;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int n1 = Convert.ToInt32(key_state[j, i], 16);
                    int n2 = Convert.ToInt32(round_Key[j, index + i], 16);
                    int result = n1 ^ n2;
                    key_state[j, i] = result.ToString("x");
                    if (key_state[j, i].Length == 1)
                    {
                        key_state[j, i] = "0" + key_state[j, i];
                    }
                }
            }
        }
        static string XOR(string str1, string str2)
        {
            string result = null;
            if (str1 != null && str2 != null)
            {
                for (int i = 0; i < 8; i++)
                {
                    if (str1[i] == str2[i])
                    {
                        result += '0';
                    }
                    else
                    {
                        result += '1';
                    }
                }
            }
            return result;
        }
        static string Shift_1B(string str)
        {
            if (str[0] == '0')
            {
                return str.Remove(0, 1) + "0";
            }
            else
            {
                return XOR((str.Remove(0, 1) + "0"), HexToBinary("1B"));
            }
        }
        private string[,] InvMixColumns(string[,] cipherMatrix)
        {
            string[,] Output = { { "", "", "", "" }, { "", "", "", "" }, { "", "", "", "" }, { "", "", "", "" } };
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        string bit = HexToBinary(cipherMatrix[k, j]);
                        string res = "";
                        if (Inverse_MC[i, k] == "09")
                        {
                            res = XOR(Shift_1B(Shift_1B(Shift_1B(bit))), bit);
                        }
                        else if (Inverse_MC[i, k] == "0B")
                        {
                            res = XOR(Shift_1B(XOR(Shift_1B(Shift_1B(bit)), bit)), bit);
                        }
                        else if (Inverse_MC[i, k] == "0D")
                        {
                            res = XOR(Shift_1B(Shift_1B(XOR(Shift_1B(bit), bit))), bit);
                        }
                        else if (Inverse_MC[i, k] == "0E")
                        {
                            res = Shift_1B(XOR(Shift_1B(XOR(Shift_1B(bit), bit)), bit));
                        }
                        Output[i, j] = XOR(Output[i, j].PadLeft(8, '0'), res);
                        if (k == 3)
                        {
                            Output[i, j] = BinaryToHex(Output[i, j]).PadLeft(2, '0').ToUpper();
                        }
                    }
                }
            }
            return Output;
        }
        public override string Decrypt(string cipherText, string key)
        {
            string[,] KeyToMatrix = Matrix(key);
            string[,] keySchedule = new string[4, 44];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    keySchedule[j, i] = KeyToMatrix[j, i];
                }
            }
            KeySchedule(ref keySchedule);
            string[,] cipherToMatrix = Matrix(cipherText);
            Add_Round_Key(cipherToMatrix, keySchedule, 10);
            for (int i = 10; i > 0; i--)
            {
                cipherToMatrix = ShiftRowsRight(cipherToMatrix);
                cipherToMatrix = SubByte(cipherToMatrix);
                Add_Round_Key(cipherToMatrix, keySchedule, i - 1);
                if (i != 1)
                {
                    cipherToMatrix = InvMixColumns(cipherToMatrix);
                }
            }
            string result = "0x";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result += cipherToMatrix[j, i];
                }
            }
            return result;
            // throw new NotImplementedException();
        }
        public override string Encrypt(string plainText, string key)
        {
            string[,] PT = new string[4, 4];
            string[,] k = new string[4, 4];
            int index = 2; // to remove 0x
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    PT[j, i] = (plainText[index].ToString() + plainText[index + 1].ToString());
                    k[j, i] = (key[index].ToString() + key[index + 1].ToString());
                    index += 2;
                }
            }
            //Round 0
            PT = XOR2Matrix(PT, k);
            //Round for 9 times
            string[,] tempk = new string[4, 4];
            for (int i = 1; i <= 9; i++)
            {
                PT = SubBytes(PT);
                PT = ShiftRows(PT);
                PT = MixColumns(PT);
                tempk = GetKeyOfCurrentRound(k, i - 1);
                for (int d = 0; d < 4; d++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        k[d, j] = tempk[d, j];
                    }
                }
                PT = XOR2Matrix(tempk, PT);
            }
            //last Round
            PT = XOR2Matrix(GetKeyOfCurrentRound(k, 9), ShiftRows(SubBytes(PT)));
            string cipherText = "";

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    cipherText += PT[j, i];
                }
            }
            return "0x" + cipherText;
        }
        public string[,] SubBytes(string[,] plainText)
        {

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string tmp = plainText[i, j];
                    int left = int.Parse(tmp[0].ToString(), System.Globalization.NumberStyles.HexNumber);   //split cell
                    int right = int.Parse(tmp[1].ToString(), System.Globalization.NumberStyles.HexNumber); // how to convert from hex to int
                    plainText[i, j] = SBOX[left, right];
                }
            }
            return plainText;
        }
        public string[,] ShiftRows(string[,] plainText)
        {
            for (int i = 1; i < 4; i++) // Start from row 1 since first row does not need shifting
            {
                List<string> row = new List<string>(4);
                for (int j = 0; j < 4; j++)
                {
                    row.Add(plainText[i, j]);
                }

                // a,b,c,d         i=2
                row.AddRange(row.GetRange(0, i)); //append first two elements to end of the list==>a,b,c,d,a,b 
                row.RemoveRange(0, i); // remove first two elements from the start of the list==> c,d,a,b
                for (int j = 0; j < 4; j++)
                {
                    plainText[i, j] = row[j]; // Update the characters in the row
                }
            }
            return plainText;
        }
        public static string HexToBinary(string hexa)
        {
            hexa = hexa.ToUpper(); // Convert all characters to upper case 
            Dictionary<char, string> data = new Dictionary<char, string>()
            {
                {'0', "0000"},
                {'1', "0001"},
                {'2', "0010"},
                {'3', "0011"},
                {'4', "0100"},
                {'5', "0101"},
                {'6', "0110"},
                {'7', "0111"},
                {'8', "1000"},
                {'9', "1001"},
                {'A', "1010"},
                {'B', "1011"},
                {'C', "1100"},
                {'D', "1101"},
                {'E', "1110"},
                {'F', "1111"}
            };

            return data[hexa[0]] + data[hexa[1]];
        }
        public static string BinaryToHex(string binary)
        {
            Dictionary<string, string> data = new Dictionary<string, string>()
            {
                { "0000", "0" },
                { "0001", "1" },
                { "0010", "2" },
                { "0011", "3" },
                { "0100", "4" },
                { "0101", "5" },
                { "0110", "6" },
                { "0111", "7" },
                { "1000", "8" },
                { "1001", "9" },
                { "1010", "A" },
                { "1011", "B" },
                { "1100", "C" },
                { "1101", "D" },
                { "1110", "E" },
                { "1111", "F" },
            };
            return (data[binary.Substring(0, 4)] + data[binary.Substring(4, 4)]);
        }
        public static string MultiplyTwoElements(string s1, string s2)
        {   //02
            s1 = s1.ToUpper();
            //D4
            s2 = s2.ToUpper();
            string result1 = HexToBinary(s1);
            string result2 = HexToBinary(s2);
            // convert from string to binary
            int firstNumber = Convert.ToInt32(result1, 2);
            int secoundNumber = Convert.ToInt32(result2, 2);
            // GF
            if (s1 == "03")
            {
                int ans2 = secoundNumber * 2;
                ans2 ^= secoundNumber; //XOR
                string binary2 = Convert.ToString(ans2, 2);
                return binary2;
            }
            int ans = firstNumber * secoundNumber;
            string binary = Convert.ToString(ans, 2);
            return binary;
        }
        // XOR if (binary.Length > 8) with 1b
        public static string XOR(string s1, string s2, string s3, string s4)
        {
            int ans = (Convert.ToInt32(s1, 2) ^ Convert.ToInt32(s2, 2) ^ Convert.ToInt32(s3, 2) ^ Convert.ToInt32(s4, 2));
            string binary = Convert.ToString(ans, 2);

            int _1b = 283;
            if (binary.Length > 8)
            {
                ans ^= _1b;
            }

            binary = Convert.ToString(ans, 2);
            string leadingZeros = "";

            for (int i = 0; i < 8 - binary.Length; i++)
                leadingZeros += '0';

            return (leadingZeros + binary);
        }
        public string[,] MixColumns(string[,] plainText)
        {
            string[,] result = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string[] PlainTextAfterMultiply = new string[4];
                    for (int k = 0; k < 4; k++)
                    {
                        // 4  columns
                        PlainTextAfterMultiply[k] = MultiplyTwoElements(MC[i, k], plainText[k, j]);
                    }
                    result[i, j] = BinaryToHex(XOR(PlainTextAfterMultiply[0], PlainTextAfterMultiply[1], PlainTextAfterMultiply[2], PlainTextAfterMultiply[3]));
                }
            }
            return result;
        }
        // logical XOR
        public string xor(string a, string b)
        {
            string result = "";
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] == b[i])
                    result += '0';
                else
                    result += '1';
            }
            return result;
        }
        public string[,] GetKeyOfCurrentRound(string[,] lastKey, int roundNumber)
        {
            string[] F_column = new string[4];
            string[] C1 = new string[4];

            //Get first column and last column
            for (int i = 0; i < 4; i++)
            {
                F_column[i] = lastKey[i, 3];
                C1[i] = lastKey[i, 0];
            }
            //rotate it
            string tmp = F_column[0];
            for (int i = 1; i < 4; i++)
                F_column[i - 1] = F_column[i];
            F_column[3] = tmp;
            //subBites
            for (int i = 0; i < 4; i++)
            {
                int right = int.Parse(F_column[i][0].ToString(), System.Globalization.NumberStyles.HexNumber);
                int left = int.Parse(F_column[i][1].ToString(), System.Globalization.NumberStyles.HexNumber);
                F_column[i] = SBOX[right, left];
            }
            //xor between 3 columns
            int con = roundNumber;

            string[] C2 = new string[4];
            for (int i = 0; i < 4; i++)
            {
                C2[i] = Rcon[i, con];
            }
            for (int i = 0; i < 4; i++)
            {
                C1[i] = BinaryToHex(xor(HexToBinary(C1[i]), HexToBinary(C2[i])));
            }
            string[,] roundKey = new string[4, 4];
            //fill first column
            for (int i = 0; i < 4; i++)
            {
                roundKey[i, 0] = BinaryToHex(xor(HexToBinary(C1[i]), HexToBinary(F_column[i])));
            }
            //fill all columns in new key
            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    roundKey[j, i] = BinaryToHex(xor(HexToBinary(lastKey[j, i]), HexToBinary(roundKey[j, i - 1])));
                }
            }
            return roundKey;
        }
        // XOR 2 Matrix
        string[,] XOR2Matrix(string[,] a, string[,] b)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    a[i, j] = BinaryToHex(xor(HexToBinary(a[i, j]), HexToBinary(b[i, j])));
                }
            }
            return a;
        }
    }
}
