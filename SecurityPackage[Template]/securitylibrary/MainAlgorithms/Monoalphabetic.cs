using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
                                 // custumer        // 8 letters

        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            char[] alphabetic = "abcdefghijklmnopqrstuvwxyz".ToCharArray();
           
            Dictionary<char, char> keysFound = new Dictionary<char, char>();

            string keysNotFound = "";

            if (plainText.Length == cipherText.Length)
            {
                for (int i = 0; i < plainText.Length; i++)
                {
                    if(!keysFound.ContainsKey(plainText[i]))
                    {
                        keysFound.Add(plainText[i], cipherText[i]);                      // key     ==>         // defghijklmnopqrstuvwxyzabc
                    }
                }                // m  e  t  a  f  r  h  o  g  p  y  ==> plain
            }                   //  p  h  w  d  i  u  k  r  j  s  b  ==> cipher
            
            foreach (char c in alphabetic)
            {
                if(!keysFound.ContainsValue(c))
                {
                    keysNotFound += c;
                }
            }


            /*                  //  b  c  d   
            string mainPlain = "meetmeafterthetogaparty";
            string mainCipher ="phhwphdiwhuwkhwrjdsduwb".ToUpper();
            string mainKey = "defghijklmnopqrstuvwxyzabc";
            */              //abcdefghijklmnopqrstuvwxyz
                            //d$$$hijk$$$$p$rs$u$w$$$$b$   ==> acefglmnoq


                            
            string Key = "";
            int count = 0;

            foreach (char c in alphabetic)           // value   ==>      //  ABCDEFGHIJKLMNOPQRSTUVWXYZ
            {
                if(keysFound.ContainsKey(c))          // key ==> de
                {
                    Key += keysFound[c];
                }
                else
                {
                    Key += keysNotFound[count];
                    count++;
                }
            }

            return Key;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();

            string plainText = "";
            //char[] keyAsChars = key.ToLower().ToCharArray();
            char[] alphabetic = "abcdefghijklmnopqrstuvwxyz".ToCharArray();

            Dictionary<char, char> keys = new Dictionary<char, char>();

            for (int i = 0; i < 26; i++)
            {
                keys.Add(key[i], alphabetic[i]);                                // key            // defghijklmnopqrstuvwxyzabc
            }

            foreach (char c in cipherText.ToLower().ToCharArray())               // value         //  ABCDEFGHIJKLMNOPQRSTUVWXYZ
            {
                plainText += keys[c];
            }

            return plainText;

        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();

            /*                  
            string mainPlain = "meetmeafterthetogaparty";
            string mainCipher ="phhwphdiwhuwkhwrjdsduwb".ToUpper();
            string mainKey = "defghijklmnopqrstuvwxyzabc";
            */


            string cipherText = "";
            //char[] keyAsChars = key.ToCharArray();
            char[] alphabetic = "abcdefghijklmnopqrstuvwxyz".ToCharArray();

            Dictionary<char,char> keys = new Dictionary<char, char>();

            for(int i = 0; i < 26; i++)
            {
                keys.Add(alphabetic[i], key[i]);
            }

            foreach (char c in plainText.ToCharArray())                   // value    ==>      // defghijklmnopqrstuvwxyzabc
            {
                cipherText += keys[c];                                   // key       ==>      //  ABCDEFGHIJKLMNOPQRSTUVWXYZ
            }

            return cipherText.ToUpper();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            //throw new NotImplementedException();
           
            cipher = cipher.ToUpper();

            Dictionary<char, int> OrderedCount = new Dictionary<char, int>();

            foreach(char c in cipher.ToCharArray())     // count  freq. of each char in cipherText 
            {
                if(OrderedCount.ContainsKey(c))
                {
                    OrderedCount[c] += 1;        // exist char
                }
                else
                {
                    OrderedCount[c] = 1;        // new char
                }
            }

            return GetPlanText(GetOrderedDictionary(OrderedCount), cipher);
        }

        // Sort Dictionary by value with Descending order
        public Dictionary<char, int> GetOrderedDictionary(Dictionary<char, int> Dict)
        {
            return Dict.OrderByDescending(i => i.Value).ToDictionary(i => i.Key, i => i.Value);
        }

        public string GetPlanText( Dictionary<char, int> Dict, string cipher)
        {
            string plainText = cipher;

            string RelativeFreqLetters = "etaoinsrhldcumfpgwybvkxjqz";

            for (int i = 0; i < Dict.Count; i++)    // Generate plainText by replace each char in chipherText by corresponding Freq. Letter

            {
                plainText = plainText.Replace(Char.ToUpper(Dict.ElementAt(i).Key), RelativeFreqLetters[i]);
            }

            return plainText;
        }
    }
}