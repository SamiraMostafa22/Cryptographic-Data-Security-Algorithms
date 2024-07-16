using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            char[] alphabets = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };

            List<string> list = new List<string>();
            for (int i = 0; i < plainText.Length; i++)
            {
                int index = Array.IndexOf(alphabets, plainText[i]);
                int myIndex = (key + index) % 26;
                string newLetter = alphabets[myIndex].ToString();
                list.Add(newLetter);

            }

            string enc = String.Join("", list);
            return enc;
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            // throw new NotImplementedException();
            char[] alphabets2 = new char[]
            {
                'a', 'b', 'c', 'd', 'e', 'f', 'g',
                'h', 'i', 'j', 'k', 'l', 'm', 'n',
                'o', 'p', 'q', 'r', 's', 't', 'u',
                'v', 'w', 'x', 'y', 'z'
            };

            List<string> list2 = new List<string>();
            for (int i = 0; i < cipherText.Length; i++)
            {

                int index_of_cipher = Array.IndexOf(alphabets2, cipherText[i]);
                int newIndex2 = (index_of_cipher - key) % 26;
                if (newIndex2 < 0)
                {
                    newIndex2 += 26;
                }
                string chaar2 = alphabets2[newIndex2].ToString();
                list2.Add(chaar2);

            }

            string dec = String.Join("", list2);
            return dec;

        }


        public int Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            //throw new NotImplementedException();
            char[] alphabets = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            int mykey = 0;

            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < cipherText.Length; j++)
                {
                    int index1 = Array.IndexOf(alphabets, plainText[i]);
                    int index2 = Array.IndexOf(alphabets, cipherText[i]);


                    mykey = index2 - index1;
                    if (mykey < 0)

                    {
                        mykey += 26;

                    }

                    break;
                }
            }


            return mykey;

        }
    }
}