using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public int GenerateKey(int number, int power, int q)
        {
            
            int result = 1;
            int count = 0;
            
            while (count <= power - 1)
            {
                result = (result * number) % q;
                count++;
            }
            return result;
            
        }
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            List<int> keys = new List<int>(2);
            int ya, yb, KeyA, KeyB;

            ya = GenerateKey(alpha, xa, q); // public key of A
            yb = GenerateKey(alpha, xb, q); // public key of B
            KeyA = GenerateKey(yb, xa, q);  // private key of A
            KeyB = GenerateKey(ya, xb, q);   // private key of B
            
            keys.Add((int)KeyA);

            keys.Add((int)KeyB);

            return keys;
        }
    }
}