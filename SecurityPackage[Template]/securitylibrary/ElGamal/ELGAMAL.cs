using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        /// 
        public long Power(int n, int pow, int mod)
        {
            long ans = n;

            for (int i = 2; i <= pow; i++)
            {
                ans *= (n);
                ans %= mod;
            }
            return ans;

        }
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            List<long> CipherT = new List<long>();

            long Key = Power(y, k, q);
            long C1 = Power(alpha, k, q);
            long C2 = (Key * m) % q;
            CipherT.Add(C1);
            CipherT.Add(C2);
            return CipherT;
            //throw new NotImplementedException();

        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            int K = c1 % q;
            for (int i = 1; i < x; i++)
            {
                K = (K * c1) % q;
            }
            //ECLUDIAN
            int Inverse = 0;
            for (int i = 0; i < q; i++)
            {
                int check = (K * i) % q;
                if (check == 1)
                {
                    Inverse = i;
                }
            }
            int M = (c2 * Inverse) % q;
            return M;
            // throw new NotImplementedException();
        }
    }
}
