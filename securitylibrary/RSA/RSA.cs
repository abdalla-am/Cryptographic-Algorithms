using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {

            int l;
            l = p * q;
            int z;
            z = Mod_Power(M, e, l);
            return z;
        }

        public int Decrypt(int p, int q, int C, int e)
        {

            int a;
            a = p * q;
            int jj;
            jj = (p - 1) * (q - 1);
            int r;
            r = Appear_D(e, jj);
            int M;
            M = Mod_Power(C, r, a);
            return M;
        }

        public int Mod_Power(int baseValue, int exponent, int modulus)
        {

            int result = 1;

            while (exponent > 0)
            {

                if ((exponent & 1) == 1)
                {

                    result = (int)(((long)result * baseValue) % modulus);

                }
                baseValue = (int)(((long)baseValue * baseValue) % modulus);
                exponent >>= 1;

            }

            return result;
        }

        public int Appear_D(int q, int p)
        {
            int h = 1;

            while (true)
            {

                if ((q * h) % p == 1)
                {

                    return h;

                }

                h++;
            }
        }

    }
}