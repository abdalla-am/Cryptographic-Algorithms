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
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            // throw new NotImplementedException();
            int ModPow(int a1, int a2, int a3)
            {

                int res = 1;

                while (a2 > 0)

                {

                    if (a2 % 2 == 1)

                        res = (res * a1) % a3;

                    a1 = (a1 * a1) % a3;

                    a2 /= 2;
                }


                return res;

            }


            long c = ModPow(alpha, k, q);

            long c1 = (m * ModPow(y, k, q)) % q;



            List<long> cipher = new List<long>();

            cipher.Add(c);

            cipher.Add(c1);

            return cipher;

        }



        public int Decrypt(int c1, int c2, int x, int q)
        {
            int k = ModPow(c1, x, q);
            int kInverse = GetMultiplicativeInverse(k, q);
            int decryptedMessage = (c2 * kInverse) % q;

            return decryptedMessage;
            int ModPow(int a1, int a2, int a3)
            {

                int res = 1;

                while (a2 > 0)

                {

                    if (a2 % 2 == 1)

                        res = (res * a1) % a3;

                    a1 = (a1 * a1) % a3;

                    a2 /= 2;
                }


                return res;

            }
            int GetMultiplicativeInverse(int number, int baseN)
            {

                int z = number;
                int y = baseN;
                int S0 = 1, S1 = 0, T0 = 0, T1 = 1;
                do
                {
                    int q1 = z / y;
                    int r = z % y;
                    z = y;
                    y = r;

                    int S2 = S0 - q1 * S1;
                    S0 = S1;
                    S1 = S2;

                    int t2 = T0 - q1 * T1;
                    T0 = T1;
                    T1 = t2;
                } while (y != 0);

                if (z != 1)
                {
                    return -1;
                }
                else
                {
                    return (S0 % baseN + baseN) % baseN;
                }
            }

        }
    }
}