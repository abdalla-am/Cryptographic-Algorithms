using System;
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
            int x = number;
            int y = baseN;
            int S0 = 1, S1 = 0, T0 = 0, T1 = 1;
            do
            {
                int q = x / y;
                int r = x % y;
                x = y;
                y = r;

                int S2 = S0 - q * S1;
                S0 = S1;
                S1 = S2;

                int t2 = T0 - q * T1;
                T0 = T1;
                T1 = t2;
            } while (y != 0);

            if (x != 1)
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
