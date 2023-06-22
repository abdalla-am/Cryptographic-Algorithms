using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {

        int powerFunction(int number, int power, int modulas)
        {
            if (power == 0)
            {
                return 1;
            }
            int temp = powerFunction(number, power / 2, modulas);
            if (power % 2 == 0)
            {
                return (temp * temp) % modulas;
            }
            else
            {
                return (((temp * temp) % modulas) * number) % modulas;
            }
        }

        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {






            //PUBLIC KEYS :

            int Ya = powerFunction(alpha, xa, q);
            int Yb = powerFunction(alpha, xb, q);


            // PRIVATE KEYS :

            int K1 = powerFunction(Ya, xb, q);
            int K2 = powerFunction(Yb, xa, q);

            List<int> result = new List<int>();
            result.Add(K1);
            result.Add(K2);
            return result;
        }
    }
}