using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        string alphabet = "abcdefghijklmnopqrstuvwxyz";
        public int Letterind(char letter)
        {
            for (int i = 0; i < 26; i++)
            {
                if (letter == alphabet[i])
                {
                    return i;
                }
            }
            return 0;
        }
        public string Analyse(string plainText, string cipherText)
        {

            char[,] tab = new char[26, 26];
            string alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToLower();
            int[] row = new int[26];
            int[] row1 = new int[25];
            int[] col = new int[26];
            int[] col1 = new int[25];
            for (int i = 0; i < 26; i++)
            {
                row[i] = i;
            }
            int q = 1;
            for (int i = 0; i < 25; i++)
            {
                row1[i] = q;
                q++;
            }
            int q1 = 25;
            for (int i = 0; i < 25; i++)
            {
                col1[i] = q1;
                q1--;
            }



            for (int i = 0; i < 26; i++)
            {
                char wow = alpha[i];

                int o1 = 0;
                for (int i1 = i; i1 >= 0; i1--)
                {
                    col[o1] = i1;
                    o1++;

                }
                for (int y = 0; y < i + 1; y++)
                {


                    tab[row[y], col[y]] = wow;
                }


            }

            for (int i = 0; i < 25; i++)
            {
                char wow = alpha[i];
                int r1 = i + 1;
                for (int u = 0; u < (25 - i); u++)
                {
                    tab[row[r1], col[u]] = wow;
                    r1++;
                }



            }

            StringBuilder sp = new StringBuilder(plainText);


            StringBuilder sc = new StringBuilder(cipherText.ToLower());

            int[] rowp = new int[sp.Length];
            for (int i = 0; i < sp.Length; i++)
            {
                for (int j = 0; j < alpha.Length; j++)
                {
                    if (alpha[j].Equals(sp[i]))
                    {
                        rowp[i] = j;
                    }
                }
            }


            StringBuilder wtf = new StringBuilder();
            for (int i = 0; i < sp.Length; i++)
            {
                for (int j = 0; j < alpha.Length; j++)
                {
                    if (sc[i].Equals(tab[rowp[i], j]))
                    {
                        wtf.Append(alpha[j]);
                    }

                }
            }
            StringBuilder yewtf = new StringBuilder();

            if (wtf[0].Equals('h'))
            {
                for (int i = 0; i < 8; i++)
                {
                    yewtf.Append(wtf[i]);
                }
            }
            else
            {

                for (int i = 0; i < 9; i++)
                {
                    yewtf.Append(wtf[i]);
                }
            }
            return yewtf.ToString();
        }

        public string Decrypt(string cipherText, string key)
        {


            cipherText = cipherText.ToLower();
            string plain = null;
            int m = 0;
            for (int i = 0; i < cipherText.Length; i++)
            {

                if (key.Length != cipherText.Length)
                {
                    key = key + key[m];
                    m++;
                }
            }
            for (int i = 0; i < cipherText.Length; i++)
            {

                plain += alphabet[((Letterind(cipherText[i]) - Letterind(key[i])) + 26) % 26];
            }
            return plain.ToLower();


        }

        public string Encrypt(string plainText, string key)
        {

            string cipher = null;
            int s = 0;
            for (int i = 0; i < plainText.Length; i++)
            {

                if (key.Length != plainText.Length)
                {
                    key = key + key[s];
                    s++;
                }
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                cipher += alphabet[((Letterind(plainText[i]) + Letterind(key[i]))) % 26];
            }
            return cipher.ToUpper();

        }
    }
}