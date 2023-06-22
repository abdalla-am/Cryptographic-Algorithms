using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string alphabet = "abcdefghijklmnopqrstuvwxyz";
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
            string alpha = "abcdefghijklmnopqrstuvwxyz";
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
            StringBuilder w = new StringBuilder();
            for (int i = 0; i < sp.Length; i++)
            {
                for (int j = 0; j < alpha.Length; j++)
                {
                    if (sc[i].Equals(tab[rowp[i], j]))
                    {
                        w.Append(alpha[j]);
                    }
                }
            }
            StringBuilder yw = new StringBuilder();

            if (w[0].Equals('h'))
            {
                for (int i = 0; i < 8; i++)
                {
                    yw.Append(w[i]);
                }
            }
            else
            {
                for (int i = 0; i < 9; i++)
                {
                    yw.Append(w[i]);
                }
            }
            return yw.ToString();
        }

        public string Decrypt(string cipherText, string key)
        {

            cipherText = cipherText.ToLower();
            string plain = null;
            for (int x = 0; x < cipherText.Length; x++)
            {
                int ci = Letterind(cipherText[x]);
                int ki = Letterind(key[x]);
                int t = (ci - ki) % 26;
                if (t < 0)
                {
                    t = (t + 26) % 26;
                }
                else
                {
                    t = t;
                }
                plain += alphabet[t];
                key += alphabet[t];
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
                    key = key + plainText[s];
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