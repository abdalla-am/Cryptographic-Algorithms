using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {

        public List<int> Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            char[,] arr = new char[100, 100];
            char f = cipherText[0];
            char s = cipherText[1];
            int n = 0;
            int i = 2;
            int res = 0;
            int len_key = 0;
            while (i < 1000)
            {
                for (int a = 0; a < 3; a++)
                {
                    for (int b = 0; b < i; b++)
                    {
                        if (n < plainText.Length)
                        {
                            arr[a, b] = plainText[n];
                            n++;
                        }
                    }
                }


                for (int r = 0; r < i; r++)
                {
                    if (arr[0, r] == f)
                    {
                        if (arr[1, r] == s)
                        {
                            res = 1;
                            break;
                        }

                    }
                }

                if (res == 1)
                {
                    len_key = i;
                    break;
                }
                else
                {
                    n = 0;
                    i++;
                }

            }

            ////////////////////////////////////////////////////////////////////////////////////////////////
            int result = 1;
            int conter = 0;
            int[] arrr = new int[35];
            for (int a = 0; a < len_key; a++)
            {
                for (int g = 0; g < cipherText.Length; g++)
                {
                    if (arr[0, a] != cipherText[g] || arr[1, a] != cipherText[g + 1] ||
                        arr[2, a] != cipherText[g + 2])
                    {
                        result++;
                    }
                    else
                    {
                        arrr[conter] = result;
                        result = 1;
                        conter++;
                        break;
                    }
                }
            }

            int c_r_f = 1;
            List<int> L = new List<int>();

            for (int q = 0; q < len_key; q++)
            {
                for (int e = 0; e < len_key; e++)
                {
                    if (arrr[q] > arrr[e])
                    {
                        c_r_f++;
                    }
                }
                L.Add(c_r_f);

                c_r_f = 1;
            }
            return L;

        }

        public string Decrypt(string cipherText, List<int> key)
        {
            string cipher_text = cipherText;
            int key_count = key.Count;

            int row = cipher_text.Length / key_count;
            int col = key_count;

            char[,] arr = new char[row, col];
            char[] arr1 = new char[cipher_text.Length];
            int y = 1;
            int c = 0;
            for (int i = 0; i < col; i++)
            {
                while (key[i] == y)
                {
                    for (int j = 0; j < row; j++)
                    {


                        arr[j, i] = cipher_text[c];
                        c++;
                    }
                    y++;
                    i = 0;
                }

            }
            int n = 0;

            for (int i = 0; i < row; i++)
            {

                for (int j = 0; j < col; j++)
                {
                    if (n < cipher_text.Length)
                    {
                        arr1[n] = arr[i, j];
                        n++;
                    }
                }
            }

            string dec = new string(arr1);
            StringBuilder plain_text = new StringBuilder(dec);

            for (int i = 0; i < arr1.Length; i++)
            {
                plain_text[i] = arr1[i];
            }

            return plain_text.ToString().ToUpper();

        }

        public string Encrypt(string plainText, List<int> key)
        {
            string plain_text = plainText;
            int key_count = key.Count;
            int r = plain_text.Length + key_count;
            int h = r - (r % key_count);
            int x = (h - plain_text.Length) % key_count;
            if (plain_text.Length % key_count != 0)
            {

                for (int i = 0; i < x; i++)
                {
                    plain_text = plain_text + 'x';

                }

            }
            char[,] mat = new char[plain_text.Length / key_count, key_count];
            int n = 0;
            for (int i = 0; i < plain_text.Length / key_count; i++)
            {

                for (int j = 0; j < key_count; j++)
                {

                    mat[i, j] = plain_text[n];
                    n++;
                }
            }

            char[] arr1 = new char[plain_text.Length];
            int y = 1;
            int c = 0;
            for (int i = 0; i < key_count; i++)
            {
                while (key[i] == y)
                {
                    for (int j = 0; j < plain_text.Length / key_count; j++)
                    {


                        arr1[c] = mat[j, i];
                        c++;
                    }
                    y++;
                    i = 0;
                }

            }

            string dec = new string(arr1);
            StringBuilder cipher_text = new StringBuilder(dec);

            for (int i = 0; i < arr1.Length - x; i++)
            {
                cipher_text[i] = arr1[i];
            }



            for (int i = 0; i < cipher_text.Length; i++)
            {
                if (cipher_text[i] == 'x' && x > 0)
                {
                    cipher_text.Remove(i, 1);
                    x--;
                }
            }
            return cipher_text.ToString().ToUpper();

        }
    }
}