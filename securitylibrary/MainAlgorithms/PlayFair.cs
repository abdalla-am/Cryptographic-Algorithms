using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {

        public string Decrypt(string cipherText, string key)
        {

            key = key.ToLower();
            cipherText = cipherText.ToLower();
            int bb = 0;
            for (int i = 0; i < cipherText.Length - 1; i++)
            {
                if (cipherText[i] == 'j')
                {
                    bb = 1;
                    break;
                }
            }
            string uniq1 = new String(key.Distinct().ToArray());
            string alpha = "abcDEFGHIJKLMNOPQRSTUVWXYZ";
            string ralpha = alpha.ToLower();
            char[] n = new char[26];

            for (int i = 0; i < alpha.Length; i++)
            {
                int l = 0;
                for (int j = 0; j < uniq1.Length; j++)
                {
                    if (ralpha[i].Equals(uniq1[j]))
                    {
                        l++;

                    }


                }
                if (l == 0)
                {
                    n[i] = ralpha[i];
                }
                else
                {
                    n[i] = ' ';
                }

            }


            StringBuilder sb = new StringBuilder();
            string all = String.Concat(n.Where(c => !Char.IsWhiteSpace(c)));
            sb.Append(uniq1);
            sb.Append(all);
            int ii = 0;
            int ij = 0;
            for (int i = 0; i < sb.Length; i++)
            {
                if (sb[i].Equals('i'))
                {
                    ii = i;
                }
                if (sb[i].Equals('j'))
                {
                    ij = i;
                }
            }
            if (ii < ij)
            {
                sb.Remove(ij, 1);
            }
            else
                sb.Remove(ii, 1);
            char[,] mat = new char[5, 5];
            int o = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    mat[i, j] = sb[o];
                    o++;
                }
            }

            if (bb == 1)
            {


                for (int i = 0; i < 5; i++)
                {

                    for (int j = 0; j < 5; j++)
                    {

                        if (mat[i, j] == 'i')
                        {

                            mat[i, j] = 'j';
                        }

                    }

                }

            }

            int x1, y1, x2, y2;
            cipherText = cipherText.ToLower();
            char[] arr = new char[cipherText.Length + 3];
            for (int i = 0; i < cipherText.Length - 1; i += 2)
            {

                for (int x = 0; x < 5; x++)
                {

                    for (int y = 0; y < 5; y++)
                    {

                        if (cipherText[i] == mat[x, y])
                        {
                            x1 = x;
                            y1 = y;



                            for (int a = 0; a < 5; a++)
                            {
                                for (int b = 0; b < 5; b++)
                                {
                                    if (cipherText[i + 1] == mat[a, b])
                                    {

                                        x2 = a;
                                        y2 = b;
                                        if (x1 == x2)
                                        {
                                            if (y1 == 0)
                                                y1 = 5;
                                            else if (y2 == 0)
                                                y2 = 5;
                                            arr[i] = mat[x1, y1 - 1];
                                            arr[i + 1] = mat[x1, y2 - 1];
                                        }
                                        else if (y1 == y2)
                                        {
                                            if (x1 == 0)
                                                x1 = 5;
                                            else if (x2 == 0)
                                                x2 = 5;
                                            arr[i] = mat[x1 - 1, y1];
                                            arr[i + 1] = mat[x2 - 1, y1];
                                        }

                                        else
                                        {
                                            arr[i] = mat[x1, y2];
                                            arr[i + 1] = mat[x2, y1];
                                        }
                                    }


                                }


                            }
                        }


                    }


                }

            }

            string dec = new string(arr);
            dec = dec.ToLower();

            StringBuilder s1 = new StringBuilder(dec);
            char[] arr1 = new char[cipherText.Length + 3];
            int ff = 0;
            int u = 0;

            for (int i = 0; i < s1.Length - 2; i++)
            {

                if (s1[i] == 'x' && i % 2 != 0 && s1[i + 1] == s1[i - 1])
                {
                    ff++;
                    continue;
                }
                else
                {
                    arr1[u] = s1[i];
                    u++;
                }

            }

            for (int i = 0; i < arr1.Length; i++)
            {
                s1[i] = arr1[i];
            }

            if (cipherText.Length % 2 == 0 && s1[cipherText.Length - (1 + ff)] == 'x')
            {
                s1.Remove(cipherText.Length - (1 + ff), 1);
            }
            return s1.ToString();

        }

        public string Encrypt(string plainText, string key)
        {
            string uniq1 = new String(key.Distinct().ToArray());

            string alpha = "abcDEFGHIJKLMNOPQRSTUVWXYZ";
            string ralpha = alpha.ToLower();
            char[] n = new char[26];

            for (int i = 0; i < alpha.Length; i++)
            {
                int l = 0;
                for (int j = 0; j < uniq1.Length; j++)
                {
                    if (ralpha[i].Equals(uniq1[j]))
                    {
                        l++;

                    }


                }
                if (l == 0)
                {
                    n[i] = ralpha[i];
                }
                else
                {
                    n[i] = ' ';
                }

            }


            StringBuilder sb = new StringBuilder();
            string all = String.Concat(n.Where(c => !Char.IsWhiteSpace(c)));
            sb.Append(uniq1);
            sb.Append(all);
            int ii = 0;
            int ij = 0;
            for (int i = 0; i < sb.Length; i++)
            {
                if (sb[i].Equals('i'))
                {
                    ii = i;
                }
                if (sb[i].Equals('j'))
                {
                    ij = i;
                }
            }
            if (ii < ij)
            {
                sb.Remove(ij, 1);
            }
            else
                sb.Remove(ii, 1);


            char[,] mat = new char[5, 5];
            int o = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    mat[i, j] = sb[o];
                    o++;
                }
            }



            StringBuilder s1 = new StringBuilder(plainText);
            for (int i = 0; i < s1.Length - 1; i += 2)
            {
                if (s1[i].Equals(s1[i + 1]))
                {
                    s1.Insert(i + 1, 'x');
                }
            }

            if (s1.Length % 2 != 0)
            {
                s1.Append('x');
            }

            Console.WriteLine(s1);

            int[,] ind = new int[s1.Length, 2];
            int d = 0;
            for (int i = 0; i < s1.Length; i++)
            {
                for (int i1 = 0; i1 < 5; i1++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (mat[i1, j].Equals(s1[i]))
                        {

                            ind[d, 0] = i1;
                            ind[d, 1] = j;
                            d++;
                        }

                    }
                }
            }

            StringBuilder sc = new StringBuilder();
            for (int i = 0; i < s1.Length - 1; i = i + 2)
            {
                if (ind[i, 0] == ind[i + 1, 0])
                {
                    int x = ind[i, 0];
                    if (ind[i, 1] == 4)
                    {
                        sc.Append(mat[x, 0]);
                        sc.Append(mat[x, ind[i + 1, 1] + 1]);
                    }
                    else if (ind[i + 1, 1] == 4)
                    {
                        sc.Append(mat[x, ind[i, 1] + 1]);
                        sc.Append(mat[x, 0]);

                    }
                    else
                    {
                        sc.Append(mat[x, ind[i, 1] + 1]);
                        sc.Append(mat[x, ind[i + 1, 1] + 1]);


                    }
                }
                else if (ind[i, 1] == ind[i + 1, 1])
                {
                    int y = ind[i, 1];
                    if (ind[i, 0] == 4)
                    {

                        sc.Append(mat[0, y]);
                        sc.Append(mat[ind[i + 1, 0] + 1, y]);
                    }
                    else if (ind[i + 1, 0] == 4)
                    {
                        sc.Append(mat[ind[i, 0] + 1, y]);
                        sc.Append(mat[0, y]);

                    }
                    else
                    {
                        sc.Append(mat[ind[i, 0] + 1, y]);
                        sc.Append(mat[ind[i + 1, 0] + 1, y]);
                    }
                }
                
                else
                {

                    sc.Append(mat[ind[i, 0], ind[i + 1, 1]]);
                    sc.Append(mat[ind[i + 1, 0], ind[i, 1]]);


                }
            }
            return sc.ToString();
        }
    }
}