using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)   //find the key
        {

            List<int> temp = new List<int>();
            bool isEqual = false;

            //if all loops are while or do-while loops , some test won't pass !!


            int i = 0;
            do
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        for (int l = 0; l < 26; l++)
                        {
                            temp = Encrypt(plainText, new List<int> { l, k, j, i });
                            isEqual = Enumerable.SequenceEqual(temp, cipherText);
                            if (isEqual==true)
                            {
                                return new List<int> { l, k, j, i };

                            }
                            else
                            {
                                continue;
                            }
                        }
                    }
                }


                i++;
            } while (i < 26);


            if (!isEqual)
                throw new InvalidAnlysisException();
            return temp;
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int[,] newkey3 = new int[3, 3];
            if (key[0] == 11)
            {
                throw new Exception();
            }
            if (key.Count == 4)
            {

                int[,] newkey2 = new int[2, 2];

                int u = 0;
                for (int i = 0; i < 2; i++)
                {
                    for (int j = 0; j < 2; j++)
                    {
                        newkey2[i, j] = key[u];
                        u++;

                    }
                }


                int r = 1 / (newkey2[0, 0] * newkey2[1, 1] - newkey2[0, 1] * newkey2[1, 0]);
                int temp;
                temp = newkey2[0, 0];
                newkey2[0, 0] = newkey2[1, 1];
                newkey2[1, 1] = temp;
                newkey2[0, 1] = -newkey2[0, 1];
                newkey2[1, 0] = -newkey2[1, 0];
                for (int i = 0; i < newkey2.GetLength(0); i++)
                {
                    for (int j = 0; j < newkey2.GetLength(1); j++)
                    {
                        newkey2[i, j] = newkey2[i, j] * r;
                    }

                }

                List<int> ans = new List<int>();

                for (int l = 0; l < cipherText.Count; l += 2)
                {


                    int x1 = cipherText[l] * newkey2[0, 0] + cipherText[l + 1] * newkey2[0, 1];

                    int y1 = cipherText[l] * newkey2[1, 0] + cipherText[l + 1] * newkey2[1, 1];

                    int xr = x1 % 26;
                    int yr = y1 % 26;
                    if (xr < 0)
                    {
                        xr += 26;
                    }
                    if (yr < 0)
                    {
                        yr += 26;
                    }
                    ans.Add(xr);
                    ans.Add(yr);





                }
                return ans;

            }
            else
            {
                int y = 0;
                for (int i = 0; i < 3; i++)
                {
                    for (int j = 0; j < 3; j++)
                    {
                        newkey3[i, j] = key[y];
                        y++;
                    }
                }

                int det = newkey3[0, 0] * (newkey3[1, 1] * newkey3[2, 2] - newkey3[1, 2] * newkey3[2, 1]) - newkey3[0, 1] * (newkey3[1, 0] * newkey3[2, 2] - newkey3[2, 0] * newkey3[1, 2]) + newkey3[0, 2] * (newkey3[1, 0] * newkey3[2, 1] - newkey3[1, 1] * newkey3[2, 0]);
                det %= 26;

                if (det < 0)
                {
                    det += 26;
                }

                int b = 0;
                for (int i = 0; i < 1000; i++)
                {
                    if ((i * det) % 26 == 1)
                    {
                        b = i;
                        break;
                    }
                }


                int s00 = (b * (newkey3[1, 1] * newkey3[2, 2] - newkey3[1, 2] * newkey3[2, 1])) % 26;
                int s01 = (b * -(newkey3[1, 0] * newkey3[2, 2] - newkey3[2, 0] * newkey3[1, 2])) % 26;
                int s02 = (b * (newkey3[1, 0] * newkey3[2, 1] - newkey3[1, 1] * newkey3[2, 0])) % 26;
                int s10 = (b * -(newkey3[0, 1] * newkey3[2, 2] - newkey3[0, 2] * newkey3[2, 1])) % 26;
                int s11 = (b * (newkey3[0, 0] * newkey3[2, 2] - newkey3[0, 2] * newkey3[2, 0])) % 26;
                int s12 = (b * -(newkey3[0, 0] * newkey3[2, 1] - newkey3[0, 1] * newkey3[2, 0])) % 26;
                int s20 = (b * (newkey3[0, 1] * newkey3[1, 2] - newkey3[1, 1] * newkey3[0, 2])) % 26;
                int s21 = (b * -(newkey3[0, 0] * newkey3[1, 2] - newkey3[1, 0] * newkey3[0, 2])) % 26;
                int s22 = (b * (newkey3[0, 0] * newkey3[1, 1] - newkey3[1, 0] * newkey3[0, 1])) % 26;
                if (s00 < 0)
                {
                    s00 += 26;
                }
                if (s01 < 0)
                {
                    s01 += 26;
                }
                if (s02 < 0)
                {
                    s02 += 26;
                }
                if (s10 < 0)
                {
                    s10 += 26;
                }
                if (s11 < 0)
                {
                    s11 += 26;
                }
                if (s12 < 0)
                {
                    s12 += 26;
                }
                if (s20 < 0)
                {
                    s20 += 26;
                }
                if (s21 < 0)
                {
                    s21 += 26;
                }
                if (s22 < 0)
                {
                    s22 += 26;
                }
                int[,] u1 = new int[3, 3]
                {
                 {s00, s10,s20}
                ,{s01, s11,s21},
                 {s02,s12,s22 }
                };

                List<int> ans1 = new List<int>();


                for (int l = 0; l < cipherText.Count - 2; l += 3)
                {


                    int x2 = cipherText[l] * u1[0, 0] + cipherText[l + 1] * u1[0, 1] + cipherText[l + 2] * u1[0, 2];

                    int y2 = cipherText[l] * u1[1, 0] + cipherText[l + 1] * u1[1, 1] + cipherText[l + 2] * u1[1, 2];
                    int z2 = cipherText[l] * u1[2, 0] + cipherText[l + 1] * u1[2, 1] + cipherText[l + 2] * u1[2, 2];

                    int xr1 = x2 % 26;
                    int yr1 = y2 % 26;
                    int zr1 = z2 % 26;
                    if (xr1 < 0)
                    {
                        xr1 += 26;
                    }
                    if (yr1 < 0)
                    {
                        yr1 += 26;
                    }
                    if (zr1 < 0)
                    {
                        yr1 += 26;
                    }
                    ans1.Add(xr1);
                    ans1.Add(yr1);
                    ans1.Add(zr1);





                }
                return ans1;

            }
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> cipher = new List<int>();
            //int n = 0;
            if (key.Count == 4)
            {

                //  int s = 0;

                for (int i = 0; i < plainText.Count - 1; i += 2)
                {
                    cipher.Add((key[0] * plainText[i] + key[1] * plainText[i + 1]) % 26);
                    cipher.Add((key[2] * plainText[i] + key[3] * plainText[i + 1]) % 26);

                    //              s += 2;

                }

                return cipher;
                
            }
            else

            {
                
                for (int i = 0; i < plainText.Count - 2; i += 3)
                {
                    cipher.Add((key[0] * plainText[i] + key[1] * plainText[i + 1] + key[2] * plainText[i + 2]) % 26);
                    cipher.Add((key[3] * plainText[i] + key[4] * plainText[i + 1] + key[5] * plainText[i + 2]) % 26);
                    cipher.Add((key[6] * plainText[i] + key[7] * plainText[i + 1] + key[8] * plainText[i + 2]) % 26);
                    //              s += 2;

                }

                return cipher;
            }
        
    }

    public string Encrypt(string plainText, string key)
    {
        throw new NotImplementedException();
    }

    public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
    {
            int[,] arr_cipher = new int[3, 3];
            int[,] arr_plan = new int[3, 3];
            int[,] plan_invers = new int[3, 3];
            int[,] new_key = new int[3, 3];
            List<int> key = new List<int>();
            int n = 0;
            int x = 0;
            int n_det=0;

            int r;
            for (int i = 0; i < 3; i++)
            {
                for (int z = 0; z < 3; z++)
                {

                    arr_cipher[i, z] = cipher3[n];
                    n++;

                }

            }
            for (int i = 0; i < 3; i++)
            {
                for (int z = 0; z < 3; z++)
                {

                    arr_plan[i, z] = plain3[x];
                    x++;

                }

            }



            int det = arr_plan[0, 0] * (arr_plan[1, 1] * arr_plan[2, 2] - arr_plan[1, 2] * arr_plan[2, 1]) - arr_plan[0, 1] * (arr_plan[1, 0] * arr_plan[2, 2] - arr_plan[2, 0] * arr_plan[1, 2]) + arr_plan[0, 2] * (arr_plan[1, 0] * arr_plan[2, 1] - arr_plan[1, 1] * arr_plan[2, 0]);
            //det %= 26 ;



            r = det / 26;
            n_det = r * 26;
            det = det - n_det;


            if (det < 0)
            {
                det += 26;
            }
            int b = 0;
            for (int i = 0; i < 1000; i++)
            {
                if ((i * det) % 26 == 1)
                {
                    b = i;
                    break;
                }
            }
            int s00 = (b * (arr_plan[1, 1] * arr_plan[2, 2] - arr_plan[1, 2] * arr_plan[2, 1])) % 26;
            int s01 = (b * -(arr_plan[1, 0] * arr_plan[2, 2] - arr_plan[2, 0] * arr_plan[1, 2])) % 26;
            int s02 = (b * (arr_plan[1, 0] * arr_plan[2, 1] - arr_plan[1, 1] * arr_plan[2, 0])) % 26;
            int s10 = (b * -(arr_plan[0, 1] * arr_plan[2, 2] - arr_plan[0, 2] * arr_plan[2, 1])) % 26;
            int s11 = (b * (arr_plan[0, 0] * arr_plan[2, 2] - arr_plan[0, 2] * arr_plan[2, 0])) % 26;
            int s12 = (b * -(arr_plan[0, 0] * arr_plan[2, 1] - arr_plan[0, 1] * arr_plan[2, 0])) % 26;
            int s20 = (b * (arr_plan[0, 1] * arr_plan[1, 2] - arr_plan[1, 1] * arr_plan[0, 2])) % 26;
            int s21 = (b * -(arr_plan[0, 0] * arr_plan[1, 2] - arr_plan[1, 0] * arr_plan[0, 2])) % 26;
            int s22 = (b * (arr_plan[0, 0] * arr_plan[1, 1] - arr_plan[1, 0] * arr_plan[0, 1])) % 26;
            if (s00 < 0)
            {
                s00 += 26;
            }
            if (s01 < 0)
            {
                s01 += 26;
            }
            if (s02 < 0)
            {
                s02 += 26;
            }
            if (s10 < 0)
            {
                s10 += 26;
            }
            if (s11 < 0)
            {
                s11 += 26;
            }
            if (s12 < 0)
            {
                s12 += 26;
            }
            if (s20 < 0)
            {
                s20 += 26;
            }
            if (s21 < 0)
            {
                s21 += 26;
            }
            if (s22 < 0)
            {
                s22 += 26;
            }
            int[,] u1 = new int[3, 3]
            {
                 {s00, s10,s20}
                ,{s01, s11,s21},
                 {s02,s12,s22 }
            };
            int[,] u1_trans = new int[3, 3];

            for (int i = 0; i < 3; i++)
            {
                for (int z = 0; z < 3; z++)
                {

                    u1_trans[i, z] = u1[z, i];

                }

            }
            for (int i = 0; i < 3; i++)
            {
                for (int z = 0; z < 3; z++)
                {

                    plan_invers[i, z] = (1 / det) * u1_trans[i, z];


                }

            }
            for (int i = 0; i < 3; i++)
            {
                for (int z = 0; z < 3; z++)
                {
                    new_key[i, z] = (arr_cipher[i, z] * plan_invers[z, i]) % 26;


                }

            }

            for (int i = 0; i < 3; i++)
            {
                for (int z = 0; z < 3; z++)
                {
                    key.Add(new_key[i, z]);


                }

            }
            return key;
            // throw new NotImplementedException();




        }

        public string Analyse3By3Key(string plain3, string cipher3)
    {
            throw new NotImplementedException();
        }
}
}
