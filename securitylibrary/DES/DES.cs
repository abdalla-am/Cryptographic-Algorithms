using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections;


namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            string cipher = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0');
            string bi_key = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            int[,] PC1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 }, { 1, 58, 50, 42, 34, 26, 18 }, { 10, 2, 59, 51, 43, 35, 27 }, { 19, 11, 3, 60, 52, 44, 36 }, { 63, 55, 47, 39, 31, 23, 15 }, { 7, 62, 54, 46, 38, 30, 22 }, { 14, 6, 61, 53, 45, 37, 29 }, { 21, 13, 5, 28, 20, 12, 4 } };

            int[,] PC2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 }, { 3, 28, 15, 6, 21, 10 }, { 23, 19, 12, 4, 26, 8 }, { 16, 7, 27, 20, 13, 2 }, { 41, 52, 31, 37, 47, 55 }, { 30, 40, 51, 45, 33, 48 }, { 44, 49, 39, 56, 34, 53 }, { 46, 42, 50, 36, 29, 32 } };

            int[,] m1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
            int[,] m2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
            int[,] m3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
            int[,] m4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
            int[,] m5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
            int[,] m6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] m7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] m8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

            int[,] P = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 }, { 1, 15, 23, 26 }, { 5, 18, 31, 10 }, { 2, 8, 24, 14 }, { 32, 27, 3, 9 }, { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };

            int[,] E = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };

            int[,] IP = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 }, { 60, 52, 44, 36, 28, 20, 12, 4 }, { 62, 54, 46, 38, 30, 22, 14, 6 }, { 64, 56, 48, 40, 32, 24, 16, 8 }, { 57, 49, 41, 33, 25, 17, 9, 1 }, { 59, 51, 43, 35, 27, 19, 11, 3 }, { 61, 53, 45, 37, 29, 21, 13, 5 }, { 63, 55, 47, 39, 31, 23, 15, 7 } };

            int[,] IP_1 = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 }, { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 }, { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };

            string L_m = "";
            string R_m = "";

            foreach (char s in cipher.Take(cipher.Length / 2))
            {
                L_m = L_m + s;
            }

            foreach (char z in cipher.Skip(cipher.Length / 2))
            {
                R_m = R_m + z;
            }

            string tmpk = "";
            List<string> C = new List<string>();
            List<string> D = new List<string>();
            foreach (int q in Enumerable.Range(0, 8))
            {
                foreach (int j in Enumerable.Range(0, 7))
                {
                    tmpk = tmpk + bi_key[PC1[q, j] - 1];
                }
            }

            string c = tmpk.Substring(0, 28);
            string d = tmpk.Substring(28, 28);
            string temp;
            foreach (int g in Enumerable.Range(0, 17))
            {
                C.Add(c);
                D.Add(d);
                temp = "";
                if (g == 0 || g == 1 || g == 8 || g == 15)
                {
                    temp = temp + c[0];
                    c = c.Remove(0, 1);
                    c = c + temp;
                    temp = "";
                    temp = temp + d[0];
                    d = d.Remove(0, 1);
                    d = d + temp;
                }

                else
                {
                    temp = temp + c.Substring(0, 2);
                    c = c.Remove(0, 2);
                    c = c + temp;
                    temp = "";
                    temp = temp + d.Substring(0, 2);
                    d = d.Remove(0, 2);
                    d = d + temp;
                }
            }

            List<string> keys = new List<string>();
            foreach (string v in C)
            {
                int w = C.IndexOf(v);
                keys.Add(v + D[w]);
            }
            List<string> nkeys = new List<string>();
            int u = 1;
            do
            {
                tmpk = "";
                temp = keys[u];
                int f = 0;
                do
                {
                    int j = 0;
                    do
                    {
                        tmpk = tmpk + temp[PC2[f, j] - 1];
                        j++;
                    } while (j < 6);
                    f++;
                } while (f < 8);
                nkeys.Add(tmpk);
                u++;
            } while (u < keys.Count);
            string ip = "";
            int i = 0;
            while (i < 8)
            {
                int j = 0;
                while (j < 8)
                {
                    ip = ip + cipher[IP[i, j] - 1];
                    j++;
                }
                i++;
            }

            List<string> L = new List<string>();
            List<string> R = new List<string>();
            string l = ip.Substring(0, 32);
            string r = ip.Substring(32, 32);
            L.Add(l);
            R.Add(r);
            string x, h, ebit, exork, t;
            List<string> sbox = new List<string>();
            int row, col;
            string tsb, pp, lf;
            for (int n = 0; n < 16; n++)
            {
                L.Add(r);
                exork = "";
                ebit = "";
                lf = "";
                pp = "";
                sbox.Clear();
                tsb = "";

                for (int j = 0; j < 8; j++)
                {
                    for (int k = 0; k < 6; k++)
                    {
                        ebit = ebit + r[E[j, k] - 1];
                    }
                }

                for (int g = 0; g < ebit.Length; g++)
                {
                    exork = exork + (nkeys[nkeys.Count - 1 - n][g] ^ ebit[g]).ToString();
                }

                for (int z = 0; z < exork.Length; z = z + 6)
                {
                    t = "";
                    for (int y = z; y < 6 + z; y++)
                    {
                        if (6 + z <= exork.Length)
                            t = t + exork[y];
                    }

                    sbox.Add(t);
                }

                int sb = 0;
                for (int s = 0; s < sbox.Count; s++)
                {
                    t = sbox[s];
                    x = t[0].ToString() + t[5];
                    h = t[1].ToString() + t[2] + t[3] + t[4];

                    row = Convert.ToInt32(x, 2);
                    col = Convert.ToInt32(h, 2);
                    if (s == 0)
                        sb = m1[row, col];

                    if (s == 1)
                        sb = m2[row, col];

                    if (s == 2)
                        sb = m3[row, col];

                    if (s == 3)
                        sb = m4[row, col];

                    if (s == 4)
                        sb = m5[row, col];

                    if (s == 5)
                        sb = m6[row, col];

                    if (s == 6)
                        sb = m7[row, col];

                    if (s == 7)
                        sb = m8[row, col];

                    tsb = tsb + Convert.ToString(sb, 2).PadLeft(4, '0');
                }

                int o = 0;
                while (o < 8)
                {
                    int j = 0;
                    while (j < 4)
                    {
                        pp = pp + tsb[P[o, j] - 1];
                        j++;
                    }
                    o++;
                }

                int v = 0;
                foreach (char p in pp)
                {
                    lf = lf + (p ^ l[v]).ToString();
                    v++;
                }

                r = lf;
                l = L[n + 1];
                R.Add(r);
            }

            string r16 = R[16] + L[16];
            string cipher_txt = "";
            int b = 0;
            while (b < 8)
            {
                int j = 0;
                while (j < 8)
                {
                    cipher_txt = cipher_txt + r16[IP_1[b, j] - 1];
                    j++;
                }
                b++;
            }
            string p_t = "0x" + Convert.ToInt64(cipher_txt, 2).ToString("X").PadLeft(16, '0');
            return p_t;
        }

        public override string Encrypt(string plainText, string key)
        {
            long keyInt = Convert.ToInt64(key.Substring(2), 16);
            string keyBinary = Convert.ToString(keyInt, 2).PadLeft(64, '0');



            BitArray keyBits = new BitArray(keyBinary.Select(c => c == '1').ToArray());

            long mainInt = Convert.ToInt64(plainText.Substring(2), 16);
            string mainBinary = Convert.ToString(mainInt, 2).PadLeft(64, '0');
            BitArray mainBits = new BitArray(mainBinary.Select(c => c == '1').ToArray());

            BitArray result = PermutePC1(keyBits, pc1Table);

            BitArray c0 = new BitArray(28);
            BitArray d0 = new BitArray(28);

            for (int i = 0; i < result.Length / 2; i++)
            {
                c0[i] = result[i];
            }
            int s = 0;
            for (int i = result.Length / 2; i < result.Length; i++)
            {
                d0[s] = result[i];
                s++;
            }


            BitArray c1 = new BitArray(28);
            BitArray d1 = new BitArray(28);
            BitArray c2 = new BitArray(28);
            BitArray d2 = new BitArray(28);
            BitArray c3 = new BitArray(28);
            BitArray d3 = new BitArray(28);
            BitArray c4 = new BitArray(28);
            BitArray d4 = new BitArray(28);
            BitArray c5 = new BitArray(28);
            BitArray d5 = new BitArray(28);
            BitArray c6 = new BitArray(28);
            BitArray d6 = new BitArray(28);
            BitArray c7 = new BitArray(28);
            BitArray d7 = new BitArray(28);
            BitArray c8 = new BitArray(28);
            BitArray d8 = new BitArray(28);
            BitArray c9 = new BitArray(28);
            BitArray d9 = new BitArray(28);
            BitArray c10 = new BitArray(28);
            BitArray d10 = new BitArray(28);
            BitArray c11 = new BitArray(28);
            BitArray d11 = new BitArray(28);
            BitArray c12 = new BitArray(28);
            BitArray d12 = new BitArray(28);
            BitArray c13 = new BitArray(28);
            BitArray d13 = new BitArray(28);
            BitArray c14 = new BitArray(28);
            BitArray d14 = new BitArray(28);
            BitArray c15 = new BitArray(28);
            BitArray d15 = new BitArray(28);
            BitArray c16 = new BitArray(28);
            BitArray d16 = new BitArray(28);


            left(c0, ref c1, 1);
            left(c1, ref c2, 1);
            left(c2, ref c3, 2);
            left(c3, ref c4, 2);
            left(c4, ref c5, 2);
            left(c5, ref c6, 2);
            left(c6, ref c7, 2);
            left(c7, ref c8, 2);
            left(c8, ref c9, 1);
            left(c9, ref c10, 2);
            left(c10, ref c11, 2);
            left(c11, ref c12, 2);
            left(c12, ref c13, 2);
            left(c13, ref c14, 2);
            left(c14, ref c15, 2);
            left(c15, ref c16, 1);
            left(d0, ref d1, 1);
            left(d1, ref d2, 1);
            left(d2, ref d3, 2);
            left(d3, ref d4, 2);
            left(d4, ref d5, 2);
            left(d5, ref d6, 2);
            left(d6, ref d7, 2);
            left(d7, ref d8, 2);
            left(d8, ref d9, 1);
            left(d9, ref d10, 2);
            left(d10, ref d11, 2);
            left(d11, ref d12, 2);
            left(d12, ref d13, 2);
            left(d13, ref d14, 2);
            left(d14, ref d15, 2);
            left(d15, ref d16, 1);

            BitArray key1 = PermutePC2(findkey(c1, d1), pc2Table);
            BitArray key2 = PermutePC2(findkey(c2, d2), pc2Table);
            BitArray key3 = PermutePC2(findkey(c3, d3), pc2Table);
            BitArray key4 = PermutePC2(findkey(c4, d4), pc2Table);
            BitArray key5 = PermutePC2(findkey(c5, d5), pc2Table);
            BitArray key6 = PermutePC2(findkey(c6, d6), pc2Table);
            BitArray key7 = PermutePC2(findkey(c7, d7), pc2Table);
            BitArray key8 = PermutePC2(findkey(c8, d8), pc2Table);
            BitArray key9 = PermutePC2(findkey(c9, d9), pc2Table);
            BitArray key10 = PermutePC2(findkey(c10, d10), pc2Table);
            BitArray key11 = PermutePC2(findkey(c11, d11), pc2Table);
            BitArray key12 = PermutePC2(findkey(c12, d12), pc2Table);
            BitArray key13 = PermutePC2(findkey(c13, d13), pc2Table);
            BitArray key14 = PermutePC2(findkey(c14, d14), pc2Table);
            BitArray key15 = PermutePC2(findkey(c15, d15), pc2Table);
            BitArray key16 = PermutePC2(findkey(c16, d16), pc2Table);
            BitArray mp = ip(mainBits, ipInvTable);
            BitArray l0 = new BitArray(32);
            BitArray r0 = new BitArray(32);

            for (int i = 0; i < mp.Length / 2; i++)
            {
                l0[i] = mp[i];
            }
            int p = 0;
            for (int i = mp.Length / 2; i < mp.Length; i++)
            {
                r0[p] = mp[i];
                p++;
            }

            //1
            BitArray l1 = r0;
            BitArray op = ebitxor(r0, eTable, key1);
            BitArray yea = new BitArray(32);
            sresult(ref yea, op, s0, s1, s2, s3, s4, s5, s6, s7);
            BitArray r1 = ppp(yea, pTable).Xor(l0);


            //2
            BitArray l2 = r1;
            BitArray op1 = ebitxor(r1, eTable, key2);
            BitArray yea1 = new BitArray(32);
            sresult(ref yea1, op1, s0, s1, s2, s3, s4, s5, s6, s7);
            BitArray r2 = ppp(yea1, pTable).Xor(l1);

            //3
            BitArray l3 = r2;
            BitArray op2 = ebitxor(r2, eTable, key3);
            BitArray yea2 = new BitArray(32);
            sresult(ref yea2, op2, s0, s1, s2, s3, s4, s5, s6, s7);
            BitArray r3 = ppp(yea2, pTable).Xor(l2);


            //4
            BitArray l4 = r3;
            BitArray op3 = ebitxor(r3, eTable, key4);
            BitArray yea3 = new BitArray(32);
            sresult(ref yea3, op3, s0, s1, s2, s3, s4, s5, s6, s7);
            BitArray r4 = ppp(yea3, pTable).Xor(l3);

            //5
            BitArray l5 = r4;
            BitArray op4 = ebitxor(r4, eTable, key5);
            BitArray yea4 = new BitArray(32);
            sresult(ref yea4, op4, s0, s1, s2, s3, s4, s5, s6, s7);
            BitArray r5 = ppp(yea4, pTable).Xor(l4);

            //6
            BitArray l6 = r5;
            BitArray op5 = ebitxor(r5, eTable, key6);
            BitArray yea5 = new BitArray(32);
            sresult(ref yea5, op5, s0, s1, s2, s3, s4, s5, s6, s7);
            BitArray r6 = ppp(yea5, pTable).Xor(l5);

            //7
            BitArray l7 = r6;
            BitArray op6 = ebitxor(r6, eTable, key7);
            BitArray yea6 = new BitArray(32);
            sresult(ref yea6, op6, s0, s1, s2, s3, s4, s5, s6, s7);
            BitArray r7 = ppp(yea6, pTable).Xor(l6);

            //8
            BitArray l8 = r7;
            BitArray op7 = ebitxor(r7, eTable, key8);
            BitArray yea7 = new BitArray(32);
            sresult(ref yea7, op7, s0, s1, s2, s3, s4, s5, s6, s7);
            BitArray r8 = ppp(yea7, pTable).Xor(l7);

            //9
            BitArray l9 = r8;
            BitArray op8 = ebitxor(r8, eTable, key9);
            BitArray yea8 = new BitArray(32);
            sresult(ref yea8, op8, s0, s1, s2, s3, s4, s5, s6, s7);
            BitArray r9 = ppp(yea8, pTable).Xor(l8);

            //10
            BitArray l10 = r9;
            BitArray op9 = ebitxor(r9, eTable, key10);
            BitArray yea9 = new BitArray(32);
            sresult(ref yea9, op9, s0, s1, s2, s3, s4, s5, s6, s7);
            BitArray r10 = ppp(yea9, pTable).Xor(l9);

            //11
            BitArray l11 = r10;
            BitArray op10 = ebitxor(r10, eTable, key11);
            BitArray yea10 = new BitArray(32);
            sresult(ref yea10, op10, s0, s1, s2, s3, s4, s5, s6, s7);
            BitArray r11 = ppp(yea10, pTable).Xor(l10);

            //12
            BitArray l12 = r11;
            BitArray op11 = ebitxor(r11, eTable, key12);
            BitArray yea11 = new BitArray(32);
            sresult(ref yea11, op11, s0, s1, s2, s3, s4, s5, s6, s7);
            BitArray r12 = ppp(yea11, pTable).Xor(l11);

            //13
            BitArray l13 = r12;
            BitArray op12 = ebitxor(r12, eTable, key13);
            BitArray yea12 = new BitArray(32);
            sresult(ref yea12, op12, s0, s1, s2, s3, s4, s5, s6, s7);
            BitArray r13 = ppp(yea12, pTable).Xor(l12);

            //14
            BitArray l14 = r13;
            BitArray op13 = ebitxor(r13, eTable, key14);
            BitArray yea13 = new BitArray(32);
            sresult(ref yea13, op13, s0, s1, s2, s3, s4, s5, s6, s7);
            BitArray r14 = ppp(yea13, pTable).Xor(l13);

            //15
            BitArray l15 = r14;
            BitArray op14 = ebitxor(r14, eTable, key15);
            BitArray yea14 = new BitArray(32);
            sresult(ref yea14, op14, s0, s1, s2, s3, s4, s5, s6, s7);
            BitArray r15 = ppp(yea14, pTable).Xor(l14);

            //16
            BitArray l16 = r15;
            BitArray op15 = ebitxor(r15, eTable, key16);
            BitArray yea15 = new BitArray(32);
            sresult(ref yea15, op15, s0, s1, s2, s3, s4, s5, s6, s7);
            BitArray r16 = ppp(yea15, pTable).Xor(l15);
            BitArray bigresult = ip(findkey1(r16, l16), IP1);

            string binaryString = "";
            for (int i = 0; i < bigresult.Length; i++)
            {
                binaryString += bigresult[i] ? "1" : "0";
            }
            int numBytes = binaryString.Length / 8;
            byte[] bytes = new byte[numBytes];
            for (int i = 0; i < numBytes; i++)
            {
                bytes[i] = Convert.ToByte(binaryString.Substring(i * 8, 8), 2);
            }
            string hexString = BitConverter.ToString(bytes).Replace("-", "");
            string hl = hexString.Insert(0, "0");
            string hl1 = hl.Insert(1, "x");
            return hl1;



            /*for(int i=0; i<po.Length; i++)
            {
                string binary_str = Convert.ToString(po[i], 2).PadLeft(4, '0');
                Console.Write(binary_str);
            }*/






        }

        BitArray PermutePC1(BitArray key90, int[] pc1Table1)
        {
            BitArray result1 = new BitArray(56);
            for (int i = 0; i < 56; i++)
            {
                result1[i] = key90[pc1Table1[i] - 1];
            }
            return result1;
        }
        BitArray left(BitArray c00, ref BitArray c22, int n)
        {
            if (n == 1)
            {
                bool x1 = c00[0];

                for (int i = 1; i < 28; i++)
                {
                    c22[i - 1] = c00[i];

                }
                c22[c22.Length - 1] = x1;
            }
            if (n == 2)
            {
                bool x1 = c00[0];
                bool x2 = c00[1];
                for (int i = 2; i < 28; i++)
                {
                    c22[i - 2] = c00[i];

                }
                c22[c22.Length - 2] = x1;
                c22[c22.Length - 1] = x2;

            }

            return c22;

        }
        BitArray findkey(BitArray c00, BitArray c22)
        {
            BitArray key90 = new BitArray(56);
            for (int i = 0; i < 28; i++)
            {
                key90[i] = c00[i];
            }
            int u = 0;
            for (int i = 28; i < 56; i++)
            {
                key90[i] = c22[u];
                u++;
            }
            return key90;

        }
        BitArray findkey1(BitArray c00, BitArray c22)
        {
            BitArray key90 = new BitArray(64);
            for (int i = 0; i < 32; i++)
            {
                key90[i] = c00[i];
            }
            int u = 0;
            for (int i = 32; i < 64; i++)
            {
                key90[i] = c22[u];
                u++;
            }
            return key90;
        }
        BitArray PermutePC2(BitArray key90, int[] pc2Table1)
        {
            BitArray result1 = new BitArray(48);
            for (int i = 0; i < 48; i++)
            {
                result1[i] = key90[pc2Table1[i] - 1];
            }
            return result1;
        }
        BitArray ip(BitArray mp1, int[] ipInvTable1)
        {
            BitArray result1 = new BitArray(64);
            for (int i = 0; i < ipInvTable1.Length; i++)
            {
                result1[i] = mp1[ipInvTable1[i] - 1];
            }
            return result1;
        }
        BitArray ebitxor(BitArray r, int[] e_bit, BitArray key90)
        {
            BitArray result1 = new BitArray(48);
            for (int i = 0; i < e_bit.Length; i++)
            {
                result1[i] = r[e_bit[i] - 1];
            }
            return result1.Xor(key90);
        }
        void sresult(ref BitArray r, BitArray o, int[,] s01, int[,] s11, int[,] s21, int[,] s31, int[,] s41, int[,] s51, int[,] s61, int[,] s71)
        {




            int[] t = new int[8];
            BitArray pa = new BitArray(6);
            for (int e = 0; e < 8; e++)
            {

                int u = 0;
                int w = e * 6;
                int w1 = w + 6;
                for (int i = w; i < w1; i++)
                {

                    pa[u] = o[i];
                    u++;

                }
                bool bit0 = pa[0];
                bool bit5 = pa[5];

                int row = (bit0 ? 1 : 0) * 2 + (bit5 ? 1 : 0) * 1;
                bool bit1 = pa[1];
                bool bit2 = pa[2];
                bool bit3 = pa[3];
                bool bit4 = pa[4];

                int col = (bit1 ? 1 : 0) * 8 + (bit2 ? 1 : 0) * 4 + (bit3 ? 1 : 0) * 2 + (bit4 ? 1 : 0) * 1;
                if (e == 0)
                {
                    t[0] = s01[row, col];
                }
                else if (e == 1)
                {
                    t[1] = s11[row, col];
                }
                else if (e == 2)
                {
                    t[2] = s21[row, col];
                }
                else if (e == 3)
                {
                    t[3] = s31[row, col];
                }
                else if (e == 4)
                {
                    t[4] = s41[row, col];
                }
                else if (e == 5)
                {
                    t[5] = s51[row, col];
                }
                else if (e == 6)
                {
                    t[6] = s61[row, col];
                }
                else if (e == 7)
                {
                    t[7] = s71[row, col];
                }

            }
            for (int e = 0; e < 8; e++)
            {
                string b = Convert.ToString(t[e], 2).PadLeft(4, '0');
                int w = e * 4;
                int w1 = w + 4;
                int s99 = 0;
                for (int i = w; i < w1; i++)
                {
                    if (b[s99].Equals('1'))
                    {
                        r[i] = true;
                        s99++;
                    }
                    else if (b[s99].Equals('0'))
                    {
                        r[i] = false;
                        s99++;
                    }
                }
            }


        }

        BitArray ppp(BitArray key90, int[] pc1Table1)
        {
            BitArray result1 = new BitArray(32);
            for (int i = 0; i < 32; i++)
            {
                result1[i] = key90[pc1Table1[i] - 1];
            }
            return result1;
        }



        int[,] s0 = new int[,] {
    { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
    { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
    { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
    { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }
};
        int[,] s1 = new int[,] {
    { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
    { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
    { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
    { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 }
};
        int[,] s2 = new int[,] {
    { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
    { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
    { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
    { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }
};
        int[,] s3 = new int[,] {
    { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
    { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
    { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
    { 3, 15, 0, 6, 10, 1, 13, 8, 9,4, 5, 11, 12, 7, 2, 14 }
};

        int[,] s4 = new int[,] {
    { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
    { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
    { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
    { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }
};
        int[,] s5 = new int[,] {
    { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
    { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
    { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
    { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }
};
        int[,] s6 = new int[,] {
    { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
    { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
    { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
    { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }
};
        int[,] s7 = new int[,] {
    { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
    { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
    { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
    { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
};

        int[] eTable = new int[]
        {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
        };


        int[] ipInvTable = new int[]
        {
     58 ,50,42,34,26,18,10,2,
     60,52,44,36,28,20,12,4,
     62,54,46,38,30,22,14,6,
     64,56,48,40,32,24,16,8,
     57,49,41,33,25,17,9,1,59,
51,
43,
35,
27,
19,
11,
3,
61,
53,
45,
37,
29,
21,
13,
5,
63,
55,
47,
39,
31,
23,
15,
7

        };

        int[] pc1Table = new int[]
        {
    57, 49, 41, 33, 25, 17, 9, 1,
    58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3,
    60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15, 7, 62, 54, 46, 38,
    30, 22, 14, 6, 61, 53, 45, 37,
    29, 21, 13, 5, 28, 20, 12, 4
        };
        int[] pc2Table = new int[]
        {
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
        };
        int[] pTable = new int[] {
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
};
        int[] IP1 = new int[] { 40, 8, 48, 16, 56, 24, 64, 32,
                        39, 7, 47, 15, 55, 23, 63, 31,
                        38, 6, 46, 14, 54, 22, 62, 30,
                        37, 5, 45, 13, 53, 21, 61, 29,
                        36, 4, 44, 12, 52, 20, 60, 28,
                        35, 3, 43, 11, 51, 19, 59, 27,
                        34, 2, 42, 10, 50, 18, 58, 26,
                        33, 1, 41, 9,   49, 17, 57, 25 };
    }
}
