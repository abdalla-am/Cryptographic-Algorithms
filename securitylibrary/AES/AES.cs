using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        //tables
        public static string[,] SBOX = {
            {"63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76" },
            {"CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0" },
            {"B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15" },
            {"04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75" },
            {"09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84"},
            {"53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF"},
            {"D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8"},
            {"51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2"},
            {"CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73"},
            {"60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB"},
            {"E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79"},
            {"E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08"},
            {"BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A"},
            {"70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E"},
            {"E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF"},
            {"8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"}
        };



        string[,] Matrix_for_Mix_Columns = {
                {"02","03","01","01"},
                {"01","02","03","01"},
                { "01","01","02","03"},
                { "03","01","01","02"}
            };



        //functions:



        public string gbs(string converted)
        {
            converted = Convert.ToString(Convert.ToInt64(converted, 16), 2);
            converted = converted.Length < 8 ? (new String('0', 8 - converted.Length) + converted) : converted;
            return converted;

        }
        //convert from binary to hexa
        public string get_hexa(string s)
        {
            Dictionary<string, string> dict = new Dictionary<string, string>();
            dict.Add("0000", "0");
            dict.Add("0001", "1");
            dict.Add("0010", "2");
            dict.Add("0011", "3");
            dict.Add("0100", "4");
            dict.Add("0101", "5");
            dict.Add("0110", "6");
            dict.Add("0111", "7");
            dict.Add("1000", "8");
            dict.Add("1001", "9");
            dict.Add("1010", "A");
            dict.Add("1011", "B");
            dict.Add("1100", "C");
            dict.Add("1101", "D");
            dict.Add("1110", "E");
            dict.Add("1111", "F");
            string tmp1 = s.Substring(0, 4);
            string tmp2 = s.Substring(4, 4);
            return (dict[tmp1] + dict[tmp2]);
        }
        public string X_or(string x, string y)
        {
            //(1) if 1,0 else (0)
            string res = "";
            for (int i = 0; i < x.Length; i++)
            {
                if (x[i] == y[i])
                    res += '0';
                else
                    res += '1';
            }
            return res;

        }


        string[,] xrrt(string[,] a, string[,] b)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    a[i, j] = get_hexa(X_or(gbs(a[i, j]), gbs(b[i, j])));
                }
            }
            return a;
        }


        public static string[,] Shift_Rows(string[,] plaintext)
        {


            for (int i = 0; i < 4; i++)
            {

                string[] tr = new string[4];


                for (int j = 0; j < 4; j++)
                {
                    tr[j] = plaintext[i, (j + i) % 4];
                }


                for (int j = 0; j < 4; j++)
                {
                    plaintext[i, j] = tr[j];
                }
            }


            return plaintext;
        }


        public string Mul(string s1, string s2)
        {
            s1 = s1.ToUpper();
            s2 = s2.ToUpper();

            Dictionary<char, string> data = new Dictionary<char, string>
            {
                { '0', "0000" },
                { '1', "0001" },
                { '2', "0010" },
                { '3', "0011" },
                { '4', "0100" },
                { '5', "0101" },
                { '6', "0110" },
                { '7', "0111" },
                { '8', "1000" },
                { '9', "1001" },
                { 'A', "1010" },
                { 'B', "1011" },
                { 'C', "1100" },
                { 'D', "1101" },
                { 'E', "1110" },
                { 'F', "1111" }
            };

            string r1 = "", r2 = "";
            for (int i = 0; i < s1.Length; i++)
            {
                r1 += data[s1[i]];
                r2 += data[s2[i]];
            }
            int tmp1 = Convert.ToInt32(r1, 2);
            int tmp2 = Convert.ToInt32(r2, 2);
            if (s1 == "03")
            {
                int ans2 = tmp2 * 2;
                ans2 ^= tmp2;
                string binary2 = Convert.ToString(ans2, 2);
                return binary2;
            }
            int ans = tmp1 * tmp2;
            string binary = Convert.ToString(ans, 2);
            return binary;
        }


        public string X_OR(string s1, string s2, string s3, string s4)
        {
            int tt1 = Convert.ToInt32(s1, 2);
            int tt2 = Convert.ToInt32(s2, 2);
            int tt3 = Convert.ToInt32(s3, 2);
            int tt4 = Convert.ToInt32(s4, 2);

            int ans = (tt1 ^ tt2 ^ tt3 ^ tt4);

            string binary = Convert.ToString(ans, 2);

            int sta = 283;
            if (binary.Length > 8)
                ans ^= sta;

            binary = Convert.ToString(ans, 2);
            string temp = "";

            for (int i = 0; i < 8 - binary.Length; i++)
                temp += '0';

            return (temp + binary);
        }


        public string[,] mc(string[,] plain_Text)
        {
            string[,] res = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string[] arr = new string[4];
                    for (int k = 0; k < 4; k++)
                    {
                        arr[k] = Mul(Matrix_for_Mix_Columns[i, k], plain_Text[k, j]);
                    }

                    res[i, j] = get_hexa(X_OR(arr[0], arr[1], arr[2], arr[3]));
                }
            }
            return res;
        }




        public string[,] sb(string[,] plain_text)
        {

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string tmp = plain_text[i, j];
                    int r = int.Parse(tmp[0].ToString(), System.Globalization.NumberStyles.HexNumber);
                    int c = int.Parse(tmp[1].ToString(), System.Globalization.NumberStyles.HexNumber);
                    plain_text[i, j] = SBOX[r, c];
                }
            }
            return plain_text;
        }


        public string[,] grd(string[,] last, int num)
        {
            string[] fc = new string[4];
            string[] C1 = new string[4];


            for (int i = 0; i < 4; i++)
            {
                fc[i] = last[i, 3];
                C1[i] = last[i, 0];
            }


            string tmp = fc[0];
            for (int i = 1; i < 4; i++)
                fc[i - 1] = fc[i];
            fc[3] = tmp;


            for (int i = 0; i < 4; i++)
            {
                int r = int.Parse(fc[i][0].ToString(), System.Globalization.NumberStyles.HexNumber);
                int c = int.Parse(fc[i][1].ToString(), System.Globalization.NumberStyles.HexNumber);
                fc[i] = SBOX[r, c];
            }


            int Rcon = num;

            string[,] Con =
            {
                { "01", "02","04","08","10","20","40","80","1b","36"},
                { "00", "00","00","00","00","00","00","00","00","00"},
                { "00", "00","00","00","00","00","00","00","00","00"},
                { "00", "00","00","00","00","00","00","00","00","00"}
            };

            string[] C2 = new string[4];
            for (int i = 0; i < 4; i++)
                C2[i] = Con[i, Rcon];

            for (int i = 0; i < 4; i++)
                C1[i] = get_hexa(X_or(gbs(C1[i]), gbs(C2[i])));

            string[,] ans = new string[4, 4];


            for (int i = 0; i < 4; i++)
                ans[i, 0] = get_hexa(X_or(gbs(C1[i]), gbs(fc[i])));


            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    ans[j, i] = get_hexa(X_or(gbs(last[j, i]), gbs(ans[j, i - 1])));
                }
            }
            return ans;
        }



        //------------------------------------------------------------------------------------------------------------------------------




        public string[,] Inv_Mix_Columns(string[,] cipher_Text)
        {
            string[,] res = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string[] arr = new string[4];
                    for (int k = 0; k < 4; k++)
                    {
                        arr[k] = Mul(Matrix_for_Inv_Mix_Columns[i, k], cipher_Text[k, j]);
                    }

                    res[i, j] = get_hexa(X_OR(arr[0], arr[1], arr[2], arr[3]));
                }
            }
            return res;
        }

        readonly string[,] Matrix_for_Inv_Mix_Columns =  {
    {"0e", "0b", "0d", "09"},
    {"09", "0e", "0b", "0d"},
    {"0d", "09", "0e", "0b"},
    {"0b", "0d", "09", "0e"}
};

        public static string[,] Inv_Shift_Rows(string[,] cipherText)
        {

            for (int i = 0; i < 4; i++)
            {

                string[] trrr = new string[4];


                for (int j = 0; j < 4; j++)
                {
                    trrr[(j + i) % 4] = cipherText[i, j];
                }


                for (int j = 0; j < 4; j++)
                {
                    cipherText[i, j] = trrr[j];
                }
            }
            return cipherText;
        }



        readonly byte[,] sbox = new byte[16, 16] {   {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
                                            {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
                                            {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
                                            {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
                                            {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
                                            {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
                                            {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
                                            {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
                                            {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
                                            {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
                                            {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
                                            {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
                                            {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
                                            {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
                                            {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
                                            {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16} };









        static readonly byte[,] sboxInverse = new byte[16, 16] { { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb },
                                                        { 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb },
                                                        { 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e },
                                                        { 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 },
                                                        { 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 },
                                                        { 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 },
                                                        { 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 },
                                                        { 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b },
                                                        { 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 },
                                                        { 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e },
                                                        { 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b },
                                                        { 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 },
                                                        { 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f },
                                                        { 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef },
                                                        { 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 },
                                                        { 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d } };







        byte amb2(byte x)
        {
            byte ret;
            UInt32 temp = Convert.ToUInt32(x << 1);
            ret = (byte)(temp & 0xFF);
            if (x > 127)
                ret = Convert.ToByte(ret ^ 27);
            return ret;
        }
        byte[] shr(byte[] row, int n)
        {
            UInt32 number = 0;
            for (int i = 0; i < 4; i++)
            {

                number += Convert.ToUInt32(row[i]);
                if (i != 3) number = number << 8;
            }
            number = ((number << (n * 8)) | (number) >> (32 - (n * 8)));

            byte[] newRow = new byte[4];
            for (int i = 3; i >= 0; i--)
            {
                newRow[i] = (byte)(number & 0xFF);
                number >>= 8;
            }
            return newRow;
        }
        byte[] Sssss(byte[] row, int n)
        {
            UInt32 number = 0;
            for (int i = 0; i < 4; i++)
            {

                number += Convert.ToUInt32(row[i]);
                if (i != 3) number <<= 8;
            }
            number = ((number >> (n * 8)) | (number) << (32 - (n * 8)));

            byte[] newRow = new byte[4];
            for (int i = 3; i >= 0; i--)
            {
                newRow[i] = (byte)(number & 0xFF);
                number >>= 8;
            }
            return newRow;
        }



        int ri = 0;




        readonly byte[,] rconn = new byte[4, 10] { {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 },
                                         {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                                         {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                                         {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }};



        byte[,] ggg = new byte[4, 4] {  {0x02, 0x03, 0x01, 0x01},
                                                {0x01, 0x02, 0x03, 0x01},
                                                {0x01, 0x01, 0x02, 0x03},
                                                {0x03, 0x01, 0x01, 0x02}};





        readonly byte[,] gf = new byte[4, 4] {   {0x0e, 0x0b, 0x0d, 0x09},
                                                        {0x09, 0x0e, 0x0b, 0x0d},
                                                        {0x0d, 0x09, 0x0e, 0x0b},
                                                        {0x0b, 0x0d, 0x09, 0x0e}};


        readonly byte[,] kp = new byte[44, 4];
        byte[,] Collllllllllllllllllllllll(int c, byte[,] m, string ssssssssssss)
        {



            if (c == 1)
            {

                byte[] aaaaaaaaaaa = new byte[4];
                byte[,] mixCols = new byte[4, 4];
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        for (int k = 0; k < 4; k++)
                        {
                            if (gf[j, k] == 0x9)
                            {
                                byte x0 = m[k, i];
                                byte x1 = amb2(x0);
                                byte x2 = amb2(x1);
                                byte x3 = amb2(x2);
                                aaaaaaaaaaa[k] = Convert.ToByte(x3 ^ x0);
                            }
                            if (gf[j, k] == 0xB)
                            {


                                byte x0 = m[k, i];
                                byte x1 = amb2(x0);
                                byte x2 = amb2(x1);
                                byte x3 = amb2(x2);
                                aaaaaaaaaaa[k] = Convert.ToByte(x3 ^ x0 ^ x1);



                            }
                            if (gf[j, k] == 0xD)
                            {



                                byte x0 = m[k, i];
                                byte x1 = amb2(x0);
                                byte x2 = amb2(x1);
                                byte x3 = amb2(x2);
                                aaaaaaaaaaa[k] = Convert.ToByte(x3 ^ x2 ^ x0);


                            }

                            if (gf[j, k] == 0xE)
                            {


                                byte x0 = m[k, i];
                                byte x1 = amb2(x0);
                                byte x2 = amb2(x1);
                                byte x3 = amb2(x2);
                                aaaaaaaaaaa[k] = Convert.ToByte(x3 ^ x2 ^ x1);

                            }
                        }


                        int cccccccccccccccccccccccccc = aaaaaaaaaaa[0] ^ aaaaaaaaaaa[1] ^ aaaaaaaaaaa[2] ^ aaaaaaaaaaa[3];
                        mixCols[j, i] = Convert.ToByte(cccccccccccccccccccccccccc);
                    }
                }
                return mixCols;
            }
            else if (c == 2)
            {


                byte[] aaaaaaaaaaaa = new byte[4];
                byte[,] mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm = new byte[4, 4];

                int q = 0;
                while (q < 4)
                {
                    int j = 0;
                    while (j < 4)
                    {
                        int k = 0;
                        while (k < 4)
                        {
                            if (ggg[j, k] == 3)
                            {
                                aaaaaaaaaaaa[k] = Convert.ToByte(amb2(m[k, q]) ^ m[k, q]);
                            }

                            if (ggg[j, k] == 1)
                            {
                                aaaaaaaaaaaa[k] = m[k, q];
                            }


                            if (ggg[j, k] == 2)
                            {
                                aaaaaaaaaaaa[k] = amb2(m[k, q]);
                            }





                            k++;
                        }

                        int ccccccccccccccccccccccc = aaaaaaaaaaaa[0] ^ aaaaaaaaaaaa[1] ^ aaaaaaaaaaaa[2] ^ aaaaaaaaaaaa[3];
                        mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm[j, q] = Convert.ToByte(ccccccccccccccccccccccc);

                        j++;
                    }

                    q++;
                }
                return mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm;
            }
            else if (c == 3)
            {



                return m;

            }


            else if (c == 4)
            {


                string tmp;
                int v = 0;
                while (v < 4)
                {
                    int j = 0;
                    while (j < 4)
                    {
                        tmp = Convert.ToString(m[j, v] ^ kp[v, j], 16);
                        m[j, v] = Convert.ToByte(tmp, 16);
                        j++;
                    }
                    v++;
                }

                return m;

            }



            else if (c == 5)
            {

                string t2 = " ";
                int a = 0;
                byte[,] nmnmnm = new byte[4, 4];



                while (a < 4)
                {
                    int j = 0;
                    while (j < 4)
                    {
                        t2 = Convert.ToString(m[a, j], 16);
                        int n1, n2;

                        if (t2.Length == 1)
                        {
                            n1 = 0;
                            n2 = Convert.ToInt32(t2[0].ToString(), 16);
                        }

                        else
                        {
                            n1 = Convert.ToInt32(t2[0].ToString(), 16);
                            n2 = Convert.ToInt32(t2[1].ToString(), 16);
                        }


                        nmnmnm[a, j] = sbox[n1, n2];
                        j++;
                    }


                    a++;
                }

                return nmnmnm;

            }

            else if (c == 6)
            {


                int l = 0;
                byte[,] mmmmmmmmmeeee = new byte[4, 4];
                string tmp3 = " ";


                while (l < 4)
                {
                    int j = 0;
                    while (j < 4)
                    {
                        tmp3 = Convert.ToString(m[l, j], 16);
                        int nn1, nn2;
                        if (tmp3.Length == 1)
                        {
                            nn1 = 0;
                            nn2 = Convert.ToInt32(tmp3[0].ToString(), 16);
                        }
                        else
                        {
                            nn1 = Convert.ToInt32(tmp3[0].ToString(), 16);
                            nn2 = Convert.ToInt32(tmp3[1].ToString(), 16);
                        }

                        mmmmmmmmmeeee[l, j] = sboxInverse[nn1, nn2];

                        j++;
                    }
                    l++;
                }
                return mmmmmmmmmeeee;

            }


            else if (c == 7)
            {

                int e = 0;
                byte[,] nnnnwww = new byte[4, 4];
                byte[] rr = new byte[4];


                while (e < 4)
                {
                    int j = 0;
                    while (j < 4)
                    {
                        rr[j] = m[e, j];
                        j++;
                    }

                    rr = shr(rr, e);

                    j = 0;
                    while (j < 4)
                    {
                        nnnnwww[e, j] = rr[j];
                        j++;
                    }

                    e++;
                }
                return nnnnwww;

            }


            else if (c == 8)
            {

                string tmp4 = " ";
                byte[,] mm = new byte[4, 4];

                int qz = 2;
                for (int j = 0; j < 4; j++)
                {
                    for (int i = 0; i < 4; i++)
                    {
                        tmp4 = "0x" + ssssssssssss[qz] + ssssssssssss[qz + 1];
                        mm[i, j] = Convert.ToByte(tmp4, 16);
                        qz += 2;
                    }
                }
                return mm;

            }

            return null;
        }
        byte[,] Ffff(int bbbb, byte[,] mx)
        {
            switch (bbbb)
            {
                case 1:

                    byte[,] nmmmm = new byte[4, 4];


                    byte[] rr = new byte[4];

                    for (int i = 0; i < 4; i++)
                    {
                        for (int j = 0; j < 4; j++)
                        {
                            rr[j] = mx[i, j];
                        }
                        rr = Sssss(rr, i);
                        for (int j = 0; j < 4; j++)
                        {
                            nmmmm[i, j] = rr[j];
                        }
                    }


                    return nmmmm;

                case 2:
                    mx = Rk(mx, 0);
                    return mx;


                default:
                    break;
            }


            return null;



        }



        byte[,] Fr(byte[,] st)
        {
            st = Rk(st, 10);
            Collllllllllllllllllllllll(3, st, null);

            st = Ffff(1, st);
            Collllllllllllllllllllllll(3, st, null);


            st = Collllllllllllllllllllllll(6, st, null);
            Collllllllllllllllllllllll(3, st, null);

            return st;
        }

        byte[,] R(byte[,] wwwwwww, int round)
        {
            wwwwwww = Rk(wwwwwww, round);



            Collllllllllllllllllllllll(3, wwwwwww, null);



            wwwwwww = Collllllllllllllllllllllll(1, wwwwwww, null);
            Collllllllllllllllllllllll(3, wwwwwww, null);

            wwwwwww = Ffff(1, wwwwwww);


            Collllllllllllllllllllllll(3, wwwwwww, null);


            wwwwwww = Collllllllllllllllllllllll(6, wwwwwww, null);
            Collllllllllllllllllllllll(3, wwwwwww, null);
            return wwwwwww;
        }





        string S(byte[,] matrix)
        {
            StringBuilder str = new StringBuilder();
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    var temp = Convert.ToString(matrix[j, i], 16);
                    if (temp.Length < 2)
                    {
                        str.Append("0" + temp);
                    }
                    else str.Append(temp);
                }
            }
            return str.ToString().ToUpper().Insert(0, "0x");
        }



        byte[,] mk(string str)
        {
            byte[,] mmm = new byte[4, 4];

            int h = 2;
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {

                    string tmp = "0x" + str[h] + str[h + 1];
                    mmm[j, i] = Convert.ToByte(tmp, 16);
                    h += 2;
                }
            }
            return mmm;
        }



        void P_k(string key)
        {
            _ = new byte[4, 4];


            byte[,] key_arr = mk(key);


            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    kp[i, j] = key_arr[i, j];

        }



        byte[] M(int c, byte[] word)
        {


            if (c == 1)
            {
                byte first = word[0];
                for (int i = 0; i < 3; i++)
                    word[i] = word[i + 1];
                word[3] = first;
                return word;
            }


            else if (c == 2)
            {


                byte[] tter = new byte[4];
                int nnn1;
                int nnn2;
                for (int i = 0; i < 4; i++)
                {
                    string tmp = Convert.ToString(word[i], 16);
                    if (tmp.Length == 1)
                    {
                        nnn1 = 0;
                        nnn2 = Convert.ToInt32(tmp[0].ToString(), 16);
                    }
                    else
                    {
                        nnn1 = Convert.ToInt32(tmp[0].ToString(), 16);
                        nnn2 = Convert.ToInt32(tmp[1].ToString(), 16);
                    }
                    tter[i] = sbox[nnn1, nnn2];
                }
                return tter;


            }
            else
            {
                return null;
            }
        }

        byte[] X_or(byte[] first, byte[] second, byte[] third, int is_multiple_of_4)
        {
            byte[] rrrttt = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                string tmp;
                if (is_multiple_of_4 == 0)
                    tmp = Convert.ToString(first[i] ^ second[i], 16);
                else
                    tmp = Convert.ToString(first[i] ^ second[i] ^ third[i], 16);

                rrrttt[i] = Convert.ToByte(tmp, 16);

            }


            return rrrttt;
        }



        byte[,] G_K(int index)
        {
            byte[,] mat = new byte[4, 4];
            int row = 0, col = 0;
            for (int i = index * 4; i < index * 4 + 4; i++)
            {
                col = 0;
                for (int j = 0; j < 4; j++)
                {
                    mat[col, row] = kp[i, j];
                    col++;
                }
                row++;
            }
            return mat;
        }


        byte[,] Rk(byte[,] mmmm, int aa)
        {
            byte[,] k_r;


            k_r = G_K(aa);

            Collllllllllllllllllllllll(3, k_r, null);

            Collllllllllllllllllllllll(3, mmmm, null);
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string tttt = Convert.ToString(k_r[i, j] ^ mmmm[i, j], 16);
                    k_r[i, j] = Convert.ToByte(tttt, 16);
                }
            }
            return k_r;
        }






        void Ik()
        {
            byte[] fff = new byte[4];
            byte[] sss = new byte[4];
            byte[] ttttttttttt = new byte[4];
            _ = new byte[4];
            for (int i = 4; i < 44; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    fff[j] = kp[i - 1, j];
                    sss[j] = kp[i - 4, j];


                    if (ri < 10)
                        ttttttttttt[j] = rconn[j, ri];
                }

                byte[] finalllllllllll;
                if (i % 4 == 0)
                {

                    ri++;
                    fff = M(1, fff);
                    fff = M(2, fff);
                    finalllllllllll = X_or(fff, sss, ttttttttttt, 1);
                }
                else
                    finalllllllllll = X_or(fff, sss, ttttttttttt, 0);

                for (int j = 0; j < 4; j++)
                {

                    kp[i, j] = finalllllllllll[j];
                }

            }
        }










        public override string Decrypt(string cipherText, string key)
        {

            P_k(key);
            Ik();

            byte[,] sssssaaaaaaac = Collllllllllllllllllllllll(8, null, cipherText);

            sssssaaaaaaac = Fr(sssssaaaaaaac);

            Collllllllllllllllllllllll(3, sssssaaaaaaac, null);

            int i = 9;
            do
            {
                sssssaaaaaaac = R(sssssaaaaaaac, i);
                i--;
            } while (i > 0);

            sssssaaaaaaac = Ffff(2, sssssaaaaaaac);


            Collllllllllllllllllllllll(2, sssssaaaaaaac, null);


            return S(sssssaaaaaaac);
        }




        public override string Encrypt(string plainText, string key)
        {
            string[,] p_T = new string[4, 4];
            string[,] k = new string[4, 4];
            int idx = 2;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {


                    p_T[j, i] = (plainText[idx].ToString() + plainText[idx + 1].ToString());
                    k[j, i] = (key[idx].ToString() + key[idx + 1].ToString());
                    idx += 2;


                }
            }




            p_T = xrrt(p_T, k);
            _ = new string[4, 4];
            _ = new string[4, 4];



            for (int i = 1; i <= 9; i++)
            {
                string[,] s = sb(p_T);
                s = Shift_Rows(s);
                s = mc(s);
                string[,] temp_k = grd(k, i - 1);
                for (int d = 0; d < 4; d++)
                {
                    for (int j = 0; j < 4; j++)
                        k[d, j] = temp_k[d, j];
                }
                p_T = xrrt(temp_k, s);
            }


            p_T = xrrt(grd(k, 9), Shift_Rows(sb(p_T)));


            string fmmmm = "";

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    fmmmm += p_T[j, i];
                }
            }
            return "0x" + fmmmm;

        }
    }
}