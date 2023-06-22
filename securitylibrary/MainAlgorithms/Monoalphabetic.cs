using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        int get_char_position(char letter)
        {
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            for (int i = 0; i < 26; i++)
            {
                if (letter == alphabet[i])
                    return i;
            }
            return 0;
        }

        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            plainText = plainText.Replace(" ", String.Empty);
            cipherText = cipherText.ToLower();
            char[] letters = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            StringBuilder key = new StringBuilder("                          ");

            for (int i = 0; i < plainText.Length; i++)
            {
                key[get_char_position(plainText[i])] = cipherText[i];
                letters[get_char_position(cipherText[i])] = '0';
            }
            for (int i = 0; i < 26; i++)                 //after there is no more letters in the plain text , the rest of the letters is put in the key string(arr of key chars) by this nested loop 
            {
                for (int j = 0; j < key.Length; j++)
                {
                    if (key[j] == ' ' && letters[i] != '0')
                    {
                        key[j] = letters[i];
                        letters[i] = '0';
                        break;
                    }
                }
            }
            return key.ToString();
        }
        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            string plainText = "";
            string letters = "abcdefghijklmnopqrstuvwxyz";

            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < key.Length; j++)
                {
                    if (key[j] == cipherText[i])
                    {
                        plainText += letters[j];
                        break;
                    }
                }
            }
            return plainText;
        }
        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();
            key = key.ToLower();
            string cipherText = "";
            string letters = "abcdefghijklmnopqrstuvwxyz";

            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < key.Length; j++)
                {
                    if (plainText[i] == letters[j])
                    {
                        cipherText += key[j];
                    }
                }
            }
            return cipherText;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            string alphabetFreq = "ETAOINSRHLDCUMFPGWYBVKXJQZ".ToLower();
            Dictionary<char, int> phaFreq = new Dictionary<char, int>();
            SortedList<char, char> ktable = new SortedList<char, char>();
            string key = null;
            for (int i = 0; i < cipher.Length; i++)
            {
                if (phaFreq.ContainsKey(cipher[i]))
                {
                    phaFreq[cipher[i]]++;
                }
                else
                {
                    phaFreq.Add(cipher[i], 0);
                }
            }
            phaFreq = phaFreq.OrderBy(x => x.Value).Reverse().ToDictionary(x => x.Key, x => x.Value);
            int c = 0;
            foreach (var item in phaFreq)
            {
                ktable.Add(item.Key, alphabetFreq[c]);
                c++;
            }

            for (int i = 0; i < cipher.Length; i++)
            {
                key += ktable[cipher[i]];
            }
            return key;
        }
    }
}