using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
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
        public string Encrypt(string plainText, int key)
        {

            string cipherText = null;
            for (int i = 0; i < plainText.Length; i++)
            {
                int CIndex = (key + Letterind(plainText[i])) % 26;
                cipherText += (alphabet[CIndex]);
            }
            return cipherText.ToUpper();

        }
        public string Decrypt(string cipherText, int key)
        {

            cipherText = cipherText.ToLower();
            string plainText = null;
            for (int i = 0; i < cipherText.Length; i++)
            {
                int PIndx = ((Letterind(cipherText[i]) - key) % 26);
                if (PIndx < 0)
                {
                    PIndx += 26;
                }
                plainText += alphabet[PIndx];
            }
            return plainText.ToLower();

        }
        public int Analyse(string plainText, string cipherText)
        {

            int letterPIn = 0;
            int letterCIn = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                letterPIn = Letterind(plainText[i]);
                letterCIn = Letterind(char.ToLower(cipherText[i]));
            }
            if ((letterCIn - letterPIn) < 0)
            {
                int m = ((letterCIn - letterPIn) + 26) % 26;
                return m;
            }
            else
            {
                int x = (letterCIn - letterPIn) % 26;
                return x;
            }
        }

    }
}