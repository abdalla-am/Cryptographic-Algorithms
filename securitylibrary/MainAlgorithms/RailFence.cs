using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)         
        {
            int key = 2;
            for (int i = 1; i < 10; i++)
            {
                if (this.Encrypt(plainText, i).ToUpper() == cipherText)
                {
                    key = i;
                    break;
                }
            }
            return key;

          
        }




        public string Decrypt(string cipherText, int key)
        {

            //we write the plaintext column wise (consider the depth) and read it row wise

            int counter = 0;
            string cText = cipherText.ToLower();
            String plainText = "";

            double plaintext_lenght = (double)cText.Length / key;
            int plaintext_lenght_converted_to_int = (int)Math.Ceiling(plaintext_lenght);


            //create a two dimentional array (table)  (key---> row)   (plaintext_lenght_converted_to_int --->column)
            char[,] matrix = new char[key, plaintext_lenght_converted_to_int];


            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < plaintext_lenght_converted_to_int; j++)
                {
                    if (counter < cText.Length)
                    {
                        matrix[i, j] = cText[counter];
                        counter++;
                    }
                }
            }
            for (int i = 0; i < plaintext_lenght_converted_to_int; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (matrix[j, i] != '\0')
                    {
                        plainText = plainText + matrix[j, i];
                    }
                }
            }
            return plainText;


        }





        public string Encrypt(string plainText, int key)
        {



            //we write the plaintext column wise (consider the depth) and read it row wise

            int counter = 0;
            string pText = plainText.ToUpper();
            String cipherText = "";

            double x = (double)pText.Length / key;
            int cipherText_lenght_converted_to_int = (int)Math.Ceiling(x);


            char[,] matrix = new char[key, cipherText_lenght_converted_to_int];



            for (int i = 0; i < cipherText_lenght_converted_to_int; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (counter < pText.Length)
                    {
                        matrix[j, i] = pText[counter];
                        counter++;
                    }

                }
            }
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < cipherText_lenght_converted_to_int; j++)
                {
                    if (matrix[i, j] != '\0')
                    {
                        cipherText = cipherText + matrix[i, j];
                    }
                }
            }
            return cipherText;
        }
    }
}
