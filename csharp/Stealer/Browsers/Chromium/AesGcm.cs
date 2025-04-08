using System;

namespace YandexDecryptor.Stealer.Browsers.Chromium
{
    public class AesGcm
    {
        private static readonly byte[] SBox = new byte[256]
        {
            // Standard AES S-box values
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
            0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
            0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
            0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
            0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
            0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
            0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
            0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
            0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
            0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
            0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
            0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
            0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
            0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
            0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
            0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
            0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        };

        private static readonly byte[] Rcon = new byte[256]
        {
            0x00, // Rcon[0] is never used
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
            0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F,
            0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4,
            0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39, 0x72,
            0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25, 0x4A,
            0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A, 0x74,
            0xE8, 0xCB, 0x8D, 0x01, // The rest are zeros
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00,
        };

        private byte[] Key;
        private byte[,] RoundKeys;

        public AesGcm(byte[] key)
        {
            if (key.Length != 32) // 256 bits
                throw new ArgumentException("Key length must be 256 bits.");

            Key = new byte[32];
            Array.Copy(key, Key, 32);

            KeyExpansion();
        }

        public static byte[] Decrypt(byte[] key, byte[] iv, byte[] aad, byte[] cipherText, byte[] authTag)
        {
            return new AesGcm(key).Decrypt(cipherText, authTag, iv, aad);
        }

        private void KeyExpansion()
        {
            int Nk = 8; // Number of 32-bit words comprising the Cipher Key
            int Nb = 4; // Number of columns (32-bit words) comprising the State
            int Nr = 14; // Number of rounds

            RoundKeys = new byte[Nb * (Nr + 1), 4];

            for (int i = 0; i < Nk; i++)
            {
                RoundKeys[i, 0] = Key[4 * i];
                RoundKeys[i, 1] = Key[4 * i + 1];
                RoundKeys[i, 2] = Key[4 * i + 2];
                RoundKeys[i, 3] = Key[4 * i + 3];
            }

            byte[] temp = new byte[4];

            for (int i = Nk; i < Nb * (Nr + 1); i++)
            {
                temp[0] = RoundKeys[i - 1, 0];
                temp[1] = RoundKeys[i - 1, 1];
                temp[2] = RoundKeys[i - 1, 2];
                temp[3] = RoundKeys[i - 1, 3];

                if (i % Nk == 0)
                {
                    // RotWord
                    byte t = temp[0];
                    temp[0] = temp[1];
                    temp[1] = temp[2];
                    temp[2] = temp[3];
                    temp[3] = t;

                    // SubWord
                    temp[0] = SBox[temp[0]];
                    temp[1] = SBox[temp[1]];
                    temp[2] = SBox[temp[2]];
                    temp[3] = SBox[temp[3]];

                    // XOR with Rcon
                    temp[0] ^= Rcon[i / Nk];
                }
                else if (Nk > 6 && i % Nk == 4)
                {
                    // SubWord
                    temp[0] = SBox[temp[0]];
                    temp[1] = SBox[temp[1]];
                    temp[2] = SBox[temp[2]];
                    temp[3] = SBox[temp[3]];
                }

                RoundKeys[i, 0] = (byte)(RoundKeys[i - Nk, 0] ^ temp[0]);
                RoundKeys[i, 1] = (byte)(RoundKeys[i - Nk, 1] ^ temp[1]);
                RoundKeys[i, 2] = (byte)(RoundKeys[i - Nk, 2] ^ temp[2]);
                RoundKeys[i, 3] = (byte)(RoundKeys[i - Nk, 3] ^ temp[3]);
            }
        }

        private void AddRoundKey(byte[,] state, int round)
        {
            for (int c = 0; c < 4; c++)
            {
                for (int r = 0; r < 4; r++)
                {
                    state[r, c] ^= RoundKeys[round * 4 + c, r];
                }
            }
        }

        private void SubBytes(byte[,] state)
        {
            for (int r = 0; r < 4; r++)
            {
                for (int c = 0; c < 4; c++)
                {
                    state[r, c] = SBox[state[r, c]];
                }
            }
        }

        private void ShiftRows(byte[,] state)
        {
            byte temp;

            // Row 1 shift (left circular shift by 1)
            temp = state[1, 0];
            state[1, 0] = state[1, 1];
            state[1, 1] = state[1, 2];
            state[1, 2] = state[1, 3];
            state[1, 3] = temp;

            // Row 2 shift (left circular shift by 2)
            temp = state[2, 0];
            state[2, 0] = state[2, 2];
            state[2, 2] = temp;
            temp = state[2, 1];
            state[2, 1] = state[2, 3];
            state[2, 3] = temp;

            // Row 3 shift (left circular shift by 3)
            temp = state[3, 3];
            state[3, 3] = state[3, 2];
            state[3, 2] = state[3, 1];
            state[3, 1] = state[3, 0];
            state[3, 0] = temp;
        }

        private void MixColumns(byte[,] state)
        {
            byte[] temp = new byte[4];

            for (int c = 0; c < 4; c++)
            {
                temp[0] = (byte)(GFMultiply(0x02, state[0, c]) ^ GFMultiply(0x03, state[1, c]) ^ state[2, c] ^ state[3, c]);
                temp[1] = (byte)(state[0, c] ^ GFMultiply(0x02, state[1, c]) ^ GFMultiply(0x03, state[2, c]) ^ state[3, c]);
                temp[2] = (byte)(state[0, c] ^ state[1, c] ^ GFMultiply(0x02, state[2, c]) ^ GFMultiply(0x03, state[3, c]));
                temp[3] = (byte)(GFMultiply(0x03, state[0, c]) ^ state[1, c] ^ state[2, c] ^ GFMultiply(0x02, state[3, c]));

                state[0, c] = temp[0];
                state[1, c] = temp[1];
                state[2, c] = temp[2];
                state[3, c] = temp[3];
            }
        }

        private byte GFMultiply(byte a, byte b)
        {
            byte p = 0;
            for (int i = 0; i < 8; i++)
            {
                if ((b & 1) != 0)
                    p ^= a;

                bool hiBitSet = (a & 0x80) != 0;
                a <<= 1;
                if (hiBitSet)
                    a ^= 0x1B; // x^8 + x^4 + x^3 + x + 1

                b >>= 1;
            }
            return p;
        }

        private void EncryptBlock(byte[] input, byte[] output)
        {
            int Nb = 4;
            int Nr = 14;

            byte[,] state = new byte[4, Nb];

            for (int i = 0; i < 16; i++)
            {
                state[i % 4, i / 4] = input[i];
            }

            AddRoundKey(state, 0);

            for (int round = 1; round <= Nr - 1; round++)
            {
                SubBytes(state);
                ShiftRows(state);
                MixColumns(state);
                AddRoundKey(state, round);
            }

            SubBytes(state);
            ShiftRows(state);
            AddRoundKey(state, Nr);

            for (int i = 0; i < 16; i++)
            {
                output[i] = state[i % 4, i / 4];
            }
        }

        private byte[] GF128Multiply(byte[] X, byte[] Y)
        {
            byte[] Z = new byte[16];
            byte[] V = new byte[16];
            Array.Copy(Y, V, 16);

            for (int i = 0; i < 128; i++)
            {
                int bit = (X[i / 8] >> (7 - (i % 8))) & 1;
                if (bit == 1)
                {
                    for (int j = 0; j < 16; j++)
                        Z[j] ^= V[j];
                }

                bool lsb = (V[15] & 1) == 1;
                for (int j = 15; j >= 0; j--)
                {
                    V[j] = (byte)((V[j] >> 1) | ((j > 0 ? V[j - 1] : 0) << 7));
                }
                if (lsb)
                {
                    V[0] ^= 0xE1;
                }
            }
            return Z;
        }

        private byte[] GHASH(byte[] H, byte[] A, byte[] C)
        {
            int totalLength = ((A.Length + 15) / 16 + (C.Length + 15) / 16) * 16;
            byte[] Y = new byte[16];
            byte[] X = new byte[16];
            byte[] block = new byte[16];

            int pos = 0;
            while (pos < A.Length)
            {
                Array.Clear(block, 0, 16);
                int len = Math.Min(16, A.Length - pos);
                Array.Copy(A, pos, block, 0, len);

                for (int i = 0; i < 16; i++)
                    X[i] = (byte)(Y[i] ^ block[i]);

                Y = GF128Multiply(X, H);
                pos += len;
            }

            pos = 0;
            while (pos < C.Length)
            {
                Array.Clear(block, 0, 16);
                int len = Math.Min(16, C.Length - pos);
                Array.Copy(C, pos, block, 0, len);

                for (int i = 0; i < 16; i++)
                    X[i] = (byte)(Y[i] ^ block[i]);

                Y = GF128Multiply(X, H);
                pos += len;
            }

            byte[] lenBlock = new byte[16];
            ulong bitLengthA = (ulong)A.Length * 8;
            ulong bitLengthC = (ulong)C.Length * 8;

            for (int i = 0; i < 8; i++)
            {
                lenBlock[7 - i] = (byte)(bitLengthA >> (i * 8));
                lenBlock[15 - i] = (byte)(bitLengthC >> (i * 8));
            }

            for (int i = 0; i < 16; i++)
                X[i] = (byte)(Y[i] ^ lenBlock[i]);

            Y = GF128Multiply(X, H);

            return Y;
        }

       /* public byte[] Encrypt(byte[] plaintext, byte[] iv, byte[] aad = null)
        {

            if (aad == null)
                aad = new byte[0];

            byte[] H = new byte[16];
            EncryptBlock(new byte[16], H);

            byte[] J0 = new byte[16];
            if (iv.Length == 12)
            {
                Array.Copy(iv, J0, 12);
                J0[15] = 0x01;
            }
            else
            {
                // Handle IVs not equal to 96 bits
                J0 = GHASH(H, new byte[0], iv);
            }

            int n = (plaintext.Length + 15) / 16;
            byte[] ciphertext = new byte[plaintext.Length];

            for (int i = 1; i <= n; i++)
            {
                byte[] counterBlock = new byte[16];
                Array.Copy(J0, counterBlock, 16);

                // Increment counter
                ulong ctr = (ulong)i;
                for (int j = 15; j >= 12; j--)
                {
                    counterBlock[j] ^= (byte)(ctr & 0xFF);
                    ctr >>= 8;
                }

                byte[] encryptedCounterBlock = new byte[16];
                EncryptBlock(counterBlock, encryptedCounterBlock);

                int blockSize = (i != n) ? 16 : (plaintext.Length % 16 == 0 ? 16 : plaintext.Length % 16);
                for (int j = 0; j < blockSize; j++)
                {
                    ciphertext[(i - 1) * 16 + j] = (byte)(plaintext[(i - 1) * 16 + j] ^ encryptedCounterBlock[j]);
                }
            }

            byte[] tag = GHASH(H, aad, ciphertext);

            byte[] tagEncrypted = new byte[16];
            byte[] counterBlockTag = new byte[16];
            Array.Copy(J0, counterBlockTag, 16);

            counterBlockTag[15] ^= 0x01;
            EncryptBlock(counterBlockTag, tagEncrypted);

            for (int i = 0; i < 16; i++)
                tag[i] ^= tagEncrypted[i];

            byte[] result = new byte[ciphertext.Length + 16];
            Array.Copy(ciphertext, 0, result, 0, ciphertext.Length);
            Array.Copy(tag, 0, result, ciphertext.Length, 16);

            return result;
        }*/

        private void IncrementCounter(byte[] counterBlock)
        {
            for (int i = 15; i >= 12; i--)
            {
                if (++counterBlock[i] != 0)
                    break;
            }
        }

        public byte[] Decrypt(byte[] ciphertext, byte[] tag, byte[] iv, byte[] aad)
        {
            if (aad == null)
                aad = new byte[0];

            byte[] H = new byte[16];
            EncryptBlock(new byte[16], H);

            byte[] J0 = new byte[16];
            if (iv.Length == 12)
            {
                Array.Copy(iv, 0, J0, 0, 12);
                J0[15] = 0x01;
            }
            else
            {
                J0 = GHASH(H, null, iv);
            }

            byte[] plaintext = new byte[ciphertext.Length];
            byte[] counterBlock = new byte[16];
            Array.Copy(J0, counterBlock, 16);

            int fullBlocks = ciphertext.Length / 16;
            int lastBlockSize = ciphertext.Length % 16;
            int n = lastBlockSize == 0 ? fullBlocks : fullBlocks + 1;

            for (int i = 0; i < n; i++)
            {
                IncrementCounter(counterBlock);

                byte[] encryptedCounterBlock = new byte[16];
                EncryptBlock(counterBlock, encryptedCounterBlock);

                int blockSize = (i < fullBlocks) ? 16 : lastBlockSize;
                for (int j = 0; j < blockSize; j++)
                {
                    plaintext[i * 16 + j] = (byte)(ciphertext[i * 16 + j] ^ encryptedCounterBlock[j]);
                }
            }

            byte[] tagInput = GHASH(H, aad, ciphertext);

            byte[] encryptedJ0 = new byte[16];
            EncryptBlock(J0, encryptedJ0);

            byte[] recomputedTag = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                recomputedTag[i] = (byte)(encryptedJ0[i] ^ tagInput[i]);
            }

            if (!VerifyTag(tag, recomputedTag))
                throw new Exception("Authentication tag does not match. Decryption failed.");

            return plaintext;
        }

        private bool VerifyTag(byte[] tag1, byte[] tag2)
        {
            if (tag1.Length != tag2.Length) return false;
            int result = 0;
            for (int i = 0; i < tag1.Length; i++)
            {
                result |= tag1[i] ^ tag2[i];
            }
            return result == 0;
        }
    }
}
