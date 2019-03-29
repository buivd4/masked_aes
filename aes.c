#include <stdlib.h>
#include <stdio.h>
#include "aes.h"
unsigned char rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};




void Expankey(unsigned char *key,unsigned char *expkey)
{
    unsigned char j,i;
    for (j=0;j<16;j++)
    {
        expkey[j] = key[j];
    }

    for (i=1;i<11;i++)
    {
        for(j=0;j<16;j++)
        {
            if (j>=0&&j<4) {
                if (j==3) {
                    expkey[i*16+j] = Sbox(expkey[i*16+j-7],0);
                } else {
                    expkey[i*16+j] = Sbox(expkey[i*16+j-3],0);
                }
                if (j==0) expkey[i*16+j] ^= expkey[i*16+j-16] ^ rcon[i-1];
                else    expkey[i*16+j] ^= expkey[i*16+j-16];
            } else {
                expkey[i*16+j] = expkey[i*16+j-4] ^ expkey[i*16+j-16];
            }
        }
    }
}

void AddRoundKey(unsigned char *state,unsigned char *expkey,unsigned char n)
{
    unsigned char i;
    for (i=0;i<16;i++){
        state[i] ^= expkey[n-16+i];
    }
}

// Begin function Encrypt
void Encrypt(unsigned char *in,unsigned char *key,unsigned char *out,unsigned char *mask)
{
    unsigned char expkey[176],i,j;
    unsigned char state[16];
    unsigned char temp[16];
    for (i=0;i<16;i++) state[i] = in[i];
    Expankey(key,expkey);
    Xor(state,mask);
    AddRoundKey(state,expkey,16);
    for (i=2;i<11;i++)
    {
        Clone(mask,temp);
        SubBytes(state,mask);
        for(j=0;j<16;j++) temp[j] = Affine_modife(temp[j]);
        ShiftRows(state);
        ShiftRows(temp);
        MixColumns(temp);
        MixColumns(state);
        AddRoundKey(state,expkey,i*16);
        Xor(state,temp);
        Xor(state,mask);
    }
    Clone(mask,temp);
    SubBytes(state,mask);
    for(j=0;j<16;j++) temp[j]=Affine_modife(temp[j]);
    ShiftRows(state);
    ShiftRows(temp);
    AddRoundKey(state,expkey,i*16);
    Xor(state,temp);
    for (i=0;i<16;i++)
        out[i] = state[i];
}

void SubBytes(unsigned char *state,unsigned char *mask) {
    unsigned char i;
    for (i = 0; i < 16; i++) {
        state[i] = Sbox(state[i], mask[i]);
    }
}
unsigned char MultiplyGF2(unsigned char a,unsigned char b)  {
    unsigned char p = 0; unsigned char counter = 0;   
    char hi_bit_set='';
    for (counter = 0; counter < 8; counter++) {
        if ((b & 1) != 0) {
            p ^= a;
        }

         hi_bit_set = (a & 0x80) != 0;
        a <<= 1;
        if (hi_bit_set!=0) {
            a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
        }
        b >>= 1;
    }
    return p;
}

unsigned char Inversion(unsigned char a){
    int i;
    unsigned char temp=a;
    for(i=0;i<253;i++){
        temp=MultiplyGF2(a,temp);
    }
    return temp;
}

unsigned char Affine(unsigned char a){
    unsigned char row=0,sum=0,result=0,t=0;
    int i,j;
    for(i=0;i<8;i++){
        sum=0;
        row = (0xF1 << i | 0xF1 >> (8 - i));
        t = row & a;
        for (j=0;j<8;j++)
            sum ^= (t >> j) & 0x1;
        result |= sum << i;
    }
    return result ^ 0x63;
}

unsigned char Affine_modife(unsigned char a){
    unsigned char row=0,sum=0,result=0,t=0;
    int i,j;
    for(i=0;i<8;i++){
        sum=0;
        row = (0xF1 << i | 0xF1 >> (8 - i));
        t = row & a;
        for (j=0;j<8;j++)
            sum ^= (t >> j) & 0x1;
        result |= sum << i;
    }
    return result;
}



unsigned char Sbox(unsigned char block,unsigned char mask)   {
    unsigned char y=(rand()%255)+1;
    block=MultiplyGF2(block,y);
    block=block^MultiplyGF2(mask,y);
    block=Inversion(block);
    block=block^MultiplyGF2(mask,Inversion(y));
    block=MultiplyGF2(block,y);
    return Affine(block);
}


void MixColumns(unsigned char *state)
{
    unsigned char a[16];
    unsigned char b[16];
    unsigned char c;
    unsigned char h;
    /* The array 'a' is simply a copy of the input array 'r'
     * The array 'b' is each element of the array 'a' multiplied by 2
     * in Rijndael's Galois field
     * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */
    for (c = 0; c < 16; c++) {
        a[c] = state[c];
        /* h is 0xff if the high bit of r[c] is set, 0 otherwise */
        h = (unsigned char)((signed char)state[c] >> 7); /* arithmetic right shift, thus shifting in either zeros or ones */
        b[c] = state[c] << 1; /* implicitly removes high bit because b[c] is an 8-bit char, so we xor by 0x1b and not 0x11b in the next line */
        b[c] ^= 0x1B & h; /* Rijndael's Galois field */
    }

    state[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; /* 2 * a0 + a3 + a2 + 3 * a1 */
    state[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; /* 2 * a1 + a0 + a3 + 3 * a2 */
    state[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; /* 2 * a2 + a1 + a0 + 3 * a3 */
    state[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; /* 2 * a3 + a2 + a1 + 3 * a0 */

    state[4] = b[4] ^ a[7] ^ a[6] ^ b[5] ^ a[5];
    state[5] = b[5] ^ a[4] ^ a[7] ^ b[6] ^ a[6];
    state[6] = b[6] ^ a[5] ^ a[4] ^ b[7] ^ a[7];
    state[7] = b[7] ^ a[6] ^ a[5] ^ b[4] ^ a[4];

    state[8] = b[8] ^ a[11] ^ a[10] ^ b[9] ^ a[9];
    state[9] = b[9] ^ a[8] ^ a[11] ^ b[10] ^ a[10];
    state[10] = b[10] ^ a[9] ^ a[8] ^ b[11] ^ a[11];
    state[11] = b[11] ^ a[10] ^ a[9] ^ b[8] ^ a[8];

    state[12] = b[12] ^ a[15] ^ a[14] ^ b[13] ^ a[13];
    state[13] = b[13] ^ a[12] ^ a[15] ^ b[14] ^ a[14];
    state[14] = b[14] ^ a[13] ^ a[12] ^ b[15] ^ a[15];
    state[15] = b[15] ^ a[14] ^ a[13] ^ b[12] ^ a[12];

}

void ShiftRows(unsigned char *state)
{
    unsigned char tmp[16],i;

    for (i=0;i<16;i++)
        tmp[i]=state[i];

    state[0]=tmp[0];
    state[1]=tmp[5];
    state[2]=tmp[10];
    state[3]=tmp[15];

    state[4]=tmp[4];
    state[5]=tmp[9];
    state[6]=tmp[14];
    state[7]=tmp[3];

    state[8]=tmp[8];
    state[9]=tmp[13];
    state[10]=tmp[2];
    state[11]=tmp[7];

    state[12]=tmp[12];
    state[13]=tmp[1];
    state[14]=tmp[6];
    state[15]=tmp[11];
}

void Xor(unsigned char* plaint,unsigned char* mask){
    int i;
    for( i=0;i<16;i++){
        plaint[i]^=mask[i];
    }
}

void Randomize(unsigned char* a)
{
    int i;
    for( i=0;i<16;i++){
        a[i]=rand();
    }
}
void Clone(unsigned char* mask,unsigned char* temp)
{
    int i;
    for( i=0;i<16;i++){
        temp[i]=mask[i];
    }
}
