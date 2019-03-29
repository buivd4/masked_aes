#ifndef _AES_H
#define _AES_H

// OverView Function Encrypt
void Encrypt(unsigned char *in,unsigned char *key,unsigned char *out,unsigned char *mask);
void Expankey(unsigned char *,unsigned char *);
void SubBytes(unsigned char *,unsigned char*);
void AddRoundKey(unsigned char *state,unsigned char *expkey,unsigned char n);
void MixColumns(unsigned char *state);
void ShiftRows(unsigned char *state);
unsigned char Sbox(unsigned char ,unsigned char );
void Xor(unsigned char* ,unsigned char* );
void Randomize(unsigned char* );
void Clone(unsigned char* ,unsigned char* );
unsigned char MultiplyGF2(unsigned char a,unsigned char b);
unsigned char Inversion(unsigned char a);
unsigned char Affine(unsigned char a);
unsigned char Affine_modife(unsigned char a);
#endif
