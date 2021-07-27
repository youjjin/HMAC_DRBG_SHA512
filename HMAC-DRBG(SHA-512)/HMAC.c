#include "HMAC-DRBG(SHA-512).h"
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>


void HMAC_SHA512(unsigned char *pszMessage, unsigned int uPlainTextLen, unsigned char *mac, unsigned char *key, unsigned int keyLen)
{
	SHA512_INFO info;
	unsigned int cnt_i, updatedKeyLen = 0;
	unsigned char K0[128] = { 0x00, }; //128byte = 1024bit
	unsigned char K1[SHA512_DIGEST_BLOCKLEN] = { 0x00 };
	unsigned char K2[SHA512_DIGEST_BLOCKLEN] = { 0x00 };
	unsigned char firstOut[SHA512_DIGEST_VALUELEN] = { 0x00 };

	/*Padding*/
	if (keyLen > SHA512_DIGEST_BLOCKLEN)
	{
		SHA512_Init(&info);
		SHA512_Process(&info, key, keyLen);
		SHA512_Close(&info, K0);
		updatedKeyLen = SHA512_DIGEST_VALUELEN;
	}

	else
	{
		memcpy(K0, key, keyLen);
		updatedKeyLen = keyLen;
	}

	/*Key Expanding*/
	memset(K1, I_PAD, 128);
	memset(K2, O_PAD, 128);

	for (cnt_i = 0; cnt_i < updatedKeyLen; cnt_i++)
	{
		K1[cnt_i] = I_PAD ^ K0[cnt_i];
		K2[cnt_i] = O_PAD ^ K0[cnt_i];
	}

	/*Hash(K' xor I_PAD) | M*/
	SHA512_Init(&info);
	SHA512_Process(&info, K1, sizeof(K1));
	SHA512_Process(&info, pszMessage, uPlainTextLen);
	SHA512_Close(&info, firstOut);

	/*Hash((K' xor O_PAD | Hash(K' xor I_PAD) | M))*/
	SHA512_Init(&info);
	SHA512_Process(&info, K2, sizeof(K2));
	SHA512_Process(&info, firstOut, sizeof(firstOut));
	SHA512_Close(&info, mac);

}