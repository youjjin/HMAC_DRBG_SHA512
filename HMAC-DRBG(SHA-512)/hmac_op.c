#include "HMAC-DRBG(SHA-512).h"
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>

const unsigned long long K512_op[80] = {
	0x428a2f98d728ae22, 0x7137449123ef65cd,	0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,	0x3956c25bf348b538,
	0x59f111f1b605d019,	0x923f82a4af194f9b, 0xab1c5ed5da6d8118,	0xd807aa98a3030242, 0x12835b0145706fbe,
	0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,	0x72be5d74f27b896f, 0x80deb1fe3b1696b1,	0x9bdc06a725c71235,
	0xc19bf174cf692694,	0xe49b69c19ef14ad2, 0xefbe4786384f25e3,	0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483,	0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,	0x983e5152ee66dfab,
	0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,	0xc6e00bf33da88fc2, 0xd5a79147930aa725,
	0x06ca6351e003826f, 0x142929670a0e6e70,	0x27b70a8546d22ffc, 0x2e1b21385c26c926,	0x4d2c6dfc5ac42aed,
	0x53380d139d95b3df,	0x650a73548baf63de, 0x766a0abb3c77b2a8,	0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001,	0xc24b8b70d0f89791, 0xc76c51a30654be30,	0xd192e819d6ef5218,
	0xd69906245565a910,	0xf40e35855771202a, 0x106aa07032bbd1b8,	0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
	0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,	0x5b9cca4f7763e373,
	0x682e6ff3d6b2b8a3,	0x748f82ee5defb2fc, 0x78a5636f43172f60,	0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9,	0xbef9a3f7b2c67915, 0xc67178f2e372532b,	0xca273eceea26619c,
	0xd186b8c721c0c207,	0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,	0x06f067aa72176fba, 0x0a637dc5a2c898a6,
	0x113f9804bef90dae, 0x1b710b35131c471b,	0x28db77f523047d84, 0x32caab7b40c72493,	0x3c9ebe0a15c9bebc,
	0x431d67c49c100d4c,	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,	0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

/*** SHA-512: *********************************************************/
void SHA512_Transform_op(SHA512_INFO* Info, unsigned long long* ChainVar)
{
	unsigned long long	a, b, c, d, e, f, g, h, s0, s1;
	unsigned long long	T1, T2, *W512 = (unsigned long long*)Info->szBuffer;
	int	i, j;

	ENDIAN_REVERSE_ULONG(*ChainVar++, W512[0]); ENDIAN_REVERSE_ULONG(*ChainVar++, W512[1]); ENDIAN_REVERSE_ULONG(*ChainVar++, W512[2]); ENDIAN_REVERSE_ULONG(*ChainVar++, W512[3]);
	ENDIAN_REVERSE_ULONG(*ChainVar++, W512[4]); ENDIAN_REVERSE_ULONG(*ChainVar++, W512[5]); ENDIAN_REVERSE_ULONG(*ChainVar++, W512[6]); ENDIAN_REVERSE_ULONG(*ChainVar++, W512[7]);
	ENDIAN_REVERSE_ULONG(*ChainVar++, W512[8]); ENDIAN_REVERSE_ULONG(*ChainVar++, W512[9]); ENDIAN_REVERSE_ULONG(*ChainVar++, W512[10]); ENDIAN_REVERSE_ULONG(*ChainVar++, W512[11]);
	ENDIAN_REVERSE_ULONG(*ChainVar++, W512[12]); ENDIAN_REVERSE_ULONG(*ChainVar++, W512[13]); ENDIAN_REVERSE_ULONG(*ChainVar++, W512[14]); ENDIAN_REVERSE_ULONG(*ChainVar++, W512[15]);

	a = Info->uChainVar[0]; b = Info->uChainVar[1]; c = Info->uChainVar[2]; d = Info->uChainVar[3];
	e = Info->uChainVar[4]; f = Info->uChainVar[5]; g = Info->uChainVar[6]; h = Info->uChainVar[7];

	for (j = 0; j < 16; j++)
	{
		T1 = h + Sigma1(e) + Ch(e, f, g) + K512_op[j] + W512[j & 0x0f]; T2 = Sigma0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	for (j = 16; j < 80; j++)
	{
		W512[j & 0x0f] += RHO1(W512[(j + 14) & 0x0f]) + W512[(j + 9) & 0x0f] + RHO0(W512[(j + 1) & 0x0f]);
		T1 = h + Sigma1(e) + Ch(e, f, g) + K512_op[j] + W512[j & 0x0f]; T2 = Sigma0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	Info->uChainVar[0] += a; Info->uChainVar[1] += b; Info->uChainVar[2] += c; Info->uChainVar[3] += d;
	Info->uChainVar[4] += e; Info->uChainVar[5] += f; Info->uChainVar[6] += g; Info->uChainVar[7] += h;
}

/*Init & Process & Close*/
void SHA512_op(SHA512_INFO* Info, unsigned char *pszMessage, unsigned int uDataLen, unsigned char* pszDigest)
{
	int i;

	/*Init*/
	Info->uChainVar[0] = 0x6a09e667f3bcc908; Info->uChainVar[1] = 0xbb67ae8584caa73b; Info->uChainVar[2] = 0x3c6ef372fe94f82b; Info->uChainVar[3] = 0xa54ff53a5f1d36f1;
	Info->uChainVar[4] = 0x510e527fade682d1; Info->uChainVar[5] = 0x9b05688c2b3e6c1f; Info->uChainVar[6] = 0x1f83d9abfb41bd6b; Info->uChainVar[7] = 0x5be0cd19137e2179;
	Info->uHighLength = Info->uLowLength = 0;

	/*Process*/
	while (uDataLen >= 128)
	{
		SHA512_Transform_op(Info, (unsigned long long*)pszMessage);
		/*************************비트길이check!****************************/
		Info->uLowLength += (unsigned long long)(1024); //unsigned int  => unsigned long long
		if (Info->uLowLength < 1024)
			Info->uHighLength++;
		/*******************************************************/
		uDataLen -= 128;
		pszMessage += 128;
	}
	if (uDataLen > 0) {
		memcpy(Info->szBuffer, pszMessage, uDataLen);

		/*************************비트길이check!****************************/
		Info->uLowLength += (unsigned long long)(uDataLen << 3); //unsigned int  => unsigned long long
		if (Info->uLowLength < (uDataLen << 3))
			Info->uHighLength++;
		/*******************************************************/
	}

	/*Close*/
	unsigned long long	*Digest = (unsigned long long*)pszDigest; //64비트로 변환해서 받아줌
	unsigned long long* Buffer = (unsigned long long*)Info->szBuffer;
	unsigned int index, j;

	index = ((Info->uLowLength >> 3) & 127);

#if defined(LITTLE_ENDIAN)
	ENDIAN_REVERSE_ULONG(Info->uLowLength, Info->uLowLength);
	ENDIAN_REVERSE_ULONG(Info->uHighLength, Info->uHighLength);
#endif
	if (index > 0)
	{
		Info->szBuffer[index++] = 0x80;

		if (index <= 112)
			memset(&Info->szBuffer[index], 0, 112 - index);

		else
		{
			if (index < 128)
				memset(&Info->szBuffer[index], 0, 128 - index);

			SHA512_Transform_op(Info, (unsigned long long*)Info->szBuffer);
			memset(Info->szBuffer, 0, 126);
		}
	}
	else {
		memset(Info->szBuffer, 0, 112);
		*Info->szBuffer = 0x80;
	}


	Buffer[14] = Info->uHighLength; //[(SHA512_DIGEST_BLOCKLEN - 16) / 8]
	Buffer[15] = Info->uLowLength; //[(SHA512_DIGEST_BLOCKLEN - 16) / 8 + 1]
	SHA512_Transform_op(Info, (unsigned long long*)Info->szBuffer);


#if defined(LITTLE_ENDIAN)
	{
		ENDIAN_REVERSE_ULONG(Info->uChainVar[0], Info->uChainVar[0]); *Digest++ = Info->uChainVar[0];
		ENDIAN_REVERSE_ULONG(Info->uChainVar[1], Info->uChainVar[1]); *Digest++ = Info->uChainVar[1];
		ENDIAN_REVERSE_ULONG(Info->uChainVar[2], Info->uChainVar[2]); *Digest++ = Info->uChainVar[2];
		ENDIAN_REVERSE_ULONG(Info->uChainVar[3], Info->uChainVar[3]); *Digest++ = Info->uChainVar[3];
		ENDIAN_REVERSE_ULONG(Info->uChainVar[4], Info->uChainVar[4]); *Digest++ = Info->uChainVar[4];
		ENDIAN_REVERSE_ULONG(Info->uChainVar[5], Info->uChainVar[5]); *Digest++ = Info->uChainVar[5];
		ENDIAN_REVERSE_ULONG(Info->uChainVar[6], Info->uChainVar[6]); *Digest++ = Info->uChainVar[6];
		ENDIAN_REVERSE_ULONG(Info->uChainVar[7], Info->uChainVar[7]); *Digest++ = Info->uChainVar[7];
	}
#endif
}


/*Init & Process & Process & Close*/
void HMAC_SHA512_IPPC(SHA512_INFO* Info, unsigned char *K, unsigned int K_Len, unsigned char *pszMessage, unsigned int uDataLen, unsigned char* pszDigest)
{
	int i;
	/*Init*/
	Info->uChainVar[0] = 0x6a09e667f3bcc908; Info->uChainVar[1] = 0xbb67ae8584caa73b; Info->uChainVar[2] = 0x3c6ef372fe94f82b; Info->uChainVar[3] = 0xa54ff53a5f1d36f1;
	Info->uChainVar[4] = 0x510e527fade682d1; Info->uChainVar[5] = 0x9b05688c2b3e6c1f; Info->uChainVar[6] = 0x1f83d9abfb41bd6b; Info->uChainVar[7] = 0x5be0cd19137e2179;
	Info->uHighLength = Info->uLowLength = 0;

	/*Process-1*/
	while (K_Len >= 128)
	{
		SHA512_Transform_op(Info, (unsigned long long*)K);
		/*************************비트길이check!****************************/
		Info->uLowLength += (unsigned long long)(1024); //unsigned int  => unsigned long long
		if (Info->uLowLength < 1024)
			Info->uHighLength++;
		/*******************************************************/
		K_Len -= 128;
		K += 128;
	}
	if (K_Len > 0) {
		memcpy(Info->szBuffer, K, K_Len);

		/*************************비트길이check!****************************/
		Info->uLowLength += (unsigned long long)(K_Len << 3); //unsigned int  => unsigned long long
		if (Info->uLowLength < (K_Len << 3))
			Info->uHighLength++;
		/*******************************************************/
	}

	/*Process-2*/
	while (uDataLen >= 128)
	{
		SHA512_Transform_op(Info, (unsigned long long*)pszMessage);
		/*************************비트길이check!****************************/
		Info->uLowLength += (unsigned long long)(1024); //unsigned int  => unsigned long long
		if (Info->uLowLength < 1024)
			Info->uHighLength++;
		/*******************************************************/
		uDataLen -= 128;
		pszMessage += 128;
	}
	if (uDataLen > 0) {
		memcpy(Info->szBuffer, pszMessage, uDataLen);
		/*************************비트길이check!****************************/
		Info->uLowLength += (unsigned long long)(uDataLen << 3); //unsigned int  => unsigned long long
		if (Info->uLowLength < (uDataLen << 3))
			Info->uHighLength++;
		/*******************************************************/
	}

	/*Close*/
	unsigned long long	*Digest = (unsigned long long*)pszDigest; //64비트로 변환해서 받아줌
	unsigned long long* Buffer = (unsigned long long*)Info->szBuffer;
	unsigned int index, j;

	index = ((Info->uLowLength >> 3) & 127);

#if defined(LITTLE_ENDIAN)
	ENDIAN_REVERSE_ULONG(Info->uLowLength, Info->uLowLength);
	ENDIAN_REVERSE_ULONG(Info->uHighLength, Info->uHighLength);
#endif
	if (index > 0)
	{
		Info->szBuffer[index++] = 0x80;

		if (index <= 112)
			memset(&Info->szBuffer[index], 0, 112 - index);
		else
		{
			if (index < 128)
				memset(&Info->szBuffer[index], 0, 128 - index);

			SHA512_Transform_op(Info, (unsigned long long*)Info->szBuffer);
			memset(Info->szBuffer, 0, 126);
		}
	}
	else {
		memset(Info->szBuffer, 0, 112);
		*Info->szBuffer = 0x80;
	}


	Buffer[14] = Info->uHighLength; //[(SHA512_DIGEST_BLOCKLEN - 16) / 8]
	Buffer[15] = Info->uLowLength; //[(SHA512_DIGEST_BLOCKLEN - 16) / 8 + 1]
	SHA512_Transform_op(Info, (unsigned long long*)Info->szBuffer);


#if defined(LITTLE_ENDIAN)
	{
		ENDIAN_REVERSE_ULONG(Info->uChainVar[0], Info->uChainVar[0]); *Digest++ = Info->uChainVar[0];
		ENDIAN_REVERSE_ULONG(Info->uChainVar[1], Info->uChainVar[1]); *Digest++ = Info->uChainVar[1];
		ENDIAN_REVERSE_ULONG(Info->uChainVar[2], Info->uChainVar[2]); *Digest++ = Info->uChainVar[2];
		ENDIAN_REVERSE_ULONG(Info->uChainVar[3], Info->uChainVar[3]); *Digest++ = Info->uChainVar[3];
		ENDIAN_REVERSE_ULONG(Info->uChainVar[4], Info->uChainVar[4]); *Digest++ = Info->uChainVar[4];
		ENDIAN_REVERSE_ULONG(Info->uChainVar[5], Info->uChainVar[5]); *Digest++ = Info->uChainVar[5];
		ENDIAN_REVERSE_ULONG(Info->uChainVar[6], Info->uChainVar[6]); *Digest++ = Info->uChainVar[6];
		ENDIAN_REVERSE_ULONG(Info->uChainVar[7], Info->uChainVar[7]); *Digest++ = Info->uChainVar[7];
	}
#endif

}


void HMAC_SHA512_op(unsigned char *pszMessage, unsigned int uPlainTextLen, unsigned char *mac, unsigned char *key, unsigned int keyLen)
{
	SHA512_INFO info;
	unsigned int cnt_i, updatedKeyLen = 0, i;
	unsigned char K0[128] = { 0x00, };
	unsigned char K1[128] = { 0x00 };
	unsigned char K2[128] = { 0x00 };
	unsigned char firstOut[64] = { 0x00 };

	/*Padding*/
	if (keyLen > 128)
	{
		SHA512_op(&info, key, keyLen, K0, updatedKeyLen);
		updatedKeyLen = 64;
	}
	else
	{
		memcpy(K0, key, keyLen);
		updatedKeyLen = keyLen;
	}

	/*Key Expanding*/
	for (i = 0; i < 128; i++)
	{
		K1[i] = 0x36;
		K2[i] = 0x5c;
	}

	for (cnt_i = 0; cnt_i < updatedKeyLen; cnt_i++)
	{
		K1[cnt_i] = 0x36 ^ K0[cnt_i];
		K2[cnt_i] = 0x5c ^ K0[cnt_i];
	}

	/*Hash(K' xor I_PAD) | M*/
	HMAC_SHA512_IPPC(&info, K1, sizeof(K1), pszMessage, uPlainTextLen, firstOut);

	/*Hash((K' xor O_PAD | Hash(K' xor I_PAD) | M))*/
	HMAC_SHA512_IPPC(&info, K2, sizeof(K2), firstOut, sizeof(firstOut), mac);

}
