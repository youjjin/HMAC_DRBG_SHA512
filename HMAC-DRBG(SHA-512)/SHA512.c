#include "HMAC-DRBG(SHA-512).h"
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>

const unsigned long long K512[80] = {
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
void SHA512_Init(SHA512_INFO* Info) {

	Info->uChainVar[0] = 0x6a09e667f3bcc908;
	Info->uChainVar[1] = 0xbb67ae8584caa73b;
	Info->uChainVar[2] = 0x3c6ef372fe94f82b;
	Info->uChainVar[3] = 0xa54ff53a5f1d36f1;
	Info->uChainVar[4] = 0x510e527fade682d1;
	Info->uChainVar[5] = 0x9b05688c2b3e6c1f;
	Info->uChainVar[6] = 0x1f83d9abfb41bd6b;
	Info->uChainVar[7] = 0x5be0cd19137e2179;

	Info->uHighLength = 0;
	Info->uLowLength = 0;
}

void SHA512_Transform(SHA512_INFO* Info, unsigned long long* ChainVar)
{
	unsigned long long	a, b, c, d, e, f, g, h, s0, s1;
	unsigned long long	T1, T2, *W512 = (unsigned long long*)Info->szBuffer;
	int	j;

	for (j = 0; j < 16; j++)
		ENDIAN_REVERSE_ULONG(*ChainVar++, W512[j]);


	a = Info->uChainVar[0];
	b = Info->uChainVar[1];
	c = Info->uChainVar[2];
	d = Info->uChainVar[3];
	e = Info->uChainVar[4];
	f = Info->uChainVar[5];
	g = Info->uChainVar[6];
	h = Info->uChainVar[7];


	j = 0;
	for (j = 0; j < 80; j++)
	{
		if (j >= 16)
			W512[j & 0x0f] += RHO1(W512[(j + 14) & 0x0f]) + W512[(j + 9) & 0x0f] + RHO0(W512[(j + 1) & 0x0f]);

		T1 = h + Sigma1(e) + Ch(e, f, g) + K512[j] + W512[j & 0x0f]; T2 = Sigma0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	Info->uChainVar[0] += a;
	Info->uChainVar[1] += b;
	Info->uChainVar[2] += c;
	Info->uChainVar[3] += d;
	Info->uChainVar[4] += e;
	Info->uChainVar[5] += f;
	Info->uChainVar[6] += g;
	Info->uChainVar[7] += h;
}

void SHA512_Process(SHA512_INFO* Info, unsigned char *pszMessage, unsigned int uDataLen)
{

	while (uDataLen >= SHA512_DIGEST_BLOCKLEN) //데이터 길이가 128보다 크면..
	{
		SHA512_Transform(Info, (unsigned long long*)pszMessage);
		/*************************비트길이check!****************************/
		Info->uLowLength += (unsigned long long)(SHA512_DIGEST_BLOCKLEN << 3); //unsigned int  => unsigned long long
		if (Info->uLowLength < (SHA512_DIGEST_BLOCKLEN << 3))
			Info->uHighLength++;
		/*******************************************************/
		uDataLen -= SHA512_DIGEST_BLOCKLEN;
		pszMessage += SHA512_DIGEST_BLOCKLEN;
	}
	if (uDataLen > 0) {
		memcpy(Info->szBuffer, pszMessage, uDataLen);
		/*************************비트길이check!****************************/
		Info->uLowLength += (unsigned long long)(uDataLen << 3); //unsigned int  => unsigned long long
		if (Info->uLowLength < (uDataLen << 3))
			Info->uHighLength++;
		/*******************************************************/
	}

}

void SHA512_Close(SHA512_INFO* Info, unsigned char* pszDigest)
{
	unsigned long long	*Digest = (unsigned long long*)pszDigest; //64비트로 변환해서 받아줌
	unsigned int index, j;
	unsigned long long* Buffer = (unsigned long long*)Info->szBuffer;

	index = (Info->uLowLength >> 3) % SHA512_DIGEST_BLOCKLEN;

#if defined(LITTLE_ENDIAN)
	ENDIAN_REVERSE_ULONG(Info->uLowLength, Info->uLowLength);
	ENDIAN_REVERSE_ULONG(Info->uHighLength, Info->uHighLength);
#endif
	if (index > 0) {
		Info->szBuffer[index++] = 0x80;

		if (index <= (SHA512_DIGEST_BLOCKLEN - 16)) {
			memset(&Info->szBuffer[index], 0, (SHA512_DIGEST_BLOCKLEN - 16) - index);
		}
		else {
			if (index < SHA512_DIGEST_BLOCKLEN) {
				memset(&Info->szBuffer[index], 0, SHA512_DIGEST_BLOCKLEN - index);
			}
			SHA512_Transform(Info, (unsigned long long*)Info->szBuffer);
			memset(Info->szBuffer, 0, SHA512_DIGEST_BLOCKLEN - 2);
		}
	}
	else {
		memset(Info->szBuffer, 0, (SHA512_DIGEST_BLOCKLEN - 16));

		*Info->szBuffer = 0x80;
	}


	Buffer[(SHA512_DIGEST_BLOCKLEN - 16) / 8] = Info->uHighLength;
	Buffer[(SHA512_DIGEST_BLOCKLEN - 16) / 8 + 1] = Info->uLowLength;

	SHA512_Transform(Info, (unsigned long long*)Info->szBuffer);


#if defined(LITTLE_ENDIAN)
	{
		for (j = 0; j < 8; j++) {
			ENDIAN_REVERSE_ULONG(Info->uChainVar[j], Info->uChainVar[j]);
			*Digest++ = Info->uChainVar[j];
		}
	}
#endif

}

void SHA512(unsigned char *pszMessage, unsigned int uDataLen, unsigned char *pszDigest)
{
	SHA512_INFO info;
	SHA512_Init(&info);
	SHA512_Process(&info, pszMessage, uDataLen);
	SHA512_Close(&info, pszDigest);
}
