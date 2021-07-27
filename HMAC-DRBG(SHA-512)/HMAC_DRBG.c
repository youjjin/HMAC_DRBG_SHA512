#include "HMAC-DRBG(SHA-512).h"
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <math.h>


/*인스턴스 생성함수*/
void Instantiaite_Function(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* nonce, unsigned int nonce_len, unsigned char* personalization, unsigned int personalization_len)
{
	int len = entropy_len + nonce_len + personalization_len;
	unsigned char* seed_material = (unsigned char*)calloc(len, sizeof(unsigned char));
	unsigned char temp[112] = { 0x00, };
	int i;

	for (i = 0; i < entropy_len; i++)
		seed_material[i] = entropy[i];

	for (i = entropy_len; i < entropy_len + nonce_len; i++)
		seed_material[i] = nonce[i - entropy_len];

	for (i = entropy_len + nonce_len; i < entropy_len + nonce_len + personalization_len; i++)
		seed_material[i] = personalization[i - (entropy_len + nonce_len)];

	for (i = 0; i < 64; i++)
		state->state_handle.Key[i] = 0x00;
	for (i = 0; i < 64; i++)
		state->state_handle.V[i] = 0x01;

	HMAC_DRBG_Update(state, seed_material, len);

	state->state_handle.reseed_counter = 1;

	free(seed_material);

}


/*내부갱신함수*/
void HMAC_DRBG_Update(STATE* state, unsigned char* additional, unsigned int additional_len)
{
	int i;
	int len = 65 + additional_len;
	unsigned char key[64] = { 0, };
	unsigned char v[64] = { 0, };
	unsigned char* temp = (unsigned char*)calloc(len, sizeof(unsigned char));
	unsigned char V[64] = { 0x00, };
	memcpy(V, state->state_handle.V, 64);

	//unsigned char mac[64] = { 0x00, };
	for (int i = 0; i < 64; i++)
		temp[i] = state->state_handle.V[i];
	temp[64] = 0x00;
	for (i = 65; i < len; i++)
		temp[i] = additional[i - 65];

	HMAC_SHA512(temp, len, key, state->state_handle.Key, 64);
	for (i = 0; i < 64; i++)
		state->state_handle.Key[i] = key[i];

	HMAC_SHA512(state->state_handle.V, 64, v, state->state_handle.Key, 64);
	for (i = 0; i < 64; i++)
		state->state_handle.V[i] = v[i];

	if (additional_len == 0)
	{
		free(temp);
		return;
	}

	for (int i = 0; i < 64; i++)
		temp[i] = state->state_handle.V[i];
	temp[64] = 0x01;
	for (i = 65; i < len; i++)
		temp[i] = additional[i - 65];

	HMAC_SHA512(temp, len, key, state->state_handle.Key, 64);
	memcpy(state->state_handle.Key, key, 64);

	HMAC_SHA512(state->state_handle.V, 64, v, state->state_handle.Key, 64);
	memcpy(state->state_handle.V, v, 64);

	free(temp);
}


/*외부갱신함수*/
void Reseed_HMAC_DRBG(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* additional, unsigned int additional_len)
{
	unsigned len = entropy_len + additional_len;
	unsigned char* temp = (unsigned char*)calloc(len, sizeof(unsigned char));
	int i = 0;


	for (i = 0; i <  entropy_len; i++)
		temp[i] = entropy[i];
	for (i = entropy_len; i < len; i++)
		temp[i] = additional[i - entropy_len];

	HMAC_DRBG_Update(state, temp, len);

	state->state_handle.reseed_counter = 1;
	free(temp);
}


void HMAC_Gen(STATE* state, unsigned char* randombits)
{
	unsigned char out[64] = { 0x00, };
	memcpy(out, state->state_handle.V, 64);
	unsigned char output[256] = { 0x00, };
	int i;
	for (i = 0; i < 4; i++)
	{
		HMAC_SHA512(out, 64, out, state->state_handle.Key, 64);
		memcpy(output + (i * 64), out, 64);
	}
	memcpy(randombits, output, 256);
	memcpy(state->state_handle.V, out, 64);
}


/*출력생성함수*/
void Generate_HMAC_DRBG_no(STATE* state, unsigned char* additional, unsigned int additional_len, unsigned char* randombits)
{
  //	unsigned char random[256] = { 0x00, };
	if (additional_len != 0)
	{
		HMAC_DRBG_Update(state, additional, additional_len);
	}

	//Reseed_HMAC_DRBG(state, entropy, entropy_len, additional, additional_len, flag);
	
	HMAC_Gen(state, randombits);

	HMAC_DRBG_Update(state, additional, additional_len);

	state->state_handle.reseed_counter = state->state_handle.reseed_counter + 1;

}

void Generate_HMAC_DRBG_yes(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* additional, unsigned int additional_len, unsigned char* randombits)
{
	Reseed_HMAC_DRBG(state, entropy, entropy_len, additional, additional_len);
	additional = NULL;
	additional_len = 0;

	HMAC_Gen(state, randombits);
	HMAC_DRBG_Update(state, additional, additional_len);

	state->state_handle.reseed_counter = state->state_handle.reseed_counter + 1;
}

void HMAC_DRBG_no(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* nonce, unsigned int nonce_len, unsigned char* personalization, unsigned int personalization_len, unsigned char* entropyreseed, unsigned int entropyreseed_len, unsigned char* additionalreseed, unsigned int additionalreseed_len, unsigned char* additional1, unsigned int additional1_len, unsigned char* additional2, unsigned int additional2_len, unsigned char* randombits)
{
	unsigned char random1[256] = { 0x00, };
	unsigned char random2[256] = { 0x00, };

	Instantiaite_Function(state, entropy, entropy_len, nonce, nonce_len, personalization, personalization_len);

	Reseed_HMAC_DRBG(state, entropyreseed, entropyreseed_len, additionalreseed, additionalreseed_len);

	Generate_HMAC_DRBG_no(state, additional1, additional1_len, random1);
	Generate_HMAC_DRBG_no(state, additional2, additional2_len, random2);

	memcpy(randombits, random2, 256);
}

void HMAC_DRBG_yes(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* nonce, unsigned int nonce_len, unsigned char* personalization, unsigned int personalization_len, unsigned char* entropy1, unsigned int entropy1_len, unsigned char* entropy2, unsigned int entropy2_len, unsigned char* additional1, unsigned int additional1_len, unsigned char* additional2, unsigned int additional2_len, unsigned char* randombits)
{
	unsigned char random1[256] = { 0x00, };
	unsigned char random2[256] = { 0x00, };

	Instantiaite_Function(state, entropy, entropy_len, nonce, nonce_len, personalization, personalization_len);

	Generate_HMAC_DRBG_yes(state, entropy1, entropy1_len, additional1, additional1_len, random1);
	Generate_HMAC_DRBG_yes(state, entropy2, entropy2_len, additional2, additional2_len, random2);

	memcpy(randombits, random2, 256);
}