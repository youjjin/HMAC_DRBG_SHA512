#include "HMAC-DRBG(SHA-512).h"
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <math.h>


void Instantiaite_Function_op(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* nonce, unsigned int nonce_len, unsigned char* personalization, unsigned int personalization_len)
{
	int len = entropy_len + nonce_len + personalization_len;
	unsigned char seed_material[250] = { 0x00, };
	unsigned char temp[112] = { 0x00, };

	memcpy(seed_material, entropy, entropy_len);
	memcpy(seed_material + entropy_len, nonce, nonce_len);
	memcpy(seed_material + entropy_len + nonce_len, personalization, personalization_len);

	memset(state->state_handle.Key, 0x00, 64);
	memset(state->state_handle.V, 0x01, 64);

	//HMAC_DRBG_Update_op(state, seed_material, len);
	int new_len = 65 + len;
	unsigned char key[64] = { 0, };
	unsigned char v[64] = { 0, };
	unsigned char temp1[250] = { 0x00, };
	unsigned char V[64] = { 0x00, };
	memcpy(V, state->state_handle.V, 64);

	memcpy(temp1, state->state_handle.V, 64);
	temp1[64] = 0x00;
	memcpy(temp1 + 65, seed_material, len);

	HMAC_SHA512_op(temp1, new_len, state->state_handle.Key, state->state_handle.Key, 64);
	HMAC_SHA512_op(state->state_handle.V, 64, state->state_handle.V, state->state_handle.Key, 64);

	if (len == 0)
		return;

	memcpy(temp1, state->state_handle.V, 64);
	temp1[64] = 0x01;
	memcpy(temp1 + 65, seed_material, len);

	HMAC_SHA512_op(temp1, new_len, key, state->state_handle.Key, 64);
	memcpy(state->state_handle.Key, key, 64);

	HMAC_SHA512_op(state->state_handle.V, 64, v, state->state_handle.Key, 64);
	memcpy(state->state_handle.V, v, 64);

	state->state_handle.reseed_counter = 1;

}

void Reseed_HMAC_DRBG_op(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* additional, unsigned int additional_len)
{
	unsigned len = entropy_len + additional_len;
	unsigned char temp[250] = { 0x00, };
	memcpy(temp, entropy, entropy_len);
	memcpy(temp + entropy_len, additional, additional_len);

	//HMAC_DRBG_Update_op(state, temp, len);
	int new_len = 65 + len;
	unsigned char key[64] = { 0, };
	unsigned char v[64] = { 0, };
	unsigned char temp1[250] = { 0x00, };
	unsigned char V[64] = { 0x00, };
	memcpy(V, state->state_handle.V, 64);

	memcpy(temp1, state->state_handle.V, 64);
	temp1[64] = 0x00;
	memcpy(temp1 + 65, temp, len);

	HMAC_SHA512_op(temp1, new_len, state->state_handle.Key, state->state_handle.Key, 64);
	HMAC_SHA512_op(state->state_handle.V, 64, state->state_handle.V, state->state_handle.Key, 64);

	if (len == 0)
		return;

	memcpy(temp1, state->state_handle.V, 64);
	temp1[64] = 0x01;
	memcpy(temp1 + 65, temp, len);

	HMAC_SHA512_op(temp1, new_len, key, state->state_handle.Key, 64);
	memcpy(state->state_handle.Key, key, 64);

	HMAC_SHA512_op(state->state_handle.V, 64, v, state->state_handle.Key, 64);
	memcpy(state->state_handle.V, v, 64);

	state->state_handle.reseed_counter = 1;
}

void Generate_HMAC_DRBG_no_op(STATE* state, unsigned char* additional, unsigned int additional_len, unsigned char* randombits)
{
	
	if (additional_len != 0)
	{
		//HMAC_DRBG_Update_op(state, additional, additional_len);
		int i;
		int len = 65 + additional_len;
		unsigned char key[64] = { 0, };
		unsigned char v[64] = { 0, };
		unsigned char temp[250] = { 0x00, };
		unsigned char V[64] = { 0x00, };
		memcpy(V, state->state_handle.V, 64);

		memcpy(temp, state->state_handle.V, 64);
		temp[64] = 0x00;
		memcpy(temp + 65, additional, additional_len);

		HMAC_SHA512_op(temp, len, state->state_handle.Key, state->state_handle.Key, 64);
		HMAC_SHA512_op(state->state_handle.V, 64, state->state_handle.V, state->state_handle.Key, 64);

		if (additional_len == 0)
			return;

		memcpy(temp, state->state_handle.V, 64);
		temp[64] = 0x01;
		memcpy(temp + 65, additional, additional_len);

		HMAC_SHA512_op(temp, len, key, state->state_handle.Key, 64);
		memcpy(state->state_handle.Key, key, 64);

		HMAC_SHA512_op(state->state_handle.V, 64, v, state->state_handle.Key, 64);
		memcpy(state->state_handle.V, v, 64);
	}

	//HMAC_Gen_op(state, randombits);
	unsigned char out[64] = { 0x00, };
	memcpy(out, state->state_handle.V, 64);
	unsigned char output[256] = { 0x00, };
	/*1*/
	HMAC_SHA512_op(out, 64, out, state->state_handle.Key, 64);
	memcpy(output, out, 64);
	/*2*/
	HMAC_SHA512_op(out, 64, out, state->state_handle.Key, 64);
	memcpy(output + 64, out, 64);
	/*3*/
	HMAC_SHA512_op(out, 64, out, state->state_handle.Key, 64);
	memcpy(output + 128, out, 64);
	/*4*/
	HMAC_SHA512_op(out, 64, out, state->state_handle.Key, 64);
	memcpy(output + 192, out, 64);

	memcpy(randombits, output, 256);
	memcpy(state->state_handle.V, out, 64);

	//HMAC_DRBG_Update_op(state, additional, additional_len);
	int new_len = 65 + additional_len;
	unsigned char key[64] = { 0, };
	unsigned char v[64] = { 0, };
	unsigned char temp1[250] = { 0x00, };
	unsigned char V[64] = { 0x00, };
	memcpy(V, state->state_handle.V, 64);

	memcpy(temp1, state->state_handle.V, 64);
	temp1[64] = 0x00;
	memcpy(temp1 + 65, additional, additional_len);

	HMAC_SHA512_op(temp1, new_len, state->state_handle.Key, state->state_handle.Key, 64);
	HMAC_SHA512_op(state->state_handle.V, 64, state->state_handle.V, state->state_handle.Key, 64);

	if (additional_len == 0)
		return;

	memcpy(temp1, state->state_handle.V, 64);
	temp1[64] = 0x01;
	memcpy(temp1 + 65, additional, additional_len);

	HMAC_SHA512_op(temp1, new_len, key, state->state_handle.Key, 64);
	memcpy(state->state_handle.Key, key, 64);

	HMAC_SHA512_op(state->state_handle.V, 64, v, state->state_handle.Key, 64);
	memcpy(state->state_handle.V, v, 64);

	state->state_handle.reseed_counter = state->state_handle.reseed_counter + 1;

}


void Generate_HMAC_DRBG_yes_op(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* additional, unsigned int additional_len, unsigned char* randombits)
{
	Reseed_HMAC_DRBG_op(state, entropy, entropy_len, additional, additional_len);
	additional = NULL;
	additional_len = 0;

	//HMAC_Gen_op(state, randombits);
	unsigned char out[64] = { 0x00, };
	memcpy(out, state->state_handle.V, 64);
	unsigned char output[256] = { 0x00, };
	/*1*/
	HMAC_SHA512_op(out, 64, out, state->state_handle.Key, 64);
	memcpy(output, out, 64);
	/*2*/
	HMAC_SHA512_op(out, 64, out, state->state_handle.Key, 64);
	memcpy(output + 64, out, 64);
	/*3*/
	HMAC_SHA512_op(out, 64, out, state->state_handle.Key, 64);
	memcpy(output + 128, out, 64);
	/*4*/
	HMAC_SHA512_op(out, 64, out, state->state_handle.Key, 64);
	memcpy(output + 192, out, 64);

	memcpy(randombits, output, 256);
	memcpy(state->state_handle.V, out, 64);

	//HMAC_DRBG_Update_op(state, additional, additional_len);
	int new_len = 65 + additional_len;
	unsigned char key[64] = { 0, };
	unsigned char v[64] = { 0, };
	unsigned char temp1[250] = { 0x00, };
	unsigned char V[64] = { 0x00, };
	memcpy(V, state->state_handle.V, 64);

	memcpy(temp1, state->state_handle.V, 64);
	temp1[64] = 0x00;
	memcpy(temp1 + 65, additional, additional_len);

	HMAC_SHA512_op(temp1, new_len, state->state_handle.Key, state->state_handle.Key, 64);
	HMAC_SHA512_op(state->state_handle.V, 64, state->state_handle.V, state->state_handle.Key, 64);

	if (additional_len == 0)
		return;

	memcpy(temp1, state->state_handle.V, 64);
	temp1[64] = 0x01;
	memcpy(temp1 + 65, additional, additional_len);

	HMAC_SHA512_op(temp1, new_len, key, state->state_handle.Key, 64);
	memcpy(state->state_handle.Key, key, 64);

	HMAC_SHA512_op(state->state_handle.V, 64, v, state->state_handle.Key, 64);
	memcpy(state->state_handle.V, v, 64);

	state->state_handle.reseed_counter = state->state_handle.reseed_counter + 1;
}

void HMAC_DRBG_no_op(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* nonce, unsigned int nonce_len, unsigned char* personalization, unsigned int personalization_len, unsigned char* entropyreseed, unsigned int entropyreseed_len, unsigned char* additionalreseed, unsigned int additionalreseed_len, unsigned char* additional1, unsigned int additional1_len, unsigned char* additional2, unsigned int additional2_len, unsigned char* randombits)
{
	unsigned char random1[256] = { 0x00, };
	unsigned char random2[256] = { 0x00, };

	Instantiaite_Function_op(state, entropy, entropy_len, nonce, nonce_len, personalization, personalization_len);

	Reseed_HMAC_DRBG_op(state, entropyreseed, entropyreseed_len, additionalreseed, additionalreseed_len);

	Generate_HMAC_DRBG_no_op(state, additional1, additional1_len, random1);
	Generate_HMAC_DRBG_no_op(state, additional2, additional2_len, random2);

	memcpy(randombits, random2, 256);
}

void HMAC_DRBG_yes_op(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* nonce, unsigned int nonce_len, unsigned char* personalization, unsigned int personalization_len, unsigned char* entropy1, unsigned int entropy1_len, unsigned char* entropy2, unsigned int entropy2_len, unsigned char* additional1, unsigned int additional1_len, unsigned char* additional2, unsigned int additional2_len, unsigned char* randombits)
{
	unsigned char random1[256] = { 0x00, };
	unsigned char random2[256] = { 0x00, };

	Instantiaite_Function_op(state, entropy, entropy_len, nonce, nonce_len, personalization, personalization_len);

	Generate_HMAC_DRBG_yes_op(state, entropy1, entropy1_len, additional1, additional1_len, random1);
	Generate_HMAC_DRBG_yes_op(state, entropy2, entropy2_len, additional2, additional2_len, random2);

	memcpy(randombits, random2, 256);
}