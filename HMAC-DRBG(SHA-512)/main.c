#include "HMAC-DRBG(SHA-512).h"
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>

unsigned int cpucycles(void) { return __rdtsc(); }


void main()
{
	STATE state;
	state.state_control.prediction_resistance_flag = 1;

	unsigned char Entropy[32] = { 0xD6, 0x2C, 0x48, 0x8B, 0x30, 0x67, 0xFF, 0x72, 0x9B, 0x08, 0xB9, 0xAF, 0xE0, 0x81, 0xAE, 0xEC, 0x13, 0x6D, 0xA0, 0x34, 0x20, 0xD1, 0x0E, 0x58, 0xA7, 0xA2, 0xAB, 0x92, 0x0A, 0x88, 0x0E, 0x69 };
	unsigned char Nonce[16] = { 0xC4, 0xE2, 0xAB, 0xD4, 0xFC, 0x0A, 0x02, 0xA2, 0x59, 0xDA, 0x16, 0x19, 0x19, 0x6F, 0x21, 0xDE };
	unsigned char* PersonalizationString = NULL;
	unsigned char Entropy1[32] = { 0x5D, 0x2C, 0x86, 0x15, 0xC7, 0x02, 0x07, 0xC8, 0x47, 0xEF, 0x38, 0x8D, 0x32, 0xC5, 0x33, 0x63, 0x95, 0x2D, 0x8E, 0xDE, 0xC8, 0xEB, 0x8A, 0x84, 0x46, 0x64, 0x8D, 0x76, 0xBB, 0x5D, 0xD3, 0x53 };
	unsigned char* Additional1 = NULL;
	unsigned char Entropy2[32] = { 0x5F, 0x05, 0x60, 0x59, 0x83, 0x36, 0x39, 0xCD, 0x69, 0xF8, 0xD3, 0x9D, 0x59, 0x47, 0xCC, 0x45, 0xF1, 0x16, 0xD9, 0xEF, 0xBD, 0x93, 0x00, 0xDE, 0x08, 0xAD, 0x07, 0x0C, 0xF1, 0xD3, 0x2C, 0x12 };
	unsigned char* Additional2 = NULL;
	//ReturnedBits = 99B18DC4D6B02367A1C2EAF295CEDC3BA6E9E35480F04F4BC05AB76A54678C5B4DFE640E824B6CE2C256E1B7AE678C1F53F69E1DA5695130AE127FF03C9C61D8E20EF14A84B8B5DE75C4050A6CD012F60326ED5853DA47DEE34DDBFC7A829335DB3DA3883730731F72C2E41C4E34CF478A8994FC201831B96DD354C581FF2FB85E695AD954B823DED71EB30EC07836642412E030DA98D814EFF9294BB73EBE2844037814D771A71FAA7C33B705122910F4D36C365A6BFF81A718044CFED345570DC377BC33335304B6C94B4058B7ED010B6C09B8B5517C225E5F457D929BECB8F7B47260D85675779F3CDBBF78085CAEEF668155CBF3BE025B1E4E118A93DC4C
	unsigned char randombits[256] = { 0x00, };

	int i;
	unsigned long long cycles = 0;
	unsigned long long cycles1 = 0;
	unsigned long long cycles2 = 0;
	unsigned int loop = 10000;

	//for loop에 들어가는 것까지 안새주려고 시간을 포루프 안에서 돌려줄것이다.
	for (i = 0; i < loop; i++)
	{
		cycles1 = cpucycles();

		HMAC_DRBG_yes_op(&state, Entropy, 32, Nonce, 16, PersonalizationString, 0, Entropy1, 32, Entropy2, 32, Additional1, 0, Additional2, 0, randombits);

		cycles2 = cpucycles();
		cycles += (cycles2 - cycles1);
	}

	printf("\n[loop = %d]cycles : %10lld\n", loop, cycles / loop);
	cycles = 0;


	printf("[난수]\n");
	for (int A = 0; A < 256; A++)
		printf("%02X ", randombits[A]);
	printf("\n");

	//HMAC_DRBG_SHA512_noPR_Test();
	//HMAC_DRBG_SHA512_usePR_Test();
}