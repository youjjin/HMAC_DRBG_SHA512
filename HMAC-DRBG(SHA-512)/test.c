#include "HMAC-DRBG(SHA-512).h"
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>



void Change_digit(unsigned char* string, unsigned int* len, unsigned int* digit)
{
	char seps[] = "=, ,\t,\n";
	char *tok;

	int i, j;
	unsigned int result = 0, dig = 0;

	tok = strtok(string, seps);

	while (tok != NULL)
	{

		if (strstr(tok, "EntropyInputLen") == NULL && strstr(tok, "NonceLen") == NULL && strstr(tok, "PersonalizationStringLen") == NULL && strstr(tok, "AdditionalInputLen") == NULL && strstr(tok, "ReturnedBitsLen") == NULL)
		{
			*len = strlen(tok);
			*digit = atoi(tok);
		}
		tok = strtok(NULL, seps);
	}

}

void Ascii(char* string, unsigned char* stream, int* len)
{

	char seps[] = "=, , \t, \n";
	char *tok;

	unsigned char buf[2500] = { 0, };
	int i = 0, j = 0, cnt = 0, n = 0;
	unsigned char result = 0, six = 0;
	int tmp = 0;
	tok = strtok(string, seps);


	while (tok != NULL)
	{
		if (strstr(tok, "AdditionalInputReseed") == NULL && strstr(tok, "EntropyInputReseed") == NULL && strstr(tok, "EntropyInput") == NULL && strstr(tok, "Nonce") == NULL && strstr(tok, "PersonalizationString") == NULL && strstr(tok, "EntropyInputPR") == NULL && strstr(tok, "AdditionalInput") == NULL)
		{
			*len = strlen(tok) / 2;

			while (j < strlen(tok))
			{
				result = 0;
				six = 0;

				for (i = j; i < j + 2; i++)
				{
					if (isalpha(tok[i]))
					{
						result = toupper(tok[i]) - 55;
						six = six * 16 + result;
					}
					else
					{
						result = tok[i] - 48;
						six = six * 16 + result;
					}
				}

				buf[n] = six;
				n++;
				j = j + 2;

				tmp = 1;

			}
		}
		tok = strtok(NULL, seps);
	}

	if (tmp == 1)
		memcpy(stream, buf, *len);

	else
	{
		stream = NULL;
		*len = 0;
	}
}

void HMAC_DRBG_SHA512_usePR_Test()
{
	STATE state;
	state.state_control.prediction_resistance_flag = 1;

	unsigned char pseudorandom_bits[256] = { 0x00, };

	FILE *fp_req;
	FILE *fp_fax;

	char Count_buff[1000];
	char EntropyInput_buff[1000]; //인스턴스
	char EntropyInput_len_buff[1000];
	char Nonce_buff[1000];
	char Nonce_len_buff[1000];
	char Personalizationstring_buff[1000];
	char Personalizationstring_len_buff[1000];
	char Additionalinput_len_buff[1000];
	char EntropyInput1_buff[1000];
	char AdditionalInput1_buff[1200];
	char EntropyInput2_buff[1000];
	char AdditionalInput2_buff[1200];
	char buff[1000];//Enter

	int i, j, p;

	unsigned int entropy_len, entropy1_len, entropy2_len, entropyinput_len, nonce_len, personalization_len, additionalinput_len, additionalinput1_len, additionalinput2_len;

	unsigned int* d_entropyinput_len, d_nonce_len, d_personalization_len, d_additionalinput_len;

	unsigned char count[1000] = { 0, };
	unsigned char Entropy[1000] = { 0, };
	unsigned char Nonce[1000] = { 0, };
	unsigned char Personalizationstring[1000] = { 0, };
	unsigned char Entropy1[1200] = { 0, };
	unsigned char Additional1[1200] = { 0, };
	unsigned char Entropy2[1200] = { 0, };
	unsigned char Additional2[1200] = { 0, };
	unsigned char Returnedbits[1200] = { 0, };

	fp_req = fopen("HMAC_DRBG(SHA512(use PR))_KAT.req", "r");
	fp_fax = fopen("HMAC_DRBG(SHA512(use PR))_KAT.rsp", "w");

	if (fp_req == NULL || fp_fax == NULL)
	{
		printf("파일열기 실패\n");
		return;
	}

	for (j = 0; j < 4; j++)
	{
		/****************[SHA-512]******************/
		fgets(buff, sizeof(buff), fp_req);
		printf("%s", buff);
		fputs(buff, fp_fax);
		memset(buff, 0, sizeof(buff));

		/****************[PredictionResistance]******************/
		fgets(buff, sizeof(buff), fp_req);
		printf("%s", buff);
		fputs(buff, fp_fax);
		memset(buff, 0, sizeof(buff));

		/****************[EntropyputLen]******************/
		fgets(buff, sizeof(buff), fp_req);
		printf("%s", buff);
		fputs(buff, fp_fax);
		memset(buff, 0, sizeof(buff));

		/****************[NonceLen]******************/
		fgets(buff, sizeof(buff), fp_req);
		printf("%s", buff);
		fputs(buff, fp_fax);
		memset(buff, 0, sizeof(buff));

		/****************[PersonalizationStringLen]******************/
		fgets(buff, sizeof(buff), fp_req);
		printf("%s", buff);
		fputs(buff, fp_fax);
		memset(buff, 0, sizeof(buff));

		/****************[AdditionnalInputLen]******************/
		fgets(buff, sizeof(buff), fp_req);
		printf("%s", buff);
		fputs(buff, fp_fax);
		memset(buff, 0, sizeof(buff));

		/****************[ReturnedBitsLen = 2048]******************/
		fgets(buff, sizeof(buff), fp_req);
		printf("%s", buff);
		fputs(buff, fp_fax);
		memset(buff, 0, sizeof(buff));
		printf("\n");
		fprintf(fp_fax, "\n");

		/****************Enter******************/
		fgets(buff, sizeof(buff), fp_req);
		memset(buff, 0, sizeof(buff));

		for (i = 0; i < 15; i++)
		{
			/****************Count******************/
			fgets(Count_buff, sizeof(Count_buff), fp_req);
			printf("%s", Count_buff);
			fputs(Count_buff, fp_fax);
			memset(Count_buff, 0, sizeof(Count_buff));

			/****************EntropyInput******************/
			fgets(EntropyInput_buff, sizeof(EntropyInput_buff), fp_req);
			printf("%s", EntropyInput_buff);
			fputs(EntropyInput_buff, fp_fax);
			Ascii(EntropyInput_buff, Entropy, &entropy_len);
			memset(EntropyInput_buff, 0, sizeof(EntropyInput_buff));

			/****************Nonce******************/
			fgets(Nonce_buff, sizeof(Nonce_buff), fp_req);
			printf("%s", Nonce_buff);
			fputs(Nonce_buff, fp_fax);
			Ascii(Nonce_buff, Nonce, &nonce_len);
			memset(Nonce_buff, 0, sizeof(Nonce_buff));

			/****************personalizationstring******************/
			fgets(Personalizationstring_buff, sizeof(Personalizationstring_buff), fp_req);
			printf("%s", Personalizationstring_buff);
			fputs(Personalizationstring_buff, fp_fax);
			Ascii(Personalizationstring_buff, Personalizationstring, &personalization_len);
			memset(Personalizationstring_buff, 0, sizeof(Personalizationstring_buff));

			/****************EntropyInput******************/
			fgets(EntropyInput1_buff, sizeof(EntropyInput1_buff), fp_req);
			printf("%s", EntropyInput1_buff);
			fputs(EntropyInput1_buff, fp_fax);
			Ascii(EntropyInput1_buff, Entropy1, &entropy1_len);
			memset(EntropyInput1_buff, 0, sizeof(EntropyInput1_buff));

			/****************AdditionalInput******************/
			fgets(AdditionalInput1_buff, sizeof(AdditionalInput1_buff), fp_req);
			printf("%s", AdditionalInput1_buff);
			fputs(AdditionalInput1_buff, fp_fax);
			Ascii(AdditionalInput1_buff, Additional1, &additionalinput1_len);
			memset(AdditionalInput1_buff, 0, sizeof(AdditionalInput1_buff));

			/****************EntropyInput******************/
			fgets(EntropyInput2_buff, sizeof(EntropyInput2_buff), fp_req);
			printf("%s", EntropyInput2_buff);
			fputs(EntropyInput2_buff, fp_fax);
			Ascii(EntropyInput2_buff, Entropy2, &entropy2_len);
			memset(EntropyInput2_buff, 0, sizeof(EntropyInput2_buff));

			/****************AdditionalInput******************/
			fgets(AdditionalInput2_buff, sizeof(AdditionalInput2_buff), fp_req);
			printf("%s", AdditionalInput2_buff);
			fputs(AdditionalInput2_buff, fp_fax);
			Ascii(AdditionalInput2_buff, Additional2, &additionalinput2_len);
			memset(AdditionalInput2_buff, 0, sizeof(AdditionalInput2_buff));

			/*****************Enter***************/
			fgets(buff, sizeof(buff), fp_req);
			memset(buff, 0, sizeof(buff));

			/****************HASH_DRBG***************/
			HMAC_DRBG_yes(&state, Entropy, entropy_len, Nonce, nonce_len, Personalizationstring, personalization_len, Entropy1, entropy1_len, Entropy2, entropy2_len, Additional1, additionalinput1_len, Additional2, additionalinput2_len, pseudorandom_bits);

			/*****************MAC***************/
			printf("ReturnedBits = ");

			for (int Z = 0; Z < 256; Z++)
			{
				printf("%02X", pseudorandom_bits[Z]);
			}
			printf("\n");
			printf("\n");

			fprintf(fp_fax, "ReturnedBits = ");
			for (int Z = 0; Z < 256; Z++)
			{
				fprintf(fp_fax, "%02X", pseudorandom_bits[Z]);
			}
			fprintf(fp_fax, "\n");
			fprintf(fp_fax, "\n");
		}
	}

	fclose(fp_req);
	fclose(fp_fax);
}

void HMAC_DRBG_SHA512_noPR_Test()
{
	STATE state;
	state.state_control.prediction_resistance_flag = 0;

	unsigned char pseudorandom_bits[256] = { 0x00, };

	FILE *fp_req;
	FILE *fp_fax;

	char Count_buff[1000];
	char EntropyInput_buff[1000]; //인스턴스
	char EntropyInput_len_buff[1000];
	char Nonce_buff[1000];
	char Nonce_len_buff[1000];
	char Personalizationstring_buff[1000];
	char Personalizationstring_len_buff[1000];
	char Additionalinput_len_buff[1000];
	char EntropyInput1_buff[1000];
	char AdditionalInput1_buff[1200];
	char EntropyInput2_buff[1000];
	char AdditionalInput2_buff[1200];
	char buff[1000];//Enter

	int i, j, p;

	unsigned int entropy_len, entropy1_len, entropy2_len, entropyinput_len, nonce_len, personalization_len, additionalinput_len, additionalinput1_len, additionalinput2_len;

	unsigned int* d_entropyinput_len, d_nonce_len, d_personalization_len, d_additionalinput_len;

	unsigned char count[1000] = { 0, };
	unsigned char Entropy[1000] = { 0, };
	unsigned char Nonce[1000] = { 0, };
	unsigned char Personalizationstring[1000] = { 0, };
	unsigned char Entropy1[1200] = { 0, };
	unsigned char Additional1[1200] = { 0, };
	unsigned char Entropy2[1200] = { 0, };
	unsigned char Additional2[1200] = { 0, };
	unsigned char Returnedbits[1200] = { 0, };

	fp_req = fopen("HMAC_DRBG(SHA512(no PR))_KAT.req", "r");
	fp_fax = fopen("HMAC_DRBG(SHA512(no PR))_KAT.rsp", "w");

	if (fp_req == NULL || fp_fax == NULL)
	{
		printf("파일열기 실패\n");
		return;
	}

	for (j = 0; j < 4; j++)
	{
		/****************[SHA-512]******************/
		fgets(buff, sizeof(buff), fp_req);
		printf("%s", buff);
		fputs(buff, fp_fax);
		memset(buff, 0, sizeof(buff));

		/****************[PredictionResistance]******************/
		fgets(buff, sizeof(buff), fp_req);
		printf("%s", buff);
		fputs(buff, fp_fax);
		memset(buff, 0, sizeof(buff));

		/****************[EntropyputLen]******************/
		fgets(buff, sizeof(buff), fp_req);
		printf("%s", buff);
		fputs(buff, fp_fax);
		memset(buff, 0, sizeof(buff));

		/****************[NonceLen]******************/
		fgets(buff, sizeof(buff), fp_req);
		printf("%s", buff);
		fputs(buff, fp_fax);
		memset(buff, 0, sizeof(buff));

		/****************[PersonalizationStringLen]******************/
		fgets(buff, sizeof(buff), fp_req);
		printf("%s", buff);
		fputs(buff, fp_fax);
		memset(buff, 0, sizeof(buff));

		/****************[AdditionnalInputLen]******************/
		fgets(buff, sizeof(buff), fp_req);
		printf("%s", buff);
		fputs(buff, fp_fax);
		memset(buff, 0, sizeof(buff));

		/****************[ReturnedBitsLen = 2048]******************/
		fgets(buff, sizeof(buff), fp_req);
		printf("%s", buff);
		fputs(buff, fp_fax);
		memset(buff, 0, sizeof(buff));
		printf("\n");
		fprintf(fp_fax, "\n");

		/****************Enter******************/
		fgets(buff, sizeof(buff), fp_req);
		memset(buff, 0, sizeof(buff));

		for (i = 0; i < 15; i++)
		{
			/****************Count******************/
			fgets(Count_buff, sizeof(Count_buff), fp_req);
			printf("%s", Count_buff);
			fputs(Count_buff, fp_fax);
			memset(Count_buff, 0, sizeof(Count_buff));

			/****************EntropyInput******************/
			fgets(EntropyInput_buff, sizeof(EntropyInput_buff), fp_req);
			printf("%s", EntropyInput_buff);
			fputs(EntropyInput_buff, fp_fax);
			Ascii(EntropyInput_buff, Entropy, &entropy_len);

			memset(EntropyInput_buff, 0, sizeof(EntropyInput_buff));

			/****************Nonce******************/
			fgets(Nonce_buff, sizeof(Nonce_buff), fp_req);
			printf("%s", Nonce_buff);
			fputs(Nonce_buff, fp_fax);
			Ascii(Nonce_buff, Nonce, &nonce_len);
			memset(Nonce_buff, 0, sizeof(Nonce_buff));

			/****************personalizationstring******************/
			fgets(Personalizationstring_buff, sizeof(Personalizationstring_buff), fp_req);
			printf("%s", Personalizationstring_buff);
			fputs(Personalizationstring_buff, fp_fax);
			Ascii(Personalizationstring_buff, Personalizationstring, &personalization_len);
			memset(Personalizationstring_buff, 0, sizeof(Personalizationstring_buff));

			/****************EntropyReseed******************/
			fgets(EntropyInput1_buff, sizeof(EntropyInput1_buff), fp_req);
			printf("%s", EntropyInput1_buff);
			fputs(EntropyInput1_buff, fp_fax);
			Ascii(EntropyInput1_buff, Entropy1, &entropy1_len);
			memset(EntropyInput1_buff, 0, sizeof(EntropyInput1_buff));

			/****************AddirtionalReseed******************/
			fgets(EntropyInput2_buff, sizeof(EntropyInput2_buff), fp_req);
			printf("%s", EntropyInput2_buff);
			fputs(EntropyInput2_buff, fp_fax);
			Ascii(EntropyInput2_buff, Entropy2, &entropy2_len);
			memset(EntropyInput2_buff, 0, sizeof(EntropyInput2_buff));

			/****************AdditionalInput******************/
			fgets(AdditionalInput1_buff, sizeof(AdditionalInput1_buff), fp_req);
			printf("%s", AdditionalInput1_buff);
			fputs(AdditionalInput1_buff, fp_fax);
			Ascii(AdditionalInput1_buff, Additional1, &additionalinput1_len);
			memset(AdditionalInput1_buff, 0, sizeof(AdditionalInput1_buff));

			/****************AdditionalInput******************/
			fgets(AdditionalInput2_buff, sizeof(AdditionalInput2_buff), fp_req);
			printf("%s", AdditionalInput2_buff);
			fputs(AdditionalInput2_buff, fp_fax);
			Ascii(AdditionalInput2_buff, Additional2, &additionalinput2_len);
			memset(AdditionalInput2_buff, 0, sizeof(AdditionalInput2_buff));

			/*****************Enter***************/
			fgets(buff, sizeof(buff), fp_req);
			memset(buff, 0, sizeof(buff));

			/****************HASH_DRBG***************/
			HMAC_DRBG_no(&state, Entropy, entropy_len, Nonce, nonce_len, Personalizationstring, personalization_len, Entropy1, entropy1_len, Entropy2, entropy2_len, Additional1, additionalinput1_len, Additional2, additionalinput2_len, pseudorandom_bits);

			/*****************MAC***************/
			printf("ReturnedBits = ");

			for (int Z = 0; Z < 256; Z++)
			{
				printf("%02X", pseudorandom_bits[Z]);
			}
			printf("\n");
			printf("\n");

			fprintf(fp_fax, "ReturnedBits = ");
			for (int Z = 0; Z < 256; Z++)
			{
				fprintf(fp_fax, "%02X", pseudorandom_bits[Z]);
			}
			fprintf(fp_fax, "\n");
			fprintf(fp_fax, "\n");
		}
	}

	fclose(fp_req);
	fclose(fp_fax);
}