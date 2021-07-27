

#undef BIG_ENDIAN
#undef LITTLE_ENDIAN

#if defined(USER_BIG_ENDIAN)
#define BIG_ENDIAN
#elif defined(USER_LITTLE_ENDIAN)
#define LITTLE_ENDIAN
#else
#if 0
#define BIG_ENDIAN
#elif defined(_MSC_VER)
#define LITTLE_ENDIAN
#else
#error
#endif
#endif


#if defined(LITTLE_ENDIAN)
#define ENDIAN_REVERSE_ULONG(w,x)	{ \
	unsigned long long tmp = (w); \
	tmp = (tmp >> 32) | (tmp << 32); \
	tmp = ((tmp & 0xff00ff00ff00ff00) >> 8) | \
	      ((tmp & 0x00ff00ff00ff00ff) << 8); \
	(x) = ((tmp & 0xffff0000ffff0000) >> 16) | \
	      ((tmp & 0x0000ffff0000ffff) << 16); \
}
#endif

#define R(b,x) 		((x) >> (b))

#define S64(b,x)	(((x) >> (b)) | ((x) << (64 - (b))))

#define Ch(x,y,z)	(((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z)	(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define Sigma0(x)	(S64(28, (x)) ^ S64(34, (x)) ^ S64(39, (x)))
#define Sigma1(x)	(S64(14, (x)) ^ S64(18, (x)) ^ S64(41, (x)))
#define RHO0(x)	(S64( 1, (x)) ^ S64( 8, (x)) ^ R( 7, (x)))
#define RHO1(x)	(S64(19, (x)) ^ S64(61, (x)) ^ R( 6, (x)))

#define SHA512_DIGEST_BLOCKLEN		128
#define SHA512_DIGEST_VALUELEN		64

#define I_PAD 0x36
#define O_PAD 0x5c


typedef struct {
	unsigned long long uChainVar[SHA512_DIGEST_BLOCKLEN / 16];
	unsigned long long	uHighLength;
	unsigned long long uLowLength;
	unsigned char szBuffer[SHA512_DIGEST_BLOCKLEN];
} SHA512_INFO;


typedef struct {
	unsigned char V[64];
	unsigned char Key[64];
	unsigned int reseed_counter;
}STATE_HANDLE;

typedef struct {
	unsigned int security_strength;
	unsigned int prediction_resistance_flag; //예측내성 설정 = 1, 미설정 = 0
}STATE_CONTROL;

//내부상태는 구조체로 정의(V, C, temp, reseed_counter)
typedef struct {
	STATE_HANDLE state_handle;
	STATE_CONTROL state_control;
} STATE;

#define OutLen 512 
#define Len_seed 2 //sha512 : len_seed = 2
#define SeedLen 888 //sha512 : SeedLen = 888bit = 111bytes
#define reseed_interval pow(2, 48)

void SHA512_Init(SHA512_INFO* info);
void SHA512_Transform(SHA512_INFO* context, unsigned long long* data);
void SHA512_Process(SHA512_INFO* Info, unsigned char *pszMessage, unsigned int uDataLen);
void SHA512_Close(SHA512_INFO* Info, unsigned char* pszDigest);
void SHA512(unsigned char *pszMessage, unsigned int uDataLen, unsigned char *pszDigest);

void HMAC_SHA512(unsigned char *pszMessage, unsigned int uPlainTextLen, unsigned char *mac, unsigned char *key, unsigned int keyLen);

void Instantiaite_Function(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* nonce, unsigned int nonce_len, unsigned char* personalization, unsigned int personalization_len);
void HMAC_DRBG_Update(STATE* state, unsigned char* additional, unsigned int additional_len);
void Reseed_HMAC_DRBG(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* additional, unsigned int additional_len);
void HMAC_Gen(STATE* state, unsigned char* randombits);
void Generate_HMAC_DRBG_no(STATE* state, unsigned char* additional, unsigned int additional_len, unsigned char* randombits);
void Generate_HMAC_DRBG_yes(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* additional, unsigned int additional_len, unsigned char* randombits);
void HMAC_DRBG_no(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* nonce, unsigned int nonce_len, unsigned char* personalization, unsigned int personalization_len, unsigned char* entropyreseed, unsigned int entropyreseed_len, unsigned char* additionalreseed, unsigned int additionalreseed_len, unsigned char* additional1, unsigned int additional1_len, unsigned char* additional2, unsigned int additional2_len, unsigned char* randombits);
void HMAC_DRBG_yes(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* nonce, unsigned int nonce_len, unsigned char* personalization, unsigned int personalization_len, unsigned char* entropy1, unsigned int entropy1_len, unsigned char* entropy2, unsigned int entropy2_len, unsigned char* additional1, unsigned int additional1_len, unsigned char* additional2, unsigned int additional2_len, unsigned char* randombits);

void Instantiaite_Function_op(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* nonce, unsigned int nonce_len, unsigned char* personalization, unsigned int personalization_len);
void HMAC_DRBG_Update_op(STATE* state, unsigned char* additional, unsigned int additional_len);
void Reseed_HMAC_DRBG_op(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* additional, unsigned int additional_len);
void HMAC_Gen_op(STATE* state, unsigned char* randombits);
void Generate_HMAC_DRBG_yes_op(STATE* state, unsigned char* entropy, unsigned int entropy_len, unsigned char* additional, unsigned int additional_len, unsigned char* randombits);

void HMAC_SHA512_op(unsigned char *pszMessage, unsigned int uPlainTextLen, unsigned char *mac, unsigned char *key, unsigned int keyLen);

void HMAC_DRBG_SHA512_noPR_Test();
void HMAC_DRBG_SHA512_usePR_Test();