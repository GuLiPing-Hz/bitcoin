// crypto.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "crypto/aes.h"
#include "config.h"
#include "funcs.h"
#include "compat/endian.h"
#include "crypto/chacha20.h"

void testAes256(){
	unsigned char key[AES256_KEYSIZE] = { 0 };
	unsigned char ivIn[AES_BLOCKSIZE] = { 0 };

	/*构造一个aes256 key*/
	for (int i = 0; i < AES256_KEYSIZE; i++){
		key[i] = 101 + i;
	}
	/*构造亦或key*/
	for (int i = 0; i < AES_BLOCKSIZE; i++){
		ivIn[i] = 10 + i;
	}

	AES256CBCEncrypt aes256enc(key, ivIn, true);
	AES256CBCDecrypt aes256dec(key, ivIn, true);

	/*初始化数据*/
	unsigned char data[16] = "123456abcdef";
	int dataLen = sizeof(data);

	/*计算需要存储的数据长度*/
	int outLen = (dataLen + AES_BLOCKSIZE) / AES_BLOCKSIZE*AES_BLOCKSIZE;
	unsigned char* out = new unsigned char[outLen];
	LOGI("加密前:%s", data);
	int data_enc_len = aes256enc.Encrypt(data, sizeof(data), out);//加密数据需要放到其他内存
	LOGI("加密后:");
	LogCiphertext(out, data_enc_len);
	aes256dec.Decrypt(out, data_enc_len, out);
	LOGI("解密后:%s", out);

	delete out;
}

void testEndian(){
	char a[10] = { 0 };
	uint16_t b = 0xabcd;
	LOGI("b = %#x\n初始序列a:", b);
	LogCiphertext((unsigned char*)a, 10);
	*((uint16_t*)a) = b;
	LOGI("a[0]:");
	LogCiphertext((unsigned char*)a, 2);
	*((uint16_t*)a + 1) = htobe16(b);//n_be
	LOGI("htobe16 a[1]:");
	LogCiphertext((unsigned char*)a+2, 2);
	*((uint16_t*)a + 2) = htole16(b);//n_le
	LOGI("htole16 a[2]:");
	LogCiphertext((unsigned char*)a+4, 2);
	*((uint16_t*)a + 3) = be16toh(b);//be_h
	LOGI("be16toh a[3]:");
	LogCiphertext((unsigned char*)a+6, 2);
	*((uint16_t*)a + 4) = le16toh(b);//le_h
	LOGI("le16toh a[4]:");
	LogCiphertext((unsigned char*)a+8, 2);

	char a64[40] = { 0 };
	uint64_t b64 = 0x123456789abcdeff;
	LOGI("b64 = %#x\n初始序列a64:", b64);
	LogCiphertext((unsigned char*)a64, 40);
	*((uint64_t*)a64) = b64;
	LOGI("a64[0]:");
	LogCiphertext((unsigned char*)a64, 8);
	*((uint64_t*)a64 + 1) = htobe64(b64);//n_be
	LOGI("htobe64 a64[1]:");
	LogCiphertext((unsigned char*)a64 + 8, 8);
	*((uint64_t*)a64 + 2) = htole64(b64);//n_le
	LOGI("htole64 a64[2]:");
	LogCiphertext((unsigned char*)a64 + 16, 8);
	*((uint64_t*)a64 + 3) = be64toh(b64);//be_h
	LOGI("be64toh a64[3]:");
	LogCiphertext((unsigned char*)a64 + 24, 8);
	*((uint64_t*)a64 + 4) = le64toh(b64);//le_h
	LOGI("le64toh a64[4]:");
	LogCiphertext((unsigned char*)a64 + 32, 8);
}

void testChaCha20(){
	unsigned char key[32] = { 0 };
	for (int i = 0; i < 32; i++){
		key[i] = 10 + i;
	}
	ChaCha20 chacha20(key, sizeof(key));
	chacha20.SetIV(10);
	chacha20.Seek(100);

	unsigned char data[16] = { 0 };
	chacha20.Output(data, sizeof(data));
	LogCiphertext(data, sizeof(data));
	chacha20.Output(data, sizeof(data));
	LogCiphertext(data, sizeof(data));
	chacha20.Output(data, sizeof(data));
	LogCiphertext(data, sizeof(data));
}

int _tmain(int argc, _TCHAR* argv[])
{
	testAes256();//测试aes加密解密
	testEndian();//测试大小端字节序
	testChaCha20();//伪随机数生成器 for chacha20

	return 0;
}

