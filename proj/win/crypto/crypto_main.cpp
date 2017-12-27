// crypto.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "crypto/aes.h"
#include "config.h"
#include "funcs.h"

void testAes256(){
	unsigned char key[AES256_KEYSIZE] = { 0 };
	unsigned char ivIn[AES_BLOCKSIZE] = { 0 };

	/*
	构造一个aes256 key
	*/
	for (int i = 0; i < AES256_KEYSIZE; i++){
		key[i] = 101 + i;
	}
	/*
	构造亦或key
	*/
	for (int i = 0; i < AES_BLOCKSIZE; i++){
		ivIn[i] = 10 + i;
	}

	AES256CBCEncrypt aes256enc(key, ivIn, true);
	AES256CBCDecrypt aes256dec(key, ivIn, true);

	/*
	初始化数据
	*/
	unsigned char data[16] = "123456abcdef";
	int dataLen = sizeof(data);

	/*
	计算需要存储的数据长度
	*/
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

int _tmain(int argc, _TCHAR* argv[])
{
	testAes256();

	return 0;
}

