// crypto.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "crypto/aes.h"
#include "config.h"
#include "funcs.h"

void testAes256(){
	unsigned char key[AES256_KEYSIZE] = { 0 };
	unsigned char ivIn[AES_BLOCKSIZE] = { 0 };

	/*
	����һ��aes256 key
	*/
	for (int i = 0; i < AES256_KEYSIZE; i++){
		key[i] = 101 + i;
	}
	/*
	�������key
	*/
	for (int i = 0; i < AES_BLOCKSIZE; i++){
		ivIn[i] = 10 + i;
	}

	AES256CBCEncrypt aes256enc(key, ivIn, true);
	AES256CBCDecrypt aes256dec(key, ivIn, true);

	/*
	��ʼ������
	*/
	unsigned char data[16] = "123456abcdef";
	int dataLen = sizeof(data);

	/*
	������Ҫ�洢�����ݳ���
	*/
	int outLen = (dataLen + AES_BLOCKSIZE) / AES_BLOCKSIZE*AES_BLOCKSIZE;
	unsigned char* out = new unsigned char[outLen];
	LOGI("����ǰ:%s", data);
	int data_enc_len = aes256enc.Encrypt(data, sizeof(data), out);//����������Ҫ�ŵ������ڴ�
	LOGI("���ܺ�:");
	LogCiphertext(out, data_enc_len);
	aes256dec.Decrypt(out, data_enc_len, out);
	LOGI("���ܺ�:%s", out);

	delete out;
}

int _tmain(int argc, _TCHAR* argv[])
{
	testAes256();

	return 0;
}

