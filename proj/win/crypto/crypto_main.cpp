// crypto.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "crypto/aes.h"
#include "config.h"
#include "funcs.h"
#include "compat/endian.h"

void testAes256(){
	unsigned char key[AES256_KEYSIZE] = { 0 };
	unsigned char ivIn[AES_BLOCKSIZE] = { 0 };

	/*����һ��aes256 key*/
	for (int i = 0; i < AES256_KEYSIZE; i++){
		key[i] = 101 + i;
	}
	/*�������key*/
	for (int i = 0; i < AES_BLOCKSIZE; i++){
		ivIn[i] = 10 + i;
	}

	AES256CBCEncrypt aes256enc(key, ivIn, true);
	AES256CBCDecrypt aes256dec(key, ivIn, true);

	/*��ʼ������*/
	unsigned char data[16] = "123456abcdef";
	int dataLen = sizeof(data);

	/*������Ҫ�洢�����ݳ���*/
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

void testEndian(){
	char a[10] = { 0 };
	uint16_t b = 0xabcd;
	LOGI("b = 0xabcd\n��ʼ����a:");
	LogCiphertext((unsigned char*)a, 10);
	*((uint16_t*)a) = b;
	LOGI("a[0-1]:");
	LogCiphertext((unsigned char*)a, 2);
	*((uint16_t*)a + 1) = htobe16(b);//n_be
	LOGI("htobe16 a[2-3]:");
	LogCiphertext((unsigned char*)a+2, 2);
	*((uint16_t*)a + 2) = htole16(b);//n_le
	LOGI("htole16 a[4-5]:");
	LogCiphertext((unsigned char*)a+4, 2);
	*((uint16_t*)a + 3) = be16toh(b);//be_h
	LOGI("be16toh a[6-7]:");
	LogCiphertext((unsigned char*)a+6, 2);
	*((uint16_t*)a + 4) = le16toh(b);//le_h
	LOGI("le16toh a[8-9]:");
	LogCiphertext((unsigned char*)a+8, 2);
}

int _tmain(int argc, _TCHAR* argv[])
{
	testAes256();
	testEndian();
	

	return 0;
}

