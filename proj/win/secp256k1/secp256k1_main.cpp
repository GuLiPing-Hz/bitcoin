// secp256k1.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"

extern "C" {
#include "libsecp256k1-config.h"
#include "secp256k1.h"
#include "src/bench.h"
}

typedef struct {
	secp256k1_context *ctx;
	unsigned char msg[32];
	unsigned char key[32];
	unsigned char sig[72];
	size_t siglen;
	unsigned char pubkey[33];
	size_t pubkeylen;
#ifdef ENABLE_OPENSSL_TESTS
	EC_GROUP* ec_group;
#endif
} benchmark_verify_t;

static void benchmark_verify(void* arg) {
	int i;
	benchmark_verify_t* data = (benchmark_verify_t*)arg;

	for (i = 0; i < 20000; i++) {
		secp256k1_pubkey pubkey;
		secp256k1_ecdsa_signature sig;
		/*
		ֻ�е�i=0��ʱ��ǩ�����ݲ��ᷢ�����ģ���������ݶ��ᱻ���ģ�
		����secp256k1_ecdsa_verify��֤ǩ��ʧ��
		*/
		data->sig[data->siglen - 1] ^= (i & 0xFF);
		data->sig[data->siglen - 2] ^= ((i >> 8) & 0xFF);
		data->sig[data->siglen - 3] ^= ((i >> 16) & 0xFF);
		CHECK(secp256k1_ec_pubkey_parse(data->ctx, &pubkey, data->pubkey, data->pubkeylen) == 1);
		CHECK(secp256k1_ecdsa_signature_parse_der(data->ctx, &sig, data->sig, data->siglen) == 1);
		CHECK(secp256k1_ecdsa_verify(data->ctx, &sig, data->msg, &pubkey) == (i == 0));//��i=0����֤�ɹ�
		data->sig[data->siglen - 1] ^= (i & 0xFF);
		data->sig[data->siglen - 2] ^= ((i >> 8) & 0xFF);
		data->sig[data->siglen - 3] ^= ((i >> 16) & 0xFF);
	}
}

int main(int argc, _TCHAR* argv[])
{
	int i;
	secp256k1_pubkey pubkey;
	secp256k1_ecdsa_signature sig;
	benchmark_verify_t data;

	/*����һ��ǩ��&��֤��context*/
	data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

	for (i = 0; i < 32; i++) {//ָ�����ܵ�message
		data.msg[i] = 1 + i;
	}
	for (i = 0; i < 32; i++) {//ָ��һ������˽Կ
		data.key[i] = 33 + i;
	}
	data.siglen = 72;

	//ʹ���������ɵ�msg��˽Կ������һ��ǩ��ժҪ
	CHECK(secp256k1_ecdsa_sign(data.ctx, &sig, data.msg, data.key, NULL, NULL));
	//���л�ǩ��ժҪ����ʽ��Ϊder��ͨ��buffer
	CHECK(secp256k1_ecdsa_signature_serialize_der(data.ctx, data.sig, &data.siglen, &sig));
	//ͨ��˽Կ����һ����Կ
	CHECK(secp256k1_ec_pubkey_create(data.ctx, &pubkey, data.key));
	data.pubkeylen = 33;
	//ѹ�������л�һ����Կ����ʽ��Ϊͨ��buffer
	CHECK(secp256k1_ec_pubkey_serialize(data.ctx, data.pubkey, &data.pubkeylen, &pubkey, SECP256K1_EC_COMPRESSED) == 1);

	//����ǩ������
	run_benchmark("ecdsa_verify", benchmark_verify, NULL, NULL, &data, 10, 20000);

	//��ʱ�ͷ��ڴ�
	secp256k1_context_destroy(data.ctx);

	return 0;
}

