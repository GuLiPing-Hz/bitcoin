// secp256k1.cpp : 定义控制台应用程序的入口点。
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
		只有当i=0的时候签名数据不会发生更改，后面的数据都会被更改，
		导致secp256k1_ecdsa_verify验证签名失败
		*/
		data->sig[data->siglen - 1] ^= (i & 0xFF);
		data->sig[data->siglen - 2] ^= ((i >> 8) & 0xFF);
		data->sig[data->siglen - 3] ^= ((i >> 16) & 0xFF);
		CHECK(secp256k1_ec_pubkey_parse(data->ctx, &pubkey, data->pubkey, data->pubkeylen) == 1);
		CHECK(secp256k1_ecdsa_signature_parse_der(data->ctx, &sig, data->sig, data->siglen) == 1);
		CHECK(secp256k1_ecdsa_verify(data->ctx, &sig, data->msg, &pubkey) == (i == 0));//当i=0是验证成功
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

	/*创建一个签名&验证的context*/
	data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

	for (i = 0; i < 32; i++) {//指定加密的message
		data.msg[i] = 1 + i;
	}
	for (i = 0; i < 32; i++) {//指定一个加密私钥
		data.key[i] = 33 + i;
	}
	data.siglen = 72;

	//使用上面生成的msg和私钥，生成一个签名摘要
	CHECK(secp256k1_ecdsa_sign(data.ctx, &sig, data.msg, data.key, NULL, NULL));
	//序列化签名摘要，格式化为der的通用buffer
	CHECK(secp256k1_ecdsa_signature_serialize_der(data.ctx, data.sig, &data.siglen, &sig));
	//通过私钥创建一个公钥
	CHECK(secp256k1_ec_pubkey_create(data.ctx, &pubkey, data.key));
	data.pubkeylen = 33;
	//压缩并序列化一个公钥，格式化为通用buffer
	CHECK(secp256k1_ec_pubkey_serialize(data.ctx, data.pubkey, &data.pubkeylen, &pubkey, SECP256K1_EC_COMPRESSED) == 1);

	//运行签名测试
	run_benchmark("ecdsa_verify", benchmark_verify, NULL, NULL, &data, 10, 20000);

	//及时释放内存
	secp256k1_context_destroy(data.ctx);

	return 0;
}

