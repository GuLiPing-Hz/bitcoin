// leveldb.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"

//���ʹ��c���Ա�̵Ļ�������ʹ��
// #include "leveldb/c.h"
#include "leveldb/db.h"
#include "leveldb/write_batch.h"

#include "../wrap_config.h"

int _tmain(int argc, _TCHAR* argv[])
{
	/*
	LevelDB��Google��Դ�ĳ־û�KV�������ݿ⣬���кܸߵ����д��˳���/д���ܣ���������������ܺ�һ�㣬Ҳ����˵��LevelDB���ʺ�Ӧ���ڲ�ѯ���٣���д�ܶ�ĳ���
	*/
	leveldb::Options options;
	leveldb::DB* db = NULL;
	options.create_if_missing = true;//������ݿ��ļ������ڣ�������һ���µ�
	leveldb::Status status = leveldb::DB::Open(options, "testDb", &db);
	if (status.ok()){
		LOGI("���ݿ�򿪳ɹ� %p", db);

		leveldb::WriteOptions writeOps;
		writeOps.sync = true;

		leveldb::ReadOptions readOps;
		
		leveldb::Slice key("id");
		leveldb::Slice data("100001");
		status = db->Put(writeOps, key, data);

		std::string ids;
		status = db->Get(readOps, "id", &ids);

		leveldb::WriteBatch batch;
		batch.Put(leveldb::Slice("id"), leveldb::Slice("100002"));
		batch.Put(leveldb::Slice("name"), leveldb::Slice("Tom"));
		batch.Put(leveldb::Slice("age"), leveldb::Slice("18"));
		batch.Put(leveldb::Slice("mail"), leveldb::Slice("1"));
		batch.Put(leveldb::Slice("score"), leveldb::Slice("90"));
		status = db->Write(writeOps, &batch);

		//std::string ids;
		status = db->Get(readOps, "id", &ids);
		status = db->Get(readOps, "id", &ids);
	}
	else {
		LOGI("���ݿ��ʧ�� %s", status.ToString().c_str());
	}

	if (db){
		delete db;
	}

	return 0;
}

