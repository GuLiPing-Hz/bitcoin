// leveldb.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

//如果使用c语言编程的话，可以使用
// #include "leveldb/c.h"
#include "leveldb/db.h"
#include "leveldb/write_batch.h"

#include "../wrap_config.h"

int _tmain(int argc, _TCHAR* argv[])
{
	/*
	LevelDB是Google开源的持久化KV单机数据库，具有很高的随机写，顺序读/写性能，但是随机读的性能很一般，也就是说，LevelDB很适合应用在查询较少，而写很多的场景
	*/
	leveldb::Options options;
	leveldb::DB* db = NULL;
	options.create_if_missing = true;//如果数据库文件不存在，则生成一个新的
	leveldb::Status status = leveldb::DB::Open(options, "testDb", &db);
	if (status.ok()){
		LOGI("数据库打开成功 %p", db);

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
		LOGI("数据库打开失败 %s", status.ToString().c_str());
	}

	if (db){
		delete db;
	}

	return 0;
}

