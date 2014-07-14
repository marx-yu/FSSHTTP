// Copyright 2014 The Authors Marx-Yu. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once
#include "CommonDefs.h"

class File
{
public:
	enum OpenMode
	{
		READ,
		READ_WRITE,
		APPEND,
		TRUNCATE,
	};
	File(const wstring& filename, OpenMode om = READ);
	~File();
	size_t length();
	size_t read(size_t offset, void* dst, size_t count);
	size_t write(const void* src, size_t count);
private:
	HANDLE hfile_;
};
bool readContent(const wstring& filename, UINT *filesize, Byte** ret_buf);
bool writeFile(const wstring& filename, const Byte* buf, UINT size);

wstring toString(UINT64 value);
wstring toString(const GUID& guid);
wstring toString(const ExGUID& exguid);
wstring toString(const SerialNumber& sn);
wstring toString(const ObjectHeader& oh);
wstring toString(const Cell_ID& cellid);
wstring toString(const CompactUint64& cu64);
wstring toString(const ExGUIDArray& exguid_array);
wstring toString(const CellIDArray& cellid_array);
wstring toString(const BinaryItem& binaryitem);

wstring DataElementType2Str(const UINT64& type);
wstring RequestType2Str(const UINT64& type);
wstring KnowledgeTypeGuid2Str(const wstring& guid);
wstring ObjectChangeFrequency2Str(const UINT64& frequency);
wstring FilterType2Str(Byte type);
wstring QueryChangesFilterDataElementType2Str(const UINT64& type);
wstring DepthMeaning2Str(Byte depth);
wstring ErrorTypeGUID2Str(const GUID& type);

void initStreamObjectTypeMap();


class ScopedObjectHeader
{
public:
	ScopedObjectHeader(ObjectHeader& oh, SmartBuf& result_buf)
		:object_header_(oh), result_buf_(result_buf)
	{
		Byte header_buf[4 + 9] = {0}; //max len is 32-bit Stream Object Header Start, 4 bytes
		size_t offset = result_buf_.size();
		object_header_.serializeStart(header_buf);
		result_buf_.resize(offset + object_header_.bytes_use);
		memcpy(&result_buf_[offset], header_buf, object_header_.bytes_use);
	}
	~ScopedObjectHeader()
	{
		if (object_header_.compound)
		{
			Byte header_buf[4] = {0};
			size_t offset = result_buf_.size();
			object_header_.serializeEnd(header_buf);
			result_buf_.resize(offset + object_header_.bytes_use);
			memcpy(&result_buf_[offset], header_buf, object_header_.bytes_use);
		}
	}
private:
	ObjectHeader& object_header_;
	SmartBuf& result_buf_;
};

void pushSerialContent(SmartBuf& result_buf, const void* src, const size_t& size);
void pushSerialContent(SmartBuf& result_buf, const UINT64& value, const size_t& size);

bool generateSha1(const Byte* data, size_t size, Byte* result);
bool generateGUID(GUID* guid);
void exmemset(void* dst, UINT64 val, size_t size);

//the type of variable argument must be CobaltObject* or the deriver pointer end with NULL of variable parameter
size_t parseBatch(const Byte* bytes, ...);
size_t serializeBatch(Byte* result, ...);

string toString(const wstring &str);

wstring toString(const string &str);
