// Copyright 2014 The Authors Marx-Yu. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once
#include <Guiddef.h>

typedef unsigned char Byte;
static const Byte kTypeBit0Flag = 0;
static const Byte kTypeBit1Flag = 0x1;
static const Byte kTypeBit2Flag = 0x2;
static const Byte kTypeBit3Flag = 0x4;
static const Byte kTypeBit4Flag = 0x8;
static const Byte kTypeBit5Flag = 16;
static const Byte kTypeBit6Flag = 32;
static const Byte kTypeBit7Flag = 64;
static const Byte kTypeBit8Flag = 128;

struct CobaltObject
{
	virtual void parse(const Byte* bytes) = 0;
	virtual void serialize(Byte* buf) = 0;
	virtual size_t used() = 0;
	virtual ~CobaltObject(){}
};

struct CompactUint64: public CobaltObject
{
	UINT64 value;
	size_t bytes_use;
	CompactUint64(): value(0), bytes_use(0)
	{
	}

	CompactUint64(UINT64 v): value(v), bytes_use(0)
	{
	}
	void parse(const Byte* bytes)
	{
		if (bytes[0] == kTypeBit0Flag)
		{
			value = 0;
			bytes_use = 1;		//only use 1 byte of 0x00
		}
		else if ((bytes[0] & kTypeBit1Flag) > 0)
		{
			value = bytes[0] >> 1;
			bytes_use = 1;
		}
		else if ((bytes[0] & kTypeBit2Flag) > 0)
		{
			UINT16 temp = *((UINT16*)bytes);
			value = temp >> 2;
			bytes_use = 2;
		}
		else if ((bytes[0] & kTypeBit3Flag) > 0)
		{
			UINT32 temp = 0;
			memcpy(&temp, bytes, 3);
			value = temp >> 3;
			bytes_use = 3;
		}
		else if ((bytes[0] & kTypeBit4Flag) > 0)
		{
			UINT32 temp = 0;
			memcpy(&temp, bytes, 4);
			value = temp >> 4;
			bytes_use = 4;
		}
		else if ((bytes[0] & kTypeBit5Flag) > 0)
		{
			UINT64 temp = 0;
			memcpy(&temp, bytes, 5);
			value = temp >> 5;
			bytes_use = 5;
		}
		else if ((bytes[0] & kTypeBit6Flag) > 0)
		{
			UINT64 temp = 0;
			memcpy(&temp, bytes, 6);
			value = temp >> 6;
			bytes_use = 6;
		}
		else if ((bytes[0] & kTypeBit7Flag) > 0)
		{
			UINT64 temp = 0;
			memcpy(&temp, bytes, 7);
			value = temp >> 7;
			bytes_use = 7;
		}
		else if ((bytes[0] & kTypeBit8Flag) > 0)
		{
			UINT64 temp = 0;
			memcpy(&temp, bytes+1, 8);
			value = temp;
			bytes_use = 9;
		}
	}

	void serialize(Byte* buf)
	{
		if (value == 0)
		{
			buf[0] = 0x00;
			bytes_use = 1;
		}
		else if (value >= 0x01 && value <=0x7f)
		{
			Byte temp = value;
			temp <<= 1;
			temp |= kTypeBit1Flag;
			memcpy(buf, &temp, 1);
			bytes_use = 1;
		}
		else if (value >= 0x0080 && value <= 0x3fff)
		{
			UINT16 temp = value;
			temp <<= 2;
			temp |= kTypeBit2Flag;
			memcpy(buf, &temp, 2);
			bytes_use = 2;
		}
		else if (value >= 0x004000 && value <= 0x1fffff)
		{
			UINT32 temp = value;
			temp <<= 3;
			temp |= kTypeBit3Flag;
			memcpy(buf, &temp, 3);
			bytes_use = 3;
		}
		else if (value >= 0x0200000 && value <= 0xFFFFFFF)
		{
			UINT32 temp = value;
			temp <<= 4;
			temp |= kTypeBit4Flag;
			memcpy(buf, &temp, 4);
			bytes_use = 4;
		}
		else if (value >= 0x010000000 && value <= 0x7FFFFFFFF)
		{
			UINT64 temp = value;
			temp <<= 5;
			temp |= kTypeBit5Flag;
			memcpy(buf, &temp, 5);
			bytes_use = 5;
		}
		else if (value >= 0x00800000000 && value <= 0x3FFFFFFFFFF)
		{
			UINT64 temp = value;
			temp <<= 6;
			temp |= kTypeBit6Flag;
			memcpy(buf, &temp, 6);
			bytes_use = 6;
		}
		else if (value >= 0x0040000000000 && value <= 0x1FFFFFFFFFFFF)
		{
			UINT64 temp = value;
			temp <<= 7;
			temp |= kTypeBit7Flag;
			memcpy(buf, &temp, 7);
			bytes_use = 7;
		}
		else if (value >= 0x0002000000000000 && value <= 0xFFFFFFFFFFFFFFFF)
		{
			buf[0] = kTypeBit8Flag;
			memcpy(buf + 1, &value, 8);
			bytes_use = 9;
		}
		else
		{
			assert(false);
		}
	}
	size_t used(){ return bytes_use; }
};

struct ExGUID: public CobaltObject
{
	UINT32 value;
	GUID guid;
	size_t bytes_use;
	ExGUID()
	{
		value = 0;
		memset(&guid, 0x00, sizeof(GUID));
		bytes_use = 0;
	}
	ExGUID(UINT32 v, const GUID& id)
		:value(v), guid(id), bytes_use(0)
	{
	}
	bool operator== (const ExGUID& that)
	{
		return (this->value == that.value && this->guid == that.guid);
	}
	void parse(const Byte *bytes)
	{
		if (bytes[0] == kTypeBit0Flag)
		{
			value = 0;
			memset(&guid, 0x00, sizeof(GUID));
			bytes_use = 1;	//only use 1 byte of 0x00
		}
		else if ((bytes[0] & kTypeBit3Flag) > 0)
		{
			value = bytes[0] >> 3;
			memcpy(&guid, bytes + 1, sizeof(guid));
			bytes_use = 17;
		}
		else if ((bytes[0] & kTypeBit6Flag) > 0)
		{
			UINT16 temp = *((UINT16*)bytes);
			value = temp >> 6;
			memcpy(&guid, bytes + 2, sizeof(guid));
			bytes_use = 18;
		}
		else if ((bytes[0] & kTypeBit7Flag) > 0)
		{
			UINT32 temp = 0;
			memcpy(&temp, bytes, 3);
			value = temp >> 7;
			memcpy(&guid, bytes + 3, sizeof(guid));
			bytes_use = 19;
		}
		else if ((bytes[0] & kTypeBit8Flag) > 0)
		{
			value = *((INT32*)(bytes + 1));
			memcpy(&guid, bytes + 5, sizeof(guid));
			bytes_use = 21;
		}
		else
		{
			assert(false);
		}
	}

	void serialize(Byte* buf)
	{
		if (value == 0 && guid.Data1 == 0)
		{
			buf[0] = 0x00;
			bytes_use = 1;
		}
		else if (value >= 0 && value <= 0x1F)
		{
			UINT32 temp = value;
			temp <<= 3;
			temp |= kTypeBit3Flag;
			memcpy(buf, &temp, 1);
			memcpy(buf + 1, &guid, 16);
			bytes_use = 1 + 16;
		}
		else if (value >= 0x20 && value <= 0x3FF)
		{
			UINT32 temp = value;
			temp <<= 6;
			temp |= kTypeBit6Flag;
			memcpy(buf, &temp, 2);
			memcpy(buf + 2, &guid, 16);
			bytes_use = 2 + 16;
		}
		else if (value >= 0x400 && value <= 0x1FFFF)
		{
			UINT32 temp = value;
			temp <<= 7;
			temp |= kTypeBit7Flag;
			memcpy(buf, &temp, 3);
			memcpy(buf + 3, &guid, 16);
			bytes_use = 3 + 16;
		}
		else if (value >= 0x20000 && value <= 0xFFFFFFFF)
		{
			buf[0] = kTypeBit8Flag;
			memcpy(buf + 1, &value, 4);
			memcpy(buf + 5, &guid, 16);
			bytes_use = 1 + 4 + 16;
		}
	}
	size_t used(){ return bytes_use; }
};

typedef std::vector<ExGUID> ExGUIDVector;
struct ExGUIDArray: public CobaltObject
{
	CompactUint64 count;
	ExGUIDVector content;
	size_t bytes_use; 
	ExGUIDArray()
		:bytes_use(0)
	{
	}
	void parse(const Byte* bytes)
	{
		bytes_use = 0;
		count.parse(bytes);
		bytes_use += count.bytes_use;
		for (UINT64 i=0; i < count.value; i++)
		{
			ExGUID exguid;
			exguid.parse(bytes + bytes_use);
			content.push_back(exguid);
			bytes_use += exguid.bytes_use;
		}
	}
	void add(const ExGUID& exguid)
	{
		count.value ++;
		content.push_back(exguid);
	}
	void serialize(Byte* buf)
	{
		assert(count.value == content.size());
		count.serialize(buf);
		bytes_use = count.bytes_use;
		for(size_t i = 0; i < count.value; i++)
		{
			ExGUID& exguid = content[i];
			exguid.serialize(buf + bytes_use);
			bytes_use += exguid.bytes_use;
		}
	}

	size_t used(){ return bytes_use; }
};

struct SerialNumber: public CobaltObject
{
	GUID guid;
	UINT64 value;
	size_t bytes_use;
	SerialNumber()
	{
		memset(&guid, 0x00, sizeof(GUID));
		value = 0;
		bytes_use = 0;
	}
	SerialNumber(UINT64 v, const GUID& id)
		:value(v), guid(id), bytes_use(0)
	{
	}
	void parse(const Byte* bytes)
	{
		if (bytes[0] == 0)
		{
			memset(&guid, 0x00, sizeof(GUID));
			value = 0;
			bytes_use = 1;	//only use 1 byte of 0x00
		}
		else if ((bytes[0] & kTypeBit8Flag) > 0)
		{
			memcpy(&guid, bytes+1, sizeof(guid));
			value = *((UINT64 *)(bytes + 17));
			bytes_use = 25;
		}
		else
		{
			assert(false);
		}
	}

	void serialize(Byte* buf)
	{
		if (value == 0 && guid.Data1 == 0)
		{
			buf[0] = 0x00;
			bytes_use = 1;
		}
		else
		{
			buf[0] = kTypeBit8Flag;
			memcpy(buf + 1, &guid, 16);
			memcpy(buf + 17, &value, 8);
			bytes_use = 1 + 16 + 8;
		}
	}
	size_t used(){ return bytes_use; }
};

struct Cell_ID: public CobaltObject
{
	ExGUID exguid_first;
	ExGUID exguid_second;
	size_t bytes_use;
	Cell_ID(): bytes_use(0)
	{
	}
	Cell_ID(const ExGUID& f, const ExGUID& s)
		:exguid_first(f), exguid_second(s), bytes_use(0)
	{
	
	}
	void parse(const Byte* bytes)
	{
		exguid_first.parse(bytes);
		exguid_second.parse(bytes + exguid_first.bytes_use);
		bytes_use = exguid_first.bytes_use + exguid_second.bytes_use;
	}
	void serialize(Byte* buf)
	{
		exguid_first.serialize(buf);
		bytes_use = exguid_first.bytes_use;
		exguid_second.serialize(buf + bytes_use);
		bytes_use += exguid_second.bytes_use;
	}
	size_t used(){ return bytes_use; }
};

typedef std::vector<Cell_ID> CellIDVector;
struct CellIDArray: public CobaltObject
{
	CompactUint64 count;
	CellIDVector content;
	size_t bytes_use; 
	CellIDArray()
		:bytes_use(0)
	{
	}
	void parse(const Byte* bytes)
	{
		bytes_use = 0;
		count.parse(bytes);
		bytes_use += count.bytes_use;
		for (UINT64 i=0; i < count.value; i++)
		{
			Cell_ID cellid;
			cellid.parse(bytes + bytes_use);
			content.push_back(cellid);
			bytes_use += cellid.bytes_use;
		}
	}
	void add(const Cell_ID& cellid)
	{
		count.value ++;
		content.push_back(cellid);
	}

	void serialize(Byte* buf)
	{
		count.serialize(buf);
		bytes_use = count.bytes_use;
		for(size_t i=0; i < count.value; i++)
		{
			Cell_ID& cellid = content[i];
			cellid.serialize(buf + bytes_use);
			bytes_use += cellid.bytes_use;
		}
	}
	size_t used(){ return bytes_use; }
};

struct BinaryItem: public CobaltObject
{
	CompactUint64 length;
	Byte start[20];
	Byte end[20];
	UINT16 example_len;
	size_t bytes_use;

	BinaryItem()
		:example_len(0), bytes_use(0)
	{
		memset(start, 0x00, sizeof(start));
		memset(end, 0x00, sizeof(end));
	}

	void parse(const Byte* bytes)
	{
		bytes_use = 0;
		length.parse(bytes);
		bytes_use += length.bytes_use;
		example_len = sizeof(start);
		if (length.value < example_len * 2)
			example_len = (UINT16)length.value / 2;
		memcpy(start, bytes+bytes_use, example_len);	//the start example bytes
		memcpy(end, bytes+bytes_use+length.value-example_len, example_len);	//the end example bytes
		bytes_use += length.value;
	}

	void serialize(Byte* buf)
	{

	}
	size_t used(){ return bytes_use; }
};

struct RawBinaryItem: public CobaltObject
{
	CompactUint64 length;
	Byte* data;
	size_t bytes_use;
	RawBinaryItem()
		:data(NULL), length(0), bytes_use(0)
	{

	}
	void fill(const Byte* src, size_t size)
	{
		if (size == 0)
			return;
		assert(src != NULL);
		data = new Byte[size];
		assert(data != NULL);
		memcpy(data, src, size);
		length.value = size;
	}
	void clear()
	{
		if (data != NULL)
			delete[] data;
	}
	void parse(const Byte* bytes)
	{
		bytes_use = 0;
		data = NULL;
		length.parse(bytes);
		bytes_use += length.bytes_use;
		fill(bytes+bytes_use, length.value);
		bytes_use += length.value;
	}
	void serialize(Byte* buf)
	{
		length.serialize(buf);
		bytes_use = length.bytes_use;
		memcpy(buf + bytes_use, data, length.value);
		bytes_use += length.value;
	}
	size_t used(){ return bytes_use; }
};

typedef std::vector<RawBinaryItem> RawBinaryVector;

typedef std::vector<Byte> SmartBuf;

static const Byte kOHBit16Start = 0x0;
static const Byte kOHBit32Start = 0x2;
static const Byte kOHBit8End = 0x1;
static const Byte kOHBit16End = 0x3;
static const UINT16 kLargeLengthFlag = 32767;	//0x7FFF
struct ObjectHeader
{
	Byte header_type;
	UINT16 object_type;
	bool compound;
	UINT64 length;
	Byte bytes[4 + 9];	//save and print for view manual, max of object header and large length
	Byte bytes_use;
	ObjectHeader(): header_type(0), object_type(0), compound(false), length(0), bytes_use(0)
	{
		memset(bytes, 0x00, sizeof(bytes));
	}
	ObjectHeader(UINT16 ot, bool com, UINT16 len)
		:object_type(ot), compound(com), length(len)
	{
	}
	void init(UINT16 ot, bool com, UINT64 len)
	{
		object_type = ot;
		compound = com;
		length = len;
	}
	void parse(const Byte *bytes)
	{
		memset(this, 0x00, sizeof(ObjectHeader));
		header_type = bytes[0] & 0x3;	//get low 2 bit
		switch (header_type)
		{
		case kOHBit16Start:
			{
				compound = (bytes[0] & 0x4) == 0x4;	//third bit
				UINT16 temp = *((UINT16*)bytes);
				object_type = (temp >> 3) & 0x3f;	//6 bits of 1
				length = (temp >> 9);	//the remain 7 bits
				memcpy(this->bytes, bytes, 2);
				bytes_use = 2;	//the target object use 4 bytes
			}
			break;
		case kOHBit32Start:
			{
				compound = (bytes[0] & 0x4) == 0x4;
				UINT32 temp = *((UINT32*)bytes);
				object_type = (temp >> 3) & 0x3fff;	//14 bits of 1
				length = temp >> 17;
				bytes_use = 4;
				if (length == kLargeLengthFlag)
				{
					CompactUint64 cuint64;
					cuint64.parse(bytes + bytes_use);
					length = cuint64.value;
					bytes_use += cuint64.bytes_use;
				}
				memcpy(this->bytes, bytes, bytes_use);
				
			}
			break;
		case kOHBit8End:
			{
				object_type = bytes[0] >> 2;
				memcpy(this->bytes, bytes, 1);
				bytes_use = 1;
			}
			break;
		case kOHBit16End:
			{
				UINT16 temp = *((UINT16*)bytes);
				object_type = temp >> 2;
				memcpy(this->bytes, bytes, 2);
				bytes_use = 2;
			}
			break;
		default:
			assert(false);
		}
	}

	void serializeStart(Byte* buf)
	{
		if (length > 0x7f || object_type > 0x3f)
		{
			//must use 32-bit Stream Object Header
			header_type = kOHBit32Start;
			bool use_large = (length >= kLargeLengthFlag);
			UINT32 temp = use_large? kLargeLengthFlag : length;
			temp <<= 14;
			temp |= object_type;
			temp <<= 1;
			temp |= (compound? 1 : 0);
			temp <<= 2;
			temp |= header_type;
			memcpy(buf, &temp, 4);
			bytes_use = 4;
			if (use_large)
			{
				CompactUint64 cuint64(length);
				cuint64.serialize(buf + bytes_use);
				bytes_use += cuint64.bytes_use;
			}
		}
		else
		{
			header_type = kOHBit16Start;
			UINT16 temp = length;
			temp <<= 6;
			temp |= object_type;
			temp <<= 1;
			temp |= (compound? 1 : 0);
			temp <<= 2;
			temp |= header_type;
			memcpy(buf, &temp, 2);
			bytes_use = 2;
		}
	}
	void serializeEnd(Byte* buf)
	{
		if (object_type > 0x3f)
		{
			header_type = kOHBit16End;
			UINT16 temp = object_type;
			temp <<= 2;
			temp |= header_type;
			memcpy(buf, &temp, 2);
			bytes_use = 2;
		}
		else
		{
			header_type = kOHBit8End;
			UINT8 temp = object_type;
			temp <<= 2;
			temp |= header_type;
			memcpy(buf, &temp, 1);
			bytes_use = 1;
		}
	}

	size_t used(){ return bytes_use; }
};

union PutChangesRequestArguments
{
	Byte b;
	struct
	{
		bool ImplyNullExpectedIfNoMapping: 1;
		bool Partial: 1;
		bool PartialLast: 1;
		bool FavorCoherencyFailureOverNotFound: 1;
		bool AbortRemainingPutChangesOnFailure: 1;
		bool MultiRequestPutHint: 1;
		bool ReturnCompleteKnowledgeIfPossible: 1;
		bool LastWriterWinsOnNextChange: 1;
	};
};

struct StreamObjectType
{
	UINT16 object_type;
	bool compound;
	wstring describe;
	StreamObjectType()
		:object_type(0), compound(false)
	{
	}
	StreamObjectType(wstring desc, UINT16 type, Byte com)
		:object_type(type), compound(com==1), describe(desc)
	{
	}
};

typedef std::map<UINT16, StreamObjectType> StreamObjectTypeMap;struct FileExInfo{	wstring path;	GUID cellstorage_guid_of_waterline;	UINT64 content_BSN;	UINT64 metadata_BSN;	GUID storage_index_guid;	UINT64 storage_index_value;	UINT64 metadata_cellrange;};struct ResponseResult{	UINT32 err_code;	wstring err_message;	bool bsn_updated;	UINT64 content_BSN;	UINT64 metadata_BSN;	UINT64 storage_index_value;	UINT64 metadata_cellrange;	ResponseResult(UINT32 err=0, wstring errm=wstring(), bool updated=false, UINT64 cb=0, UINT64 mb=0, UINT64 siv=0, UINT64 cr=0)		:err_code(err), err_message(errm), content_BSN(cb), metadata_BSN(mb), bsn_updated(updated), storage_index_value(siv), metadata_cellrange(cr)	{	}};//Stream Object Type
static const UINT16 kOTData_element = 0x01;
static const UINT16 kOTObject_data_BLOB = 0x02;
static const UINT16 kOTObject_group_object_excluded_data =  0x03;
static const UINT16 kOTWaterline_knowledge_entry = 0x04;
static const UINT16 kOTObject_group_object_BLOB_data_declaration = 0x05;
static const UINT16 kOTData_element_hash = 0x06;
static const UINT16 kOTStorage_manifest_root_declare = 0x07;
static const UINT16 kOTRevision_manifest_root_declare = 0x0A;
static const UINT16 kOTCell_manifest_current_revision = 0x0B;
static const UINT16 kOTStorage_manifest_schema_GUID = 0x0C;
static const UINT16 kOTStorage_index_revision_mapping = 0x0D;
static const UINT16 kOTStorage_index_cell_mapping = 0x0E;
static const UINT16 kOTCell_knowledge_range = 0x0F;
static const UINT16 kOTKnowledge = 0x10;
static const UINT16 kOTStorage_index_manifest_mapping = 0x11;
static const UINT16 kOTCell_Knowledge = 0x14;
static const UINT16 kOTData_element_package = 0x15;
static const UINT16 kOTObject_group_object_data = 0x16;
static const UINT16 kOTCell_knowledge_entry = 0x17;
static const UINT16 kOTObject_group_object_declare = 0x18;
static const UINT16 kOTRevision_manifest_object_group_references = 0x19;
static const UINT16 kOTRevision_manifest = 0x1A;
static const UINT16 kOTObject_group_object_data_BLOB_reference = 0x1C;
static const UINT16 kOTObject_group_declarations = 0x1D;
static const UINT16 kOTObject_group_data = 0x1E;
static const UINT16 kOTWaterline_knowledge = 0x29;
static const UINT16 kOTContent_tag_knowledge = 0x2D;
static const UINT16 kOTContent_tag_knowledge_entry = 0x2E;
static const UINT16 kOTRequest = 0x040;
static const UINT16 kOTSubresponse = 0x041;
static const UINT16 kOTSubrequest = 0x042;
static const UINT16 kOTRead_access_response = 0x043;
static const UINT16 kOTSpecialized_knowledge = 0x044;
static const UINT16 kOTWrite_access_response = 0x046;
static const UINT16 kOTQuery_changes_filter = 0x047;
static const UINT16 kOTError_Win32 = 0x049;
static const UINT16 kOTError_Protocol = 0x04B;
static const UINT16 kOTError = 0x04D;
static const UINT16 kOTError_String_Supplemental_Info = 0x04E;
static const UINT16 kOTUser_agent_version = 0x04F;
static const UINT16 kOTQuery_changes_filter_schema_specific = 0x050;
static const UINT16 kOTQuery_changes_request = 0x051;
static const UINT16 kOTError_HRESULT = 0x052;
static const UINT16 kOTQuery_changes_filter_data_element_IDs = 0x054;
static const UINT16 kOTUser_agent_GUID = 0x055;
static const UINT16 kOTQuery_changes_filter_data_element_type = 0x057;
static const UINT16 kOTQuery_changes_data_constraint = 0x059;
static const UINT16 kOTPut_changes_request = 0x05A;
static const UINT16 kOTQuery_changes_request_arguments = 0x05B;
static const UINT16 kOTQuery_changes_filter_cell_ID = 0x05C;
static const UINT16 kOTUser_agent = 0x05D;
static const UINT16 kOTQuery_changes_response = 0x05F;
static const UINT16 kOTQuery_changes_filter_hierarchy = 0x060;
static const UINT16 kOTResponse = 0x062;
static const UINT16 kOTError_cell = 0x066;
static const UINT16 kOTQuery_changes_filter_flags = 0x068;
static const UINT16 kOTData_element_fragment = 0x06A;
static const UINT16 kOTFragment_knowledge = 0x06B;
static const UINT16 kOTFragment_knowledge_entry = 0x06C;
static const UINT16 kOTObject_group_metadata_declarations = 0x79;
static const UINT16 kOTObject_group_metadata = 0x78;
static const UINT16 kOTAllocate_ExtendedGUID_range_request = 0x080;
static const UINT16 kOTAllocate_ExtendedGUID_range_response = 0x081;
static const UINT16 kOTTarget_Partition_Id = 0x83;
static const UINT16 kOTPut_Changes_Lock_Id = 0x85;
static const UINT16 kOTAdditional_Flags = 0x86;
static const UINT16 kOTPut_Changes_Response = 0x87;
static const UINT16 kOTRequest_hashing_options = 0x88;
static const UINT16 kOTDiagnostic_Request_Option_Output = 0x89;
static const UINT16 kOTDiagnostic_Request_Option_Input = 0x8A;
static const UINT16 kOTUserAgentClient_And_Platform = 0x8B;
static const UINT16 kOTRoot_Node = 0x20;
static const UINT16 kOTSignature_Header = 0x21;
static const UINT16 kOTData_Size_Header = 0x22;
static const UINT16 kOTIntermediate_Node = 0x1F;

//data element type
static const UINT16 kDETStorage_Index = 0x01;
static const UINT16 kDETStorage_Manifest = 0x02;
static const UINT16 kDETCell_Manifest = 0x03;
static const UINT16 kDETRevision_Manifest = 0x04;
static const UINT16 kDETObject_Group = 0x05;
static const UINT16 kDETData_Element_Fragment = 0x06;
static const UINT16 kDETObject_Data_BLOB = 0x0A;//request type
static const UINT16 kRTQuery_access = 1;
static const UINT16 kRTQuery_changes = 2;
static const UINT16 kRTPut_changes = 5;
static const UINT16 kRTAllocate_ExtendedGuid_range = 11;

//knowledge type guid
const WCHAR* const kKTCell_knowledge = L"{327A35F6-0761-4414-9686-51E900667A4D}";
const WCHAR* const kKTWaterline_knowledge = L"{3A76E90E-8032-4D0C-B9DD-F3C65029433E}";
const WCHAR* const kKTFragment_knowledge = L"{0ABE4F35-01DF-4134-A24A-7C79F0859844}";
const WCHAR* const kKTContent_tag_knowledge = L"{10091F13-C882-40FB-9886-6533F934C21D}";

//Object Change Frequency
static const UINT16 kCTFrequencyUnknow = 0;
static const UINT16 kCTFrequently = 1;
static const UINT16 kCTInfrequently = 2;
static const UINT16 kCTIndependently = 3;
static const UINT16 kCTCustom_frequencies = 4;

//query changes filter type
static const UINT16 kFTAll_filter = 1;
static const UINT16 kFTData_element_type_filter = 2;
static const UINT16 kFTStorage_index_referenced_data_elements_filter = 3;
static const UINT16 kFTCell_ID_filter = 4;
static const UINT16 kFTCustom_filter = 5;
static const UINT16 kFTData_element_IDs_filter = 6;
static const UINT16 kFTHierarchy_filter = 7;

//Query Changes Filter Data Element Type
static const UINT16 kFDETNone = 0;
static const UINT16 kFDETStorage_Index = 1;
static const UINT16 kFDETStorage_Manifest = 2;
static const UINT16 kFDETCell_Manifest = 3;
static const UINT16 kFDETRevision_Manifest = 4;
static const UINT16 kFDETObject_Group = 5;
static const UINT16 kFDETData_element_fragment = 6;
static const UINT16 kFDETObject_data_BLOB = 10;

//Error Type GUID
static const GUID kCellErrorTypeGUID = {0x5A66A756, 0x87CE, 0x4290, {0xA3,0x8B,0xC6,0x1C,0x5B,0xA0,0x5A,0x67}};
static const GUID kProtocolErrorTypeGUID = {0x7AFEAEBF, 0x033D, 0x4828, {0x9C,0x31,0x39,0x77,0xAF,0xE5,0x82,0x49}};
static const GUID kWin32ErrorTypeGUID = {0x32C39011, 0x6E39, 0x46C4, {0xAB,0x78,0xDB,0x41,0x92,0x9D,0x67,0x9E}};
static const GUID kHRESULTErrorTypeGUID = {0x8454C8F2, 0xE401, 0x405A, {0xA1,0x98,0xA1,0x0B,0x69,0x91,0xB5,0x6E}};

//knowledge type GUID
const GUID kCellKnowledgeGUID = {0x327A35F6, 0x0761, 0x4414, {0x96,0x86,0x51,0xE9,0x00,0x66,0x7A,0x4D}};
const GUID kWaterlineKnowledgeGUID = {0x3A76E90E, 0x8032, 0x4D0C, {0xB9,0xDD,0xF3,0xC6,0x50,0x29,0x43,0x3E}};
const GUID kFragmentKnowledgeGUID = {0x0ABE4F35, 0x01DF, 0x4134, {0xA2,0x4A,0x7C,0x79,0xF0,0x85,0x98,0x44}};
const GUID kContenttagKnowledgeGUID = {0x10091F13, 0xC882, 0x40FB, {0x98,0x86,0x65,0x33,0xF9,0x34,0xC2,0x1D}};

//request|response signature
static const UINT64 kRequestSignature = 0x9B069439F329CF9C;
static const UINT64 kResponseSignature = 0x9B069439F329CF9D;

//constant used in building response
const UINT16 kZipFileChunkSplitThreshold = 4096;
const GUID kContentSchemaGUID = {0x0EB93394, 0x571D, 0x41E9, {0xAA, 0xD3, 0x88, 0x0D, 0x92, 0xD3, 0x19, 0x55}};
const GUID kDeclareSchemaGUID = {0x1AC27DE8, 0x152D, 0x4D52, {0x8B,0x6E,0xBB,0x16,0x6A,0xF3,0x50,0x2F}};
const GUID kContentRootGUID = {0x84DEFAB9, 0xAAA3, 0x4A0D, {0xA3,0xA8,0x52,0x0C,0x77,0xAC,0x70,0x73}};
const ExGUID kContentRootExGUID(0x2, kContentRootGUID);
const GUID kRootCellidFirstGUID = {0x84DEFAB9, 0xAAA3, 0x4A0D, {0xA3,0xA8,0x52,0x0C,0x77,0xAC,0x70,0x73}};
const ExGUID kRootCellidFirstExGUID(0x1, kRootCellidFirstGUID);
const GUID kRootCellidSecondGUID = {0x6F2A4665, 0x42C8, 0x46C7, {0xBA,0xB4,0xE2,0x8F,0xDC,0xE1,0xE3,0x2B}};
const ExGUID kRootCellidSecondExGUID(0x1, kRootCellidSecondGUID);
const Cell_ID kContentRootCellID(kRootCellidFirstExGUID, kRootCellidSecondExGUID);

const GUID kMetadataRootGUID = {0xEDF48BAC, 0x3745, 0x4416, {0xA4,0xC9,0xD5,0xB7,0x1B,0xB8,0x70,0xF6}};
const ExGUID kMetadataRootExGUID(0x2, kMetadataRootGUID);

const GUID kNullGuid = {0};
const GUID kDeclareQCRequestPartitionId = {0xBBD4E3C0, 0x21B4, 0x463D, {0x92,0x79,0x9C,0x5A,0x94,0x06,0xAA,0x8F}};
const GUID kContentQCRequestPartitionId = kNullGuid;
const GUID kMetadataQCRequestPartitionId = {0x383adc0b, 0xe66e, 0x4438, {0x95,0xe6,0xe3,0x9e,0xf9,0x72,0x01,0x22}};
const GUID kEditortableQCRequestPartitionId = {0x7808f4dd, 0x2385, 0x49d6, {0xb7,0xce,0x37,0xac,0xa5,0xe4,0x36,0x02}};
const GUID kDeclareQCResopnseStorageManifestSchemeId = {0x1AC27DE8, 0x152D, 0x4D52, {0x8B,0x6E,0xBB,0x16,0x6A,0xF3,0x50,0x2F}};
const GUID kFirstWaterlineKnowledgeEntryGuid = {0xD0F2B81C, 0x4A2B, 0x4DFE, {0x53,0xA7,0xF4,0xC0,0xF2,0xAA,0x7E,0xC1}};
const ExGUID kFirstWaterlineKnowledgeEntryExGuid(0x1, kFirstWaterlineKnowledgeEntryGuid);

const GUID kContentTagKnowledgeBlobHeapGuid1 = {0xE047B4FD, 0xEF92, 0x41DF, {0x9C,0x1D,0x2E,0x66,0xC6,0x4E,0x57,0xA5}};
const ExGUID kContentTagKnowledgeBlobHeapExGuid1(0x1, kContentTagKnowledgeBlobHeapGuid1);
const ExGUID kContentTagKnowledgeBlobHeapExGuid2(0x1, kFirstWaterlineKnowledgeEntryGuid);
const GUID kContentTagKnowledgeBlobHeapGuid3 = {0x60D8C359, 0x88AE, 0x43ED, {0x95,0x64,0xC4,0x43,0x35,0x52,0x52,0x9D}};
const ExGUID kContentTagKnowledgeBlobHeapExGuid3(0x1, kContentTagKnowledgeBlobHeapGuid3);
