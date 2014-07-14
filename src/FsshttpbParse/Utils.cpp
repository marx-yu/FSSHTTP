// Copyright 2014 The Authors Marx-Yu. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "StdAfx.h"
#include "Utils.h"
#include <objbase.h>
#include <stdarg.h>
#include "Digest.h"
#include "JsonParser.h"
#include <sstream>

static StreamObjectTypeMap g_object_type_map;

File::File( const wstring& filename, OpenMode om /*= READ*/ )
{
	hfile_ = ::CreateFile(filename.c_str(),
		om == READ? GENERIC_READ : GENERIC_READ|GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		om == READ? OPEN_EXISTING : OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hfile_ == INVALID_HANDLE_VALUE)
	{
		printf("open failed, %d\n", GetLastError());
		hfile_ = NULL;
	}
	if (om == TRUNCATE)
		SetEndOfFile(hfile_);
	else if (om == APPEND)
		SetFilePointer(hfile_, 0, NULL, FILE_END);
}


File::~File()
{
	if (hfile_ != NULL)
		::CloseHandle(hfile_);
}
size_t File::length()
{
	LARGE_INTEGER filesize = {0};
	GetFileSizeEx(hfile_, &filesize);
	return filesize.QuadPart;
}

size_t File::read( size_t offset, void* dst, size_t count )
{
	if (hfile_ == NULL)
		return 0;
	DWORD readed = 0;
	BOOL bRet = ::ReadFile(hfile_,
		dst,
		count,
		&readed,
		NULL);
	return readed;
}

size_t File::write( const void* src, size_t count )
{
	if (hfile_ == NULL)
		return 0;
	DWORD writed = 0;
	::WriteFile(hfile_, src, count, &writed, NULL);
	return writed;
}


bool readContent( const wstring& filename, UINT *filesize, Byte** ret_buf )
{
	File file(filename, File::READ);
	DWORD dwBytesToRead = file.length();
	
	Byte* buffer = new Byte[dwBytesToRead];
	memset(buffer, 0x00, dwBytesToRead);
	
	DWORD dwBytesRead = file.read(0, buffer, dwBytesToRead);

	if (dwBytesToRead != dwBytesRead)
	{
		printf("read file failed\n");
		delete[] buffer;
		return false;
	}

	*filesize = dwBytesToRead;
	*ret_buf = buffer;
	return true;
}

bool writeFile(const wstring& filename, const Byte* buf, UINT size)
{
	File file(filename, File::TRUNCATE);

	DWORD writed = file.write(buf, size);
	
	return (writed == size);
}

wstring toString( UINT64 value )
{
	wstring str;
	WCHAR buf[20] = {0};
	swprintf_s(buf, L"%llu", value);
	str += buf;
	
	return str;
}

wstring toString( const GUID& guid )
{
	WCHAR buf[20] = {0};
	wstring str = L"{";
	swprintf_s(buf, L"%08X", guid.Data1);
	str += buf;
	str += L"-";
	swprintf_s(buf, L"%04X", guid.Data2);
	str += buf;
	str += L"-";
	swprintf_s(buf, L"%04X", guid.Data3);
	str += buf;
	str += L"-";
	for (int i=0; i < 2; i++)
	{
		swprintf_s(buf, L"%02X", guid.Data4[i]);
		str += buf;
	}
	str += L"-";
	for (int i=2; i < 8; i++)
	{
		swprintf_s(buf, L"%02X", guid.Data4[i]);
		str += buf;
	}
	str += L"}";
	
	return str;
}

wstring toString( const ExGUID& exguid )
{
	wstring str = L"Value=";
	WCHAR buf[20] = {0};
	swprintf_s(buf, L"0x%X", exguid.value);
	str += buf;
	str += L" Guid=";
	str += toString(exguid.guid);

	return str;

}

wstring toString( const SerialNumber& sn )
{
	wstring str = L"Guid=";
	str += toString(sn.guid);
	
	str += L" Value=";
	WCHAR buf[20] = {0};
	swprintf_s(buf, L"0x%X", sn.value);
	str += buf;

	return str;
}

wstring toString( const Cell_ID& cellid )
{
	wstring str = L"FirstExGuid:";
	str += toString(cellid.exguid_first);
	str += L"  SecondExGuid:";
	str += toString(cellid.exguid_second);
	
	return str;
}

wstring toString( const CompactUint64& cu64 )
{
	wstring str = L"Value=";
	WCHAR buf[20] = {0};
	swprintf_s(buf, L"%llu", cu64.value);
	str += buf;

	return str;
}

wstring toString( const ObjectHeader& oh )
{
	wstring str = L"ObjectHeader:0x";
	WCHAR buf[20] = {0};
	for (UINT16 i = 0; i < oh.bytes_use; i++)
	{
		swprintf_s(buf, L"%02X", oh.bytes[i]);
		str += buf;
	}
	str += L", ";
	
	swprintf_s(buf, L"Type=0x%X, ", oh.object_type);
	str += buf;

	if (oh.header_type == kOHBit16Start || oh.header_type == kOHBit32Start)
	{
		swprintf_s(buf, L"Len=%u, ", oh.length);
		str += buf;
		swprintf_s(buf, L"com=%d ", oh.compound? 1 : 0);
		str += buf;
	}
	StreamObjectTypeMap::iterator iter = g_object_type_map.find(oh.object_type);
	if (iter != g_object_type_map.end())
	{
		str += iter->second.describe;
	}
	else
	{
		assert(false);
	}
	str += L" ";
	if (oh.header_type == kOHBit16Start || oh.header_type == kOHBit32Start)
		if (oh.compound)
			str += L"Start";
		else
			str += L"Flag";
	else
		str += L"End";

	return str;
}

wstring toString( const ExGUIDArray& exguid_array )
{
	wstring str;
	str += L"Count: " + toString(exguid_array.count);
	str += L" [";
	for (UINT64 i = 0; i < exguid_array.count.value; i++)
	{
		str += toString(exguid_array.content[i]);
		if (i < exguid_array.count.value - 1)
			str += L", ";
	}
	str += L"]";

	return str;
}

wstring toString( const CellIDArray& cellid_array )
{
	wstring str;
	str += L"Count: " + toString(cellid_array.count);
	str += L" [";
	for (UINT64 i = 0; i < cellid_array.count.value; i++)
	{
		str += toString(cellid_array.content[i]);
		if (i < cellid_array.count.value - 1)
			str += L", ";
	}
	str += L"]";

	return str;
}

wstring toString( const BinaryItem& binaryitem )
{
	wstring str;
	str += L"Length: " + toString(binaryitem.length);
	str += L" [";
	WCHAR buf[8] = {0};
	for (UINT16 i = 0; i < binaryitem.example_len; i++)
	{
		swprintf_s(buf, L"%02X", binaryitem.start[i]);
		str += buf;
	}

	if (binaryitem.length.value > binaryitem.example_len * 2)
		str += L"...";

	for (UINT16 i = 0; i < binaryitem.example_len; i++)
	{
		swprintf_s(buf, L"%02X", binaryitem.end[i]);
		str += buf;
	}
	str += L"]";

	return str;
}

string toString( const wstring &str )
{
	if (str.empty())
		return string();

	int size = ::WideCharToMultiByte(CP_UTF8,
		0,
		str.c_str(),
		-1,
		0,
		0,
		0,
		0);
	string nstr;
	nstr.resize(size-1);
	::WideCharToMultiByte(CP_UTF8,
		0,
		str.c_str(),
		-1,
		&nstr[0],
		size,
		0,
		0);
	return nstr;
}

wstring toString( const string &str )
{
	if (str.empty())
		return wstring();
	int size = ::MultiByteToWideChar(CP_UTF8,
		0,
		str.c_str(),
		-1,
		0,
		0);
	wstring wnstr;
	wnstr.resize(size-1);
	::MultiByteToWideChar(CP_UTF8,
		0,
		str.c_str(),
		-1,
		&wnstr[0],
		size);
	return wnstr;
}


wstring DataElementType2Str(const UINT64& type)
{
	wstring str;
	switch (type)
	{
	case kDETStorage_Index:
		str = L"Storage Index (section 2.2.1.12.2)";
		break;
	case kDETStorage_Manifest:
		str = L"Storage Manifest (section 2.2.1.12.3)";
		break;
	case kDETCell_Manifest:
		str = L"Cell Manifest (section 2.2.1.12.4)";
		break;
	case kDETRevision_Manifest:
		str = L"Revision Manifest (section 2.2.1.12.5)";
		break;
	case kDETObject_Group:
		str = L"Object Group (section 2.2.1.12.6)";
		break;
	case kDETData_Element_Fragment:
		str = L"Data Element Fragment (section 2.2.1.12.7)";
		break;
	case kDETObject_Data_BLOB:
		str = L"Object Data BLOB (section 2.2.1.12.8)";
		break;
	default:
		assert(false);
	}
	return str;
}

wstring RequestType2Str( const UINT64& type )
{
	wstring str;
	switch(type)
	{
	case kRTQuery_access:
		str = L"Query access.";
		break;
	case kRTQuery_changes:
		str = L"Query changes.";
		break;
	case kRTPut_changes:
		str = L"Put changes.";
		break;
	case kRTAllocate_ExtendedGuid_range:
		str = L"Allocate ExtendedGuid range.";
		break;
	default:
		assert(false);
	}
	return str;
}

wstring KnowledgeTypeGuid2Str( const wstring& guid )
{
	wstring str;
	if (guid == kKTCell_knowledge)
	{
		str = L"Cell knowledge (section 2.2.1.13.2)";
	}
	else if (guid == kKTWaterline_knowledge)
	{
		str = L"Waterline knowledge (section 2.2.1.13.4)";
	}
	else if (guid == kKTFragment_knowledge)
	{
		str = L"Fragment knowledge (section 2.2.1.13.3)";
	}
	else if (guid == kKTContent_tag_knowledge)
	{
		str = L"Content tag knowledge (section 2.2.1.13.5)";
	}
	else
	{
		assert(false);
	}
	return str;
}

wstring ObjectChangeFrequency2Str(const UINT64& frequency)
{
	wstring str;
	switch(frequency)
	{
	case kCTFrequencyUnknow:
		str = L"the change frequency is not known.";
		break;
	case kCTFrequently:
		str = L"the object is known to change frequently.";
		break;
	case kCTInfrequently:
		str = L"the object is known to change infrequently.";
		break;
	case kCTIndependently:
		str = L"the object is known to change independently of any other objects.";
		break;
	case kCTCustom_frequencies:
		str = L"the object is known to change in custom frequencies.";
		break;
	default:
		str = L"This value undefined";
	}

	return str;
}

wstring FilterType2Str(Byte type)
{
	wstring str;
	switch(type)
	{
	case kFTAll_filter:
		str = L"All filter (section 2.2.2.1.3.1.1)";
		break;
	case kFTData_element_type_filter:
		str = L"Data element type filter";
		break;
	case kFTStorage_index_referenced_data_elements_filter:
		str = L"Storage index referenced data elements filter";
		break;
	case kFTCell_ID_filter:
		str = L"Cell ID filter (section 2.2.2.1.3.1.4)";
		break;
	case kFTCustom_filter:
		str = L"Custom filter (section 2.2.2.1.3.1.5)";
		break;
	case kFTData_element_IDs_filter:
		str = L"Data element IDs filter";
		break;
	case kFTHierarchy_filter:
		str = L"Hierarchy filter (section 2.2.2.1.3.1.7).";
		break;
	default:
		assert(false);
	}

	return str;
}

wstring QueryChangesFilterDataElementType2Str(const UINT64& type)
{
	wstring str;
	switch (type)
	{
	case kFDETNone:
		str = L"None.";
		break;
	case kFDETStorage_Index:
		str = L"Storage Index.";
		break;
	case kFDETStorage_Manifest:
		str = L"Storage Manifest.";
		break;
	case kFDETCell_Manifest:
		str = L"Cell Manifest.";
		break;
	case kFDETRevision_Manifest:
		str = L"Revision Manifest.";
		break;
	case kFDETObject_Group:
		str = L"Object Group.";
		break;
	case kFDETData_element_fragment:
		str = L"Data element fragment.";
		break;
	case kFDETObject_data_BLOB:
		str = L"Object data BLOB.";
		break;
	default:
		assert(false);
	}

	return str;
}

wstring DepthMeaning2Str(Byte depth)
{
	wstring str;
	switch(depth)
	{
	case 0:
		str = L"Index values corresponding to the specified keys only.";
		break;
	case 1:
		str = L"First data elements referenced by the storage index values corresponding to the specified keys only.";
		break;
	case 2:
		str = L"Single level. All data elements under the sub-graphs rooted by the specified keys stopping at any storage index entries.";
		break;
	case 3:
		str = L"Deep. All data elements and storage index entries under the sub-graphs rooted by the specified keys.";
		break;
	default:
		assert(false);
	}

	return str;
}

wstring ErrorTypeGUID2Str(const GUID& type)
{
	wstring str;
	if (type == kCellErrorTypeGUID)
	{
		str = L"Cell error (section 2.2.3.2.1).";
	}
	else if (type == kWin32ErrorTypeGUID)
	{
		str = L"Win32 error (section 2.2.3.2.3).";
	}
	else if (type == kProtocolErrorTypeGUID)
	{
		str = L"Protocol error (section 2.2.3.2.2).";
	}
	else if (type == kHRESULTErrorTypeGUID)
	{
		str = L"HRESULT error (section 2.2.3.2.4).";
	}
	else
	{
		assert(false);
	}

	return str;
}

void initStreamObjectTypeMap()
{
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x01, StreamObjectType(L"Data element.", 0x01, 1)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x02, StreamObjectType(L"Object data BLOB.", 0x02, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x03, StreamObjectType(L"Object group object excluded data.",  0x03, 0 )));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x04, StreamObjectType(L"Waterline knowledge entry (section 2.2.1.13.4.1).", 0x04, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x05, StreamObjectType(L"Object group object BLOB data declaration.", 0x05, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x06, StreamObjectType(L"Data element hash.", 0x06, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x07, StreamObjectType(L"Storage manifest root declare.", 0x07, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x0A, StreamObjectType(L"Revision manifest root declare.", 0x0A, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x0B, StreamObjectType(L"Cell manifest current revision.", 0x0B, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x0C, StreamObjectType(L"Storage manifest schema GUID.", 0x0C, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x0D, StreamObjectType(L"Storage index revision mapping.", 0x0D, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x0E, StreamObjectType(L"Storage index cell mapping.", 0x0E, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x0F, StreamObjectType(L"Cell knowledge range (section 2.2.1.13.2.1).", 0x0F, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x10, StreamObjectType(L"Knowledge (section 2.2.1.13).", 0x10, 1)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x11, StreamObjectType(L"Storage index manifest mapping.", 0x11, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x14, StreamObjectType(L"Cell Knowledge (section 2.2.1.13.2).", 0x14, 1)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x15, StreamObjectType(L"Data element package.", 0x15, 1)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x16, StreamObjectType(L"Object group object data.", 0x16, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x17, StreamObjectType(L"Cell knowledge entry (section 2.2.1.13.2.2).", 0x17, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x18, StreamObjectType(L"Object group object declare.", 0x18, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x19, StreamObjectType(L"Revision manifest object group references.", 0x19, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x1A, StreamObjectType(L"Revision manifest.", 0x1A, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x1C, StreamObjectType(L"Object group object data BLOB reference.", 0x1C, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x1D, StreamObjectType(L"Object group declarations.", 0x1D, 1)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x1E, StreamObjectType(L"Object group data.", 0x1E, 1)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x29, StreamObjectType(L"Waterline knowledge (section 2.2.1.13.4).", 0x29, 1)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x2D, StreamObjectType(L"Content tag knowledge (section 2.2.1.13.5).", 0x2D, 1)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x2E, StreamObjectType(L"Content tag knowledge entry.", 0x2E, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x040, StreamObjectType(L"Request.", 0x040, 1)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x041, StreamObjectType(L"Sub-response.", 0x041, 1)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x042, StreamObjectType(L"Sub-request.", 0x042, 1)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x043, StreamObjectType(L"Read access response.", 0x043, 1)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x044, StreamObjectType(L"Specialized knowledge.", 0x044, 1)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x046, StreamObjectType(L"Write access response.", 0x046, 1)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x047, StreamObjectType(L"Query changes filter.", 0x047, 1)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x049, StreamObjectType(L"Error Win32.", 0x049, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x04B, StreamObjectType(L"Error Protocol.", 0x04B, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x04D, StreamObjectType(L"Error.", 0x04D, 1)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x04E, StreamObjectType(L"Error String Supplemental Info.", 0x04E, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x04F, StreamObjectType(L"User agent version.", 0x04F, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x050, StreamObjectType(L"Query changes filter schema specific.", 0x050, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x051, StreamObjectType(L"Query changes request.", 0x051, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x052, StreamObjectType(L"Error HRESULT.", 0x052, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x054, StreamObjectType(L"Query changes filter data element IDs.", 0x054, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x055, StreamObjectType(L"User agent GUID.", 0x055, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x057, StreamObjectType(L"Query changes filter data element type.", 0x057, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x059, StreamObjectType(L"Query changes data constraint.", 0x059, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x05A, StreamObjectType(L"Put changes request.", 0x05A, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x05B, StreamObjectType(L"Query changes request arguments.", 0x05B, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x05C, StreamObjectType(L"Query changes filter cell ID.", 0x05C, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x05D, StreamObjectType(L"User agent.", 0x05D, 1)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x05F, StreamObjectType(L"Query changes response.", 0x05F, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x060, StreamObjectType(L"Query changes filter hierarchy.", 0x060, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x062, StreamObjectType(L"Response.", 0x062, 1)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x066, StreamObjectType(L"Error cell.", 0x066, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x068, StreamObjectType(L"Query changes filter flags.", 0x068, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x06A, StreamObjectType(L"Data element fragment.", 0x06A, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x06B, StreamObjectType(L"Fragment knowledge.", 0x06B, 1)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x06C, StreamObjectType(L"Fragment knowledge entry.", 0x06C, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x79, StreamObjectType(L"Object group metadata declarations.", 0x79, 1)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x78, StreamObjectType(L"Object group metadata.", 0x78, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x080, StreamObjectType(L"Allocate ExtendedGUID range request (section 2.2.2.1.5).", 0x080, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x081, StreamObjectType(L"Allocate ExtendedGUID range response (section 2.2.3.1.4).", 0x081, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x83, StreamObjectType(L"Target Partition Id. (section 2.2.2.1.1).", 0x83, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x85, StreamObjectType(L"Put Changes Lock Id. (section 2.2.2.1.4.2)", 0x85, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x86, StreamObjectType(L"Additional Flags. (section 2.2.2.1.4.1)", 0x86, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x87, StreamObjectType(L"Put Changes Response.", 0x87, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x88, StreamObjectType(L"Request hashing options.", 0x88, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x89, StreamObjectType(L"Diagnostic Request Option Output (section 2.2.3.1.3.1)", 0x89, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x8A, StreamObjectType(L"Diagnostic Request Option Input (section 2.2.2.1.4.3)", 0x8A, 0)));
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x8B, StreamObjectType(L"UserAgentClientAndPlatform", 0x8B, 0)));

	//used in [FSSHTTPD]
	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x20,  StreamObjectType(L"Root Node", 0x20, 1)));	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x21,  StreamObjectType(L"Signature Header", 0x21, 0)));	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x22,  StreamObjectType(L"Data Size Header", 0x22, 0)));	g_object_type_map.insert(StreamObjectTypeMap::value_type(0x1F,  StreamObjectType(L"Intermediate Node", 0x1F, 1)));
}


bool generateSha1( const Byte* data, size_t size, Byte* result )
{
	Byte buf[21] = {0};
	ZEN_LIB::sha1(data, size, buf);
	memcpy(result, buf, 20);
	return true;
}

bool generateGUID( GUID* guid )
{
	CoInitialize(NULL);
	HRESULT hr =::CoCreateGuid(guid);
	CoUninitialize();

	return SUCCEEDED(hr);
}

void exmemset( void* dst, UINT64 val, size_t size )
{
	Byte *bp = (Byte *)&val;
	Byte *dp = (Byte *)dst;
	for ( ; size> 0; size--)
	{
		memcpy(dp++, bp + size -1, 1);
	}
}

void pushSerialContent( SmartBuf& result_buf, const void* src, const size_t& size )
{
	size_t offset = result_buf.size();
	result_buf.resize(offset + size);
	memcpy(&result_buf[offset], src, size);
}

void pushSerialContent(SmartBuf& result_buf, const UINT64& value, const size_t& size)
{
	size_t offset = result_buf.size();
	result_buf.resize(offset + size);
	exmemset(&result_buf[offset], value, size);
}

size_t parseBatch( const Byte* bytes, ... )
{
	size_t bytes_used = 0;
	va_list arg_ptr;

	va_start(arg_ptr, bytes);
	CobaltObject* obj = NULL;
	while((obj = va_arg(arg_ptr, CobaltObject*)) != NULL)
	{
		obj->parse(bytes + bytes_used);
		bytes_used += obj->used();
	}
	va_end(arg_ptr);
	
	return bytes_used;
}

size_t serializeBatch( Byte* result, ... )
{
	size_t bytes_used = 0;
	va_list arg_ptr;

	va_start(arg_ptr, result);
	CobaltObject* obj = NULL;
	while((obj = va_arg(arg_ptr, CobaltObject*)) != NULL)
	{
		obj->serialize(result + bytes_used);
		bytes_used += obj->used();
	}
	va_end(arg_ptr);

	return bytes_used;
}

GUID deserializeGuid(const string& guid_str)
{
	GUID ret = {0};
	string temp = guid_str.substr(0, 8);
	ret.Data1 = strtoul(temp.c_str(), NULL, 16);
	temp = guid_str.substr(9, 4);
	ret.Data2 = strtoul(temp.c_str(), NULL, 16);
	temp = guid_str.substr(14, 4);
	ret.Data3 = strtoul(temp.c_str(), NULL, 16);
	temp = guid_str.substr(19, 2);
	ret.Data4[0] = strtoul(temp.c_str(), NULL, 16);
	temp = guid_str.substr(21, 2);
	ret.Data4[1] = strtoul(temp.c_str(), NULL, 16);
	for (int i = 0; i < 6; i++)
	{
		temp = guid_str.substr(24+ i*2, 2);
		ret.Data4[2+i] = strtoul(temp.c_str(), NULL, 16);
	}

	return ret;
}

