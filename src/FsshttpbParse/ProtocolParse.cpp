// Copyright 2014 The Authors Marx-Yu. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "StdAfx.h"
#include "ProtocolParse.h"
#include "Digest.h"

bool decodeContent(UINT* content_size, Byte** cont_buf)
{
	Byte* bytes = *cont_buf;
	UINT64 signature = *((UINT64*)(bytes + 4));
	if (signature == kRequestSignature || signature == kResponseSignature)
	{
		return true;		//nothing need to do
	}
	else
	{
		//may be xml struct
		string line((const char*)bytes, 100);
		if (line.find("RequestVersion") != string::npos)
		{
			//xml cell request
			string request_str((const char*)bytes, *content_size);
			size_t subrequestdata_index = request_str.find("<SubRequestData");
			size_t data_start_flag = request_str.find(">", subrequestdata_index);
			data_start_flag += 1;
			size_t data_end_flag = request_str.find("</SubRequestData>", data_start_flag);
			size_t b64_len = data_end_flag - data_start_flag;
			if (subrequestdata_index == string::npos || data_end_flag == string::npos || b64_len < 8)
				goto FAILED_END;
			request_str = request_str.substr(data_start_flag, b64_len);
			*content_size = base64_decode(request_str.c_str(), *cont_buf);
		}
		else if (line.find("ResponseVersion") != string::npos)
		{
			//xml cell response
			string response_str((const char*)bytes, *content_size);
			size_t subresponsedata_index = response_str.find("<SubResponseData");
			size_t data_start_flag = response_str.find(">", subresponsedata_index);
			data_start_flag += 1;
			size_t data_end_flag = response_str.find("</SubResponseData>", data_start_flag);
			size_t b64_len = data_end_flag - data_start_flag;
			if (subresponsedata_index == string::npos || data_end_flag == string::npos || b64_len < 8)
				goto FAILED_END;
			response_str = response_str.substr(data_start_flag, b64_len);

			*content_size = base64_decode(response_str.c_str(), *cont_buf);
		}
		else
		{
			goto FAILED_END;
		}
	}

	return true;

FAILED_END:
	return false;
}

void parserSelector(const Byte* bytes, size_t size, Log& logfile)
{
	UINT64 signature = *((UINT64*)(bytes + 4));
	if (signature == kRequestSignature)
	{
		parseRequest(bytes, logfile);
	}
	else if (signature == kResponseSignature)
	{
		parseResponse(bytes, logfile);
	}
	else
	{
		printf("invalid packet file\n");
	}	
}

void parseResponse( const Byte* bytes, Log& logfile )
{
	UINT64 offset = 0;
	wstring logmsg;
	ObjectHeader object_header;
	CompactUint64 cuint64;
	bool failed_response = false;
	logmsg = L"Protocol version and Signature";
	logfile.log(offset, logmsg);
	offset += 12;
	object_header.parse(bytes + offset);
	if (object_header.object_type != kOTResponse)
		goto FAILED_END;
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;
	
	failed_response = ((bytes + offset)[0] & 0x1) == 0x1;
	logfile.log(wstring(L"A - Status: ") + (failed_response? L"Failed" : L"Success"));
	if (failed_response)
	{
		logfile.log(L"This a failed response");
		goto FAILED_END;
	}
	offset += 1;
	
	//data element package
	parseDataElementPackage(bytes, offset, logfile);

	//sub response
	parseSubResponse(bytes, offset, logfile);

	//response end
	object_header.parse(bytes + offset);
	if (object_header.object_type != kOTResponse)
		goto FAILED_END;
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;

	//finish
	printf("parse successfully!!\n");
	return;

FAILED_END:
	printf("parse failed, current offset:0x%X\n", offset);
}

void parseDataElementPackage(const Byte* bytes, UINT64& offset,Log& logfile)
{
	ObjectHeader object_header;
	ExGUID exguid;
	SerialNumber serial_num;
	CompactUint64 cuint64;
	object_header.parse(bytes + offset);
	if (object_header.object_type != kOTData_element_package)
		goto FAILED_END;
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;
	logfile.log(L"1 byte Reserved");
	offset += 1;
	
	while(true)
	{
		object_header.parse(bytes + offset);
		if (object_header.object_type == kOTData_element_package)
			//data element package end
			break;

		if (object_header.object_type != kOTData_element)
			goto FAILED_END;
		logfile.log(offset, toString(object_header));
		offset += object_header.bytes_use;

		exguid.parse(bytes + offset);
		logfile.log(L"Data Element Extended GUID: " + toString(exguid));
		offset += exguid.bytes_use;
		serial_num.parse(bytes + offset);
		logfile.log(L"Data Element Serial Number: " + toString(serial_num));
		offset += serial_num.bytes_use;
		cuint64.parse(bytes + offset);
		logfile.log(L"Data Element Type: " + toString(cuint64) + L" " + DataElementType2Str(cuint64.value));
		offset += cuint64.bytes_use;

		switch (cuint64.value)
		{
		case kDETStorage_Index:
			parseStorageIndexDataElement(bytes, offset, logfile);
			break;
		case kDETStorage_Manifest:
			parseStorageManifestDataElement(bytes, offset, logfile);
			break;
		case kDETCell_Manifest:
			parseCellManifestDataElement(bytes, offset, logfile);
			break;
		case kDETRevision_Manifest:
			parseRevisionManifestDataElement(bytes, offset, logfile);
			break;
		case kDETObject_Group:
			parseObjectGroupDataElement(bytes, offset, logfile);
			break;
		case kDETData_Element_Fragment:
			goto FAILED_END;
			break;
		case kDETObject_Data_BLOB:
			parseObjectDataBlobDataElement(bytes, offset, logfile);
			break;
		default:
			assert(false);
		}
	}

	//data element package end
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;
	return;

FAILED_END:
		printf("parse failed, current offset:0x%X\n", offset);
}

void parseObjectGroupDataElement( const Byte* bytes, UINT64& offset,Log& logfile )
{
	ObjectHeader object_header;
	ExGUID exguid;
	SerialNumber serial_num;
	CompactUint64 cuint64;
	ExGUIDArray exguid_array;
	CellIDArray cellid_array;
	BinaryItem data;
	object_header.parse(bytes + offset);
	if (object_header.object_type != kOTObject_group_declarations)
		goto FAILED_END;
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;

	while(true)
	{
		object_header.parse(bytes + offset);
		if (object_header.object_type == kOTObject_group_declarations)
			break;	//object group end

		if (object_header.object_type == kOTObject_group_object_declare || object_header.object_type == kOTObject_group_object_BLOB_data_declaration)
		{
			logfile.log(offset, toString(object_header));
			offset += object_header.bytes_use;
			exguid.parse(bytes + offset);
			logfile.log(L"Object Extended GUID: " + toString(exguid));
			offset += exguid.bytes_use;

			if (object_header.object_type == kOTObject_group_object_BLOB_data_declaration)
			{
				exguid.parse(bytes + offset);
				logfile.log(L"Object Data BLOB EXGUID: " + toString(exguid));
				offset += exguid.bytes_use;
			}
			cuint64.parse(bytes + offset);
			logfile.log(L"Object Partition ID: " + toString(cuint64));
			offset += cuint64.bytes_use;

			if (object_header.object_type == kOTObject_group_object_declare)
			{
				cuint64.parse(bytes + offset);
				logfile.log(L"Object Data Size: " + toString(cuint64));
				offset += cuint64.bytes_use;
			}

			cuint64.parse(bytes + offset);
			logfile.log(L"Object References Count: " + toString(cuint64));
			offset += cuint64.bytes_use;

			cuint64.parse(bytes + offset);
			logfile.log(L"Cell References Count: " + toString(cuint64));
			offset += cuint64.bytes_use;
		}
		else
		{
			goto FAILED_END;
		}
		
	}

	//object group end
	if (object_header.object_type != kOTObject_group_declarations || object_header.header_type != kOHBit8End)
		goto FAILED_END;
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;


	object_header.parse(bytes + offset);
	if (object_header.object_type == kOTObject_group_metadata_declarations)
	{
		logfile.log(offset, toString(object_header));
		offset += object_header.bytes_use;
		while(true)
		{
			object_header.parse(bytes + offset);
			if (object_header.object_type == kOTObject_group_metadata_declarations)
				break;	//meta declaration end

			if (object_header.object_type != kOTObject_group_metadata)
				goto FAILED_END;
			logfile.log(offset, toString(object_header));
			offset += object_header.bytes_use;
			
			cuint64.parse(bytes + offset);
			logfile.log(L"Object Change Frequency: " + toString(cuint64) + L" " + ObjectChangeFrequency2Str(cuint64.value));
			offset += cuint64.bytes_use;
		}

		//meta declaration end
		logfile.log(offset, toString(object_header));
		offset += object_header.bytes_use;

		//for next object
		object_header.parse(bytes + offset);
	}
	
	if (object_header.object_type != kOTObject_group_data)
		goto FAILED_END;
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;
	
	while (true)
	{
		object_header.parse(bytes + offset);
		if (object_header.object_type == kOTObject_group_data)
			break; //object group data end
		
		if (object_header.object_type == kOTObject_group_object_data || object_header.object_type == kOTObject_group_object_data_BLOB_reference)
		{
			logfile.log(offset, toString(object_header));
			offset += object_header.bytes_use;

			exguid_array.parse(bytes + offset);
			logfile.log(L"Object Extended GUID Array: " + toString(exguid_array));
			offset += exguid_array.bytes_use;

			cellid_array.parse(bytes + offset);
			logfile.log(L"Cell ID Array: " + toString(cellid_array));
			offset += cellid_array.bytes_use;

			if (object_header.object_type == kOTObject_group_object_data)
			{
				data.parse(bytes + offset);
				logfile.log(L"Object Group Object Data: " + toString(data));	
				//it is a node object, see [FSSHTTPD] section 2.2.4
				parseNodeObject(bytes, offset + data.length.used(), logfile);
				offset += data.bytes_use;
			}
			else
			{
				exguid.parse(bytes + offset);
				logfile.log(L"BLOB Extended GUID: " + toString(exguid));
				offset += exguid.bytes_use;
			}			
		}
		else
		{
			goto FAILED_END;
		}
		

	}

	//object group data end
	if (object_header.object_type != kOTObject_group_data || object_header.header_type != kOHBit8End)
		goto FAILED_END;
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;
	object_header.parse(bytes + offset);
	if (object_header.object_type != kOTData_element)
		goto FAILED_END;
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;

	return;
FAILED_END:
	printf("parse failed, current offset:0x%X\n", offset);
}

void parseObjectDataBlobDataElement( const Byte* bytes, UINT64& offset, Log& logfile )
{
	ObjectHeader object_header;

	object_header.parse(bytes + offset);
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;

	BinaryItem data;
	data.parse(bytes + offset);
	logfile.log(L"Blob Data: " + toString(data));
	offset += data.bytes_use;

	object_header.parse(bytes + offset);
	if (object_header.object_type != kOTData_element)
		goto FAILED_END;
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;

	return;
FAILED_END:
	printf("parse failed, current offset:0x%X\n", offset);

}

void parseRevisionManifestDataElement( const Byte* bytes, UINT64& offset,Log& logfile )
{
	ObjectHeader object_header;
	ExGUID exguid;
	SerialNumber serial_num;
	CompactUint64 cuint64;

	object_header.parse(bytes + offset);
	if (object_header.object_type != kOTRevision_manifest)
		goto FAILED_END;
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;

	exguid.parse(bytes + offset);
	logfile.log(L"Revision ID: " + toString(exguid));
	offset += exguid.bytes_use;

	exguid.parse(bytes + offset);
	logfile.log(L"Base Revision ID: " + toString(exguid));
	offset += exguid.bytes_use;

	while (true)
	{
		object_header.parse(bytes + offset);
		if (object_header.object_type == kOTData_element)
			//data element end
			break;
		logfile.log(offset, toString(object_header));
		offset += object_header.bytes_use;

		if (object_header.object_type == kOTRevision_manifest_root_declare)
		{
			exguid.parse(bytes + offset);
			logfile.log(L"Root Extended GUID: " + toString(exguid));
			offset += exguid.bytes_use;

			exguid.parse(bytes + offset);
			logfile.log(L"Object Extended GUID: " + toString(exguid));
			offset += exguid.bytes_use;
		} 
		else if (object_header.object_type == kOTRevision_manifest_object_group_references)
		{
			exguid.parse(bytes + offset);
			logfile.log(L"Object Group Extended GUID: " + toString(exguid));
			offset += exguid.bytes_use;
		}
		else
		{
			goto FAILED_END;
		}
	}

	//data element end
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;
	return;
FAILED_END:
	printf("parse failed, current offset:0x%X\n", offset);
}

void parseStorageManifestDataElement( const Byte* bytes, UINT64& offset,Log& logfile )
{
	ObjectHeader object_header;
	ExGUID exguid;
	Cell_ID cellid;
	GUID guid = {0};

	object_header.parse(bytes + offset);
	if (object_header.object_type != kOTStorage_manifest_schema_GUID)
		goto FAILED_END;
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;

	memcpy(&guid, bytes+offset, sizeof(guid));
	logfile.log(L"Schema GUID: " + toString(guid));
	offset += sizeof(guid);

	while(true)
	{
		object_header.parse(bytes + offset);
		if (object_header.object_type == kOTData_element)
			//data element end
			break;
		
		if (object_header.object_type != kOTStorage_manifest_root_declare)
			goto FAILED_END;	
		logfile.log(offset, toString(object_header));
		offset += object_header.bytes_use;

		exguid.parse(bytes + offset);
		logfile.log(L"Root Extended GUID: " + toString(exguid));
		offset += exguid.bytes_use;

		cellid.parse(bytes + offset);
		logfile.log(L"Cell ID: " + toString(cellid));
		offset += cellid.bytes_use;
	}

	//data element end
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;
	return;
FAILED_END:
	printf("parse failed, current offset:0x%X\n", offset);
}

void parseCellManifestDataElement( const Byte* bytes, UINT64& offset,Log& logfile )
{
	ObjectHeader object_header;
	ExGUID exguid;

	object_header.parse(bytes + offset);
	if (object_header.object_type != kOTCell_manifest_current_revision)
		goto FAILED_END;
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;

	exguid.parse(bytes + offset);
	logfile.log(L"Cell Manifest Current Revision Extended GUID: " + toString(exguid));
	offset += exguid.bytes_use;

	object_header.parse(bytes + offset);
	if (object_header.object_type != kOTData_element || object_header.header_type != kOHBit8End)
		goto FAILED_END;

	//data element end
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;
	return;
FAILED_END:
	printf("parse failed, current offset:0x%X\n", offset);
}

void parseStorageIndexDataElement( const Byte* bytes, UINT64& offset,Log& logfile )
{
	ObjectHeader object_header;
	ExGUID exguid;
	Cell_ID cellid;
	SerialNumber serial_num;
	
	while(true)
	{
		object_header.parse(bytes + offset);
		if (object_header.object_type == kOTData_element)
			break;
		logfile.log(offset, toString(object_header));
		offset += object_header.bytes_use;

		if (object_header.object_type == kOTStorage_index_manifest_mapping)
		{
			exguid.parse(bytes + offset);
			logfile.log(L"Manifest Mapping Extended GUID: " + toString(exguid));
			offset += exguid.bytes_use;

			serial_num.parse(bytes + offset);
			logfile.log(L"Manifest Mapping Serial Number: " + toString(serial_num));
			offset += serial_num.bytes_use;
		}
		else if (object_header.object_type == kOTStorage_index_cell_mapping)
		{
			cellid.parse(bytes + offset);
			logfile.log(L"Cell ID: " + toString(cellid));
			offset += cellid.bytes_use;

			exguid.parse(bytes + offset);
			logfile.log(L"Cell Mapping Extended GUID: " + toString(exguid));
			offset += exguid.bytes_use;

			serial_num.parse(bytes + offset);
			logfile.log(L"Cell Mapping Serial Number: " + toString(serial_num));
			offset += serial_num.bytes_use;
		}
		else if (object_header.object_type == kOTStorage_index_revision_mapping)
		{
			exguid.parse(bytes + offset);
			logfile.log(L"Revision Extended GUID: " + toString(exguid));
			offset += exguid.bytes_use;

			exguid.parse(bytes + offset);
			logfile.log(L"Revision Mapping Extended GUID: " + toString(exguid));
			offset += exguid.bytes_use;

			serial_num.parse(bytes + offset);
			logfile.log(L"Revision Mapping Serial Number: " + toString(serial_num));
			offset += serial_num.bytes_use;
		}
		else
		{
			goto FAILED_END;
		}
	}
	//data element end
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;
	return;
FAILED_END:
	printf("parse failed, current offset:0x%X\n", offset);
}

void parseSubResponse( const Byte* bytes, UINT64& offset,Log& logfile )
{
	ObjectHeader object_header;
	ExGUID exguid;
	CompactUint64 cuint64;
	bool failed_subresponse = false;
	
	while(true)
	{
		object_header.parse(bytes + offset);
		if (object_header.object_type != kOTSubresponse)
			break;
		logfile.log(offset, toString(object_header));
		offset += object_header.bytes_use;

		cuint64.parse(bytes + offset);
		logfile.log(L"Request ID: " + toString(cuint64));
		offset += cuint64.bytes_use;

		cuint64.parse(bytes + offset);
		logfile.log(L"Request Type: " + toString(cuint64) + L" " + RequestType2Str(cuint64.value));
		offset += cuint64.bytes_use;

		failed_subresponse = ((bytes + offset)[0] & 0x1) == 0x1;
		logfile.log(wstring(L"A - Status: ") + (failed_subresponse? L"Failed" : L"Success"));
		offset += 1;

		if (failed_subresponse)
		{
			parseResponseError(bytes, offset, logfile);
		}
		else
		{
			switch(cuint64.value)
			{
			case kRTQuery_changes:
				parseQueryChangesSubResponse(bytes, offset, logfile);
				break;
			case kRTQuery_access:
				goto FAILED_END;
				break;
			case kRTPut_changes:
				parsePutChangesSubResponse(bytes, offset, logfile);
				break;
			case kRTAllocate_ExtendedGuid_range:
				goto FAILED_END;
			default:
				assert(false);
			}
		}

		//sub response end
		object_header.parse(bytes + offset);
		if (object_header.object_type != kOTSubresponse)
			goto FAILED_END;
		logfile.log(offset, toString(object_header));
		offset += object_header.bytes_use;
	}

	return;

FAILED_END:
	printf("parse failed, current offset:0x%X\n", offset);
}

void parseQueryChangesSubResponse( const Byte* bytes, UINT64& offset,Log& logfile )
{
	ObjectHeader object_header;
	ExGUID exguid;

	object_header.parse(bytes + offset);
	if (object_header.object_type != kOTQuery_changes_response)
		goto FAILED_END;
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;

	exguid.parse(bytes + offset);
	logfile.log(L"Storage Index Extended GUID: " + toString(exguid));
	offset += exguid.bytes_use;
	
	bool partial_result = ((bytes+offset)[0] & 0x1) == 0x1;
	logfile.log(wstring(L"Partial result: ") + (partial_result? L"True" : L"False"));
	offset += 1;

	parseKnowledge(bytes, offset, logfile);

	return;

FAILED_END:
	printf("parse failed, current offset:0x%X\n", offset);
}

void parsePutChangesSubResponse(const Byte* bytes, UINT64& offset, Log& logfile)
{
	ObjectHeader object_header;
	ExGUID exguid;
	ExGUIDArray exguid_array;

	object_header.parse(bytes + offset);
	if (object_header.object_type != kOTPut_Changes_Response)
		goto FAILED_END;
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;

	exguid.parse(bytes + offset);
	logfile.log(L"Applied Storage Index Id: " + toString(exguid));
	offset += exguid.bytes_use;

	exguid_array.parse(bytes + offset);
	logfile.log(L"Data Elements Added: " + toString(exguid_array));
	offset += exguid_array.used();

	parseKnowledge(bytes, offset, logfile);

	object_header.parse(bytes + offset);
	if (object_header.object_type == kOTDiagnostic_Request_Option_Output)
	{
		logfile.log(offset, toString(object_header));
		offset += object_header.used();

		Byte temp = *(bytes + offset);
		logfile.log(L"Force Revision Chain Optimization: " + wstring((temp&0x1) == 0x1? L"True" : L"False"));
		offset += 1;
	}

	return;

FAILED_END:
	printf("parse failed, current offset:0x%X\n", offset);
}

void parseKnowledge( const Byte* bytes, UINT64& offset,Log& logfile )
{
	ObjectHeader object_header;
	ExGUID exguid;
	GUID guid;
	wstring guid_str;

	object_header.parse(bytes + offset);
	if (object_header.object_type != kOTKnowledge)
		return;
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;
	while(true)
	{
		object_header.parse(bytes + offset);
		
		if (object_header.object_type == kOTKnowledge)
			break;	//knowledge end

		if (object_header.object_type != kOTSpecialized_knowledge)
			goto FAILED_END;
		logfile.log(offset, toString(object_header));
		offset += object_header.bytes_use;

		memcpy(&guid, bytes+offset, sizeof(guid));
		guid_str = toString(guid);
		logfile.log(L"Knowledge type guid: " + guid_str + L" " + KnowledgeTypeGuid2Str(guid_str));
		offset += sizeof(guid);

		if (guid_str == kKTCell_knowledge)
		{
			parseCellKnowledge(bytes, offset, logfile);
		}
		else if (guid_str == kKTWaterline_knowledge)
		{
			parseWaterlineKnowledge(bytes, offset, logfile);
		}
		else if (guid_str == kKTFragment_knowledge)
		{
			goto FAILED_END;
		}
		else if (guid_str == kKTContent_tag_knowledge)
		{
			parseContentTagKnowledge(bytes, offset, logfile);
		}
		else
		{
			assert(false);
		}

		//Specialized Knowledge End
		object_header.parse(bytes + offset);
		if (object_header.object_type != kOTSpecialized_knowledge || object_header.header_type != kOHBit16End)
			goto FAILED_END;
		logfile.log(offset, toString(object_header));
		offset += object_header.bytes_use;
	}

	//Knowledge End
	if (object_header.object_type != kOTKnowledge || object_header.header_type != kOHBit8End)
		goto FAILED_END;
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;
	
	return;

FAILED_END:
	printf("parse failed, current offset:0x%X\n", offset);
}

void parseCellKnowledge( const Byte* bytes, UINT64& offset,Log& logfile )
{
	ObjectHeader object_header;
	ExGUID exguid;
	GUID guid;
	CompactUint64 cuint64;
	SerialNumber serial_num;
	
	object_header.parse(bytes + offset);
	if (object_header.object_type != kOTCell_Knowledge)
		goto FAILED_END;
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;

	while(true)
	{
		object_header.parse(bytes + offset);
		if (object_header.object_type == kOTCell_Knowledge)
			break;	//cell knowledge end
		logfile.log(offset, toString(object_header));
		offset += object_header.bytes_use;
		
		if (object_header.object_type == kOTCell_knowledge_range)
		{
			memcpy(&guid, bytes + offset, sizeof(guid));
			logfile.log(L"GUID of cell serial number range: " + toString(guid));
			offset += sizeof(guid);

			cuint64.parse(bytes + offset);
			logfile.log(L"Range From: " + toString(cuint64));
			offset += cuint64.bytes_use;

			cuint64.parse(bytes + offset);
			logfile.log(L"Range To: " + toString(cuint64));
			offset += cuint64.bytes_use;

		}
		else if (object_header.object_type == kOTCell_knowledge_entry)
		{
			serial_num.parse(bytes + offset);
			logfile.log(L"Cell Serial Number: " + toString(serial_num));
			offset += serial_num.bytes_use;
		}
		else
		{
			goto FAILED_END;
		}
	}

	//Cell Knowledge end
	if (object_header.object_type != kOTCell_Knowledge || object_header.header_type != kOHBit8End)
		goto FAILED_END;
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;
	
	return;

FAILED_END:
	printf("parse failed, current offset:0x%X\n", offset);
}

void parseWaterlineKnowledge( const Byte* bytes, UINT64& offset,Log& logfile )
{
	ObjectHeader object_header;
	ExGUID exguid;
	CompactUint64 cuint64;

	object_header.parse(bytes + offset);
	if (object_header.object_type != kOTWaterline_knowledge)
		goto FAILED_END;
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;

	while(true)
	{
		object_header.parse(bytes + offset);
		if (object_header.object_type == kOTWaterline_knowledge)
			break;	//Waterline knowledge end
		logfile.log(offset, toString(object_header));
		offset += object_header.bytes_use;

		if (object_header.object_type != kOTWaterline_knowledge_entry)
			goto FAILED_END;
		
		exguid.parse(bytes + offset);
		logfile.log(L"Cell Storage Extended GUID: " + toString(exguid));
		offset += exguid.bytes_use;

		cuint64.parse(bytes + offset);
		logfile.log(L"Waterline: " + toString(cuint64));
		offset += cuint64.bytes_use;

		cuint64.parse(bytes + offset);
		logfile.log(L"Reserved: " + toString(cuint64));
		offset += cuint64.bytes_use;
	}
	
	//Waterline Knowledge end
	if (object_header.object_type != kOTWaterline_knowledge || object_header.header_type != kOHBit8End)
		goto FAILED_END;
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;

	return;

FAILED_END:
	printf("parse failed, current offset:0x%X\n", offset);
}

void parseContentTagKnowledge( const Byte* bytes, UINT64& offset,Log& logfile )
{
	ObjectHeader object_header;
	ExGUID exguid;
	BinaryItem data;

	object_header.parse(bytes + offset);
	if (object_header.object_type != kOTContent_tag_knowledge)
		goto FAILED_END;
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;

	while(true)
	{
		object_header.parse(bytes + offset);
		if (object_header.object_type == kOTContent_tag_knowledge)
			break;	//Content Tag Knowledge End
		logfile.log(offset, toString(object_header));
		offset += object_header.bytes_use;

		if (object_header.object_type != kOTContent_tag_knowledge_entry)
			goto FAILED_END;

		exguid.parse(bytes + offset);
		logfile.log(L"BLOB Heap Extended GUID: " + toString(exguid));
		offset += exguid.bytes_use;

		data.parse(bytes + offset);
		logfile.log(L"Clock Data: " + toString(data));
		offset += data.bytes_use;
	}

	//Content Tag Knowledge end
	if (object_header.object_type != kOTContent_tag_knowledge || object_header.header_type != kOHBit8End)
		goto FAILED_END;
	logfile.log(offset, toString(object_header));
	offset += object_header.bytes_use;

	return;

FAILED_END:
	printf("parse failed, current offset:0x%X\n", offset);
}

void parseNodeObject( const Byte* bytes, UINT64 offset, Log& logfile )
{
	ObjectHeader object_header;
	ExGUID exguid;
	BinaryItem binary_item;

	object_header.parse(bytes + offset);
	//[FSSHTTPD] section 2.2.2.1 Root Node Object Data
	if (object_header.object_type == kOTRoot_Node)
	{
		logfile.log(offset, toString(object_header));
		offset += object_header.bytes_use;

		object_header.parse(bytes + offset);
		logfile.log(offset, toString(object_header));
		offset += object_header.bytes_use;

		binary_item.parse(bytes + offset);
		logfile.log(L"Signature Data: " + toString(binary_item));
		offset += binary_item.bytes_use;

		object_header.parse(bytes + offset);
		logfile.log(offset, toString(object_header));
		offset += object_header.bytes_use;

		UINT64 datasize = *((UINT64*)(bytes + offset));
		logfile.log(L"Data Size: " + toString(datasize));
		offset += object_header.length;

		object_header.parse(bytes + offset);
		if (object_header.object_type != kOTRoot_Node || object_header.header_type != kOHBit8End)
			goto FAILED_END;
		logfile.log(offset, toString(object_header));
		offset += object_header.bytes_use;
	}
	//[FSSHTTPD] section 2.2.3 Intermediate Node Object
	else if (object_header.object_type == kOTIntermediate_Node)
	{
		logfile.log(offset, toString(object_header));
		offset += object_header.bytes_use;

		object_header.parse(bytes + offset);
		logfile.log(offset, toString(object_header));
		offset += object_header.bytes_use;

		binary_item.parse(bytes + offset);
		logfile.log(L"Signature Data: " + toString(binary_item));
		offset += binary_item.bytes_use;

		object_header.parse(bytes + offset);
		logfile.log(offset, toString(object_header));
		offset += object_header.bytes_use;

		UINT64 datasize = *((UINT64*)(bytes + offset));
		logfile.log(L"Data Size: " + toString(datasize));
		offset += object_header.length;

		object_header.parse(bytes + offset);
		if (object_header.object_type != kOTIntermediate_Node || object_header.header_type != kOHBit8End)
			goto FAILED_END;
		logfile.log(offset, toString(object_header));
		offset += object_header.bytes_use;
	}
	//[FSSHTTPD] section 2.2.4 Data Node Object
	else
	{
		logfile.log(L"This is a Data Node Oject");
	}

	return;

FAILED_END:
	printf("parse failed, current offset:0x%X\n", offset);
}

void parseRequest( const Byte* bytes, Log& logfile )
{
	UINT64 offset = 0;
	ObjectHeader object_header;
	CompactUint64 cuint64;
	logfile.log(offset, L"Protocol version and Signature");
	offset += 12;
	object_header.parse(bytes + offset);
	if (object_header.object_type != kOTRequest)
		goto FAILED_END;
	logfile.log(offset, toString(object_header));
	offset += object_header.used();

	//user agent section
	object_header.parse(bytes + offset);
	logfile.log(offset, toString(object_header));
	offset += object_header.used();
	
	object_header.parse(bytes + offset);
	logfile.log(offset, toString(object_header));
	offset += object_header.used();
	logfile.log(L"UserAgentClient And Platform");
	offset += object_header.length;

	object_header.parse(bytes + offset);
	logfile.log(offset, toString(object_header));
	offset += object_header.used();
	logfile.log(L"User agent version");
	offset += object_header.length;

	object_header.parse(bytes + offset);
	logfile.log(offset, toString(object_header));
	offset += object_header.used();

	parseSubRequest(bytes, offset, logfile);

	parseDataElementPackage(bytes, offset, logfile);

	//request end
	object_header.parse(bytes + offset);
	if (object_header.object_type != kOTRequest || object_header.header_type != kOHBit16End)
		goto FAILED_END;
	logfile.log(offset, toString(object_header));
	offset += object_header.used();
	
	printf("parse successfully!!\n");
	return;

FAILED_END:
	printf("parse failed, current offset:0x%X\n", offset);
}

void parseSubRequest( const Byte* bytes, UINT64& offset,Log& logfile )
{
	UINT64 subrequest_type = 0;
	ObjectHeader object_header;
	CompactUint64 cuint64;
	while (true)
	{
		//sub requst start
		object_header.parse(bytes + offset);
		if (object_header.object_type != kOTSubrequest)
			break;
		logfile.log(offset, toString(object_header));
		offset += object_header.used();

		cuint64.parse(bytes + offset);
		logfile.log(L"Request Id: " + toString(cuint64));
		offset += cuint64.used();

		cuint64.parse(bytes + offset);
		logfile.log(L"Request Type: " + toString(cuint64) + L" " + RequestType2Str(cuint64.value));
		offset += cuint64.used();
		subrequest_type = cuint64.value;

		cuint64.parse(bytes + offset);
		logfile.log(L"Priority: " + toString(cuint64));
		offset += cuint64.used();

		//target partition id
		object_header.parse(bytes + offset);
		logfile.log(offset, toString(object_header));
		offset += object_header.used();
		GUID partition_id;
		memcpy(&partition_id, bytes+offset, 16);
		logfile.log(L"Partition Id GUID: " + toString(partition_id));
		offset += 16;

		switch(subrequest_type)
		{
		case kRTQuery_access:
			goto FAILED_END;
			break;
		case kRTQuery_changes:
			parseQueryChangesSubRequest(bytes, offset, logfile);
			break;
		case kRTPut_changes:
			parsePutChangesSubRequest(bytes, offset, logfile);
			break;
		case kRTAllocate_ExtendedGuid_range:
			goto FAILED_END;
			break;
		default:
			goto FAILED_END;
		}

		object_header.parse(bytes + offset);
		if (object_header.object_type != kOTSubrequest || object_header.header_type != kOHBit16End)
			goto FAILED_END;
		logfile.log(offset, toString(object_header));
		offset += object_header.used();
	}

	return;

FAILED_END:
	printf("parse failed, current offset:0x%X\n", offset);
}

void parseQueryChangesSubRequest( const Byte* bytes, UINT64& offset, Log& logfile )
{
	ObjectHeader object_header;
	CompactUint64 cuint64;
	object_header.parse(bytes + offset);
	if (object_header.object_type != kOTQuery_changes_request)
		goto FAILED_END;
	logfile.log(offset, toString(object_header));
	offset += object_header.used();
	
	Byte querychange_attr = *(bytes + offset);
	querychange_attr >>= 1;
	logfile.log(L"B - Allow Fragments: " + wstring((querychange_attr&0x1) == 0x1? L"YES" : L"NO"));
	querychange_attr >>= 1;
	logfile.log(L"C - Exclude Object Data: " + wstring((querychange_attr&0x1) == 0x1? L"YES" : L"NO"));
	querychange_attr >>= 1;
	logfile.log(L"D - Include Filtered Out Data Elements In Knowledge: " + wstring((querychange_attr&0x1) == 0x1? L"YES" : L"NO"));
	offset += 1;
	
	parseQueryChangeFilters(bytes, offset, logfile);

	parseKnowledge(bytes, offset, logfile);

	return;

FAILED_END:
	printf("parse failed, current offset:0x%X\n", offset);
}

void parseQueryChangeFilters( const Byte* bytes, UINT64& offset, Log& logfile )
{
	ObjectHeader object_header;
	CompactUint64 cuint64;
	while(true)
	{
		object_header.parse(bytes + offset);
		if (object_header.object_type != kOTQuery_changes_filter)
			return;
		logfile.log(offset, toString(object_header));
		offset += object_header.used();

		Byte filter_type = *(bytes + offset);
		logfile.log(L"Filter Type: " + FilterType2Str(filter_type));
		offset += 1;
		Byte filter_operation = *(bytes + offset);
		logfile.log(L"Filter Operation: " + toString(filter_operation));
		offset += 1;
		switch (filter_type)
		{
		case kFTAll_filter:
			break;	//all filter does not contain any data
		case kFTData_element_type_filter:
			{
				object_header.parse(bytes + offset);
				if (object_header.object_type != kOTQuery_changes_filter_data_element_type)
					goto FAILED_END;
				logfile.log(offset, toString(object_header));
				offset += object_header.used();
				cuint64.parse(bytes + offset);
				logfile.log(L"Data Element Type: " + QueryChangesFilterDataElementType2Str(cuint64.value));
				offset += cuint64.used();
			}
			break;
		case kFTHierarchy_filter:
			{
				object_header.parse(bytes + offset);
				if (object_header.object_type != kOTQuery_changes_filter_hierarchy)
					goto FAILED_END;
				logfile.log(offset, toString(object_header));
				offset += object_header.used();
				Byte depth = *(bytes + offset);
				logfile.log(L"Depth: " + toString(depth) + L"-" + DepthMeaning2Str(depth));
				offset += 1;
				//according to [FSSHTTPB] section 2.2.2.1.3.1.7 Hierarchy Filter, followed by Extended GUID Array, but it seems like a binary item
				BinaryItem binary_data;
				binary_data.parse(bytes + offset);
				logfile.log(L"Unknown Used: " + toString(binary_data));
				offset += binary_data.used();
			}
			break;
		case kFTCell_ID_filter:
		case kFTCustom_filter:
		case kFTData_element_IDs_filter:
		case kFTStorage_index_referenced_data_elements_filter:
			goto FAILED_END;
			break;
		default:
			goto FAILED_END;
		}

		object_header.parse(bytes + offset);
		if (object_header.object_type != kOTQuery_changes_filter || object_header.header_type != kOHBit16End)
			goto FAILED_END;
		logfile.log(offset, toString(object_header));
		offset += object_header.used();
	}

	return;

FAILED_END:
	printf("parse failed, current offset:0x%X\n", offset);
}

void parsePutChangesSubRequest( const Byte* bytes, UINT64& offset, Log& logfile )
{
	ObjectHeader object_header;
	CompactUint64 cuint64;
	ExGUID exguid;
	PutChangesRequestArguments arguments ={0};
	object_header.parse(bytes + offset);
	if (object_header.object_type != kOTPut_changes_request)
		goto FAILED_END;
	logfile.log(offset, toString(object_header));
	offset += object_header.used();

	exguid.parse(bytes + offset);
	logfile.log(L"Storage Index Extended GUID: " + toString(exguid));
	offset += exguid.used();
	exguid.parse(bytes + offset);
	logfile.log(L"Expected Storage Index Extended GUID: " + toString(exguid));
	offset += exguid.used();
	
	memcpy(&arguments, bytes+offset, 1);
	logfile.log(L"Imply Null Expected if No Mapping: " + wstring(arguments.ImplyNullExpectedIfNoMapping? L"True" : L"False"));
	logfile.log(L"Partial: " + wstring(arguments.Partial? L"True" : L"False"));
	logfile.log(L"Partial Last: " + wstring(arguments.PartialLast? L"True" : L"False"));
	logfile.log(L"Favor Coherency Failure Over Not Found: " + wstring(arguments.FavorCoherencyFailureOverNotFound? L"True" : L"False"));
	logfile.log(L"Abort Remaining Put Changes on Failure: " + wstring(arguments.AbortRemainingPutChangesOnFailure? L"True" : L"False"));
	logfile.log(L"Multi-Request Put Hint: " + wstring(arguments.MultiRequestPutHint? L"True" : L"False"));
	logfile.log(L"Return Complete Knowledge If Possible: " + wstring(arguments.ReturnCompleteKnowledgeIfPossible? L"True" : L"False"));
	logfile.log(L"Last Writer Wins On Next Change: " + wstring(arguments.LastWriterWinsOnNextChange? L"True" : L"False"));
	offset += 1;

	object_header.parse(bytes + offset);
	if (object_header.object_type == kOTAdditional_Flags)
	{
		logfile.log(offset, toString(object_header));
		offset += object_header.used();

		UINT16 temp = *((UINT16 *)(bytes + offset));
		logfile.log(L"Return Applied Storage Index Id Entries: " + wstring((temp&0x1) == 0x1? L"True" : L"False"));
		temp >>= 1;
		logfile.log(L"Return Data Elements Added: " + wstring((temp&0x1) == 0x1? L"True" : L"False"));
		temp >>= 1;
		logfile.log(L"Check for Id Reuse: " + wstring((temp&0x1) == 0x1? L"True" : L"False"));
		temp >>= 1;
		logfile.log(L"Coherency Check Only Applied Index Entries: " + wstring((temp&0x1) == 0x1? L"True" : L"False"));
		temp >>= 1;
		logfile.log(L"Full File Replace Put: " + wstring((temp&0x1) == 0x1? L"True" : L"False"));
		//reserved 11 bits
		offset += 2;
	}
	
	object_header.parse(bytes + offset);
	if (object_header.object_type == kOTPut_Changes_Lock_Id)
	{
		logfile.log(offset, toString(object_header));
		offset += object_header.used();

		GUID lock_id;
		memcpy(&lock_id, bytes + offset, 16);
		logfile.log(L"Lock Id Guid: " + toString(lock_id));
		offset += 16;
	}

	parseKnowledge(bytes, offset, logfile);

	object_header.parse(bytes + offset);
	if (object_header.object_type == kOTDiagnostic_Request_Option_Input)
	{
		logfile.log(offset, toString(object_header));
		offset += object_header.used();

		Byte temp = *(bytes + offset);
		logfile.log(L"Force Revision Chain Optimization: " + wstring((temp & 0x1) == 0x1? L"True" : L"False"));
		offset += 1;
	}

	return;

FAILED_END:
	printf("parse failed, current offset:0x%X\n", offset);
}

void parseResponseError( const Byte* bytes, UINT64& offset, Log& logfile )
{
	ObjectHeader object_header;
	CompactUint64 cuint64;
	ExGUID exguid;
	GUID error_type;
	
	while (true)
	{
		object_header.parse(bytes + offset);
		if (object_header.object_type != kOTError || object_header.header_type != kOHBit32Start)
			break;
		logfile.log(offset, toString(object_header));
		offset += object_header.used();

		memcpy(&error_type, bytes+offset, 16);
		logfile.log(L"Error Type GUID: " + toString(error_type) + L" " + ErrorTypeGUID2Str(error_type));
		offset += 16;

		if (error_type == kCellErrorTypeGUID)
		{
			object_header.parse(bytes + offset);
			logfile.log(offset, toString(object_header));
			offset += object_header.used();

			UINT32 error_code = *((UINT32*)(bytes + offset));
			logfile.log(L"Error Code: " + toString(error_code));
			offset += 4;
		}
		else if (error_type == kProtocolErrorTypeGUID)
		{
			goto FAILED_END;
		}
		else if (error_type == kWin32ErrorTypeGUID)
		{
			object_header.parse(bytes + offset);
			logfile.log(offset, toString(object_header));
			offset += object_header.used();

			UINT32 error_code = *((UINT32*)(bytes + offset));
			logfile.log(L"Error Code: " + toString(error_code));
			offset += 4;
		}
		else if (error_type == kHRESULTErrorTypeGUID)
		{
			goto FAILED_END;
		}
		else
		{
			goto FAILED_END;
		}
	}
	object_header.parse(bytes + offset);
	logfile.log(offset, toString(object_header));
	offset += object_header.used();
	
	object_header.parse(bytes + offset);
	logfile.log(offset, toString(object_header));
	offset += object_header.used();

	return;

FAILED_END:
	printf("parse failed, current offset:0x%X\n", offset);
}

