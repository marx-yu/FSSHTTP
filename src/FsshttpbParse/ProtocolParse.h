// Copyright 2014 The Authors Marx-Yu. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once
#include "CommonDefs.h"
#include "Utils.h"
#include "Log.h"

//xml and base64 decode
bool decodeContent(UINT* content_size, Byte** cont_buf);

//root parser
void parserSelector(const Byte* bytes, size_t size, Log& logfile);
void parseResponse(const Byte* bytes, Log& logfile);
void parseRequest(const Byte* bytes, Log& logfile);

//sub-response sub parser
void parseSubResponse(const Byte* bytes, UINT64& offset, Log& logfile);
void parseQueryChangesSubResponse(const Byte* bytes, UINT64& offset, Log& logfile);
void parsePutChangesSubResponse(const Byte* bytes, UINT64& offset, Log& logfile);

void parseSubRequest(const Byte* bytes, UINT64& offset,Log& logfile);
void parseQueryChangesSubRequest(const Byte* bytes, UINT64& offset, Log& logfile);
void parsePutChangesSubRequest(const Byte* bytes, UINT64& offset, Log& logfile);


//data element sub parser
void parseDataElementPackage(const Byte* bytes, UINT64& offset, Log& logfile);
void parseObjectGroupDataElement(const Byte* bytes, UINT64& offset, Log& logfile);
void parseRevisionManifestDataElement(const Byte* bytes, UINT64& offset, Log& logfile);
void parseStorageManifestDataElement(const Byte* bytes, UINT64& offset, Log& logfile);
void parseCellManifestDataElement(const Byte* bytes, UINT64& offset, Log& logfile);
void parseStorageIndexDataElement(const Byte* bytes, UINT64& offset, Log& logfile);
void parseObjectDataBlobDataElement(const Byte* bytes, UINT64& offset, Log& logfile);

//knowledge sub parser
void parseKnowledge(const Byte* bytes, UINT64& offset, Log& logfile);
void parseCellKnowledge(const Byte* bytes, UINT64& offset, Log& logfile);
void parseWaterlineKnowledge(const Byte* bytes, UINT64& offset, Log& logfile);
void parseContentTagKnowledge(const Byte* bytes, UINT64& offset, Log& logfile);

//filters sub parser, filters is only used in query changes request
void parseQueryChangeFilters(const Byte* bytes, UINT64& offset, Log& logfile);

//error sub parser, only used in response
void parseResponseError(const Byte* bytes, UINT64& offset, Log& logfile);


//Node object data of [FSSHTTPD] parser, it is opaque for [FSSHTTPB]
//PS: offset is not reference 
void parseNodeObject(const Byte* bytes, UINT64 offset, Log& logfile);