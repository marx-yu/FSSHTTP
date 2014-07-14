#pragma once

typedef UINT32 uint32_t;
typedef UINT64 uint64_t;

//字节序的小头和大头的问题
#define ZEN_LITTLE_ENDIAN  0x0123
#define ZEN_BIG_ENDIAN     0x3210

//目前所有的代码都是为了小头党服务的，不知道有生之年这套代码是否还会为大头党服务一次？
#ifndef ZEN_BYTES_ORDER
#define ZEN_BYTES_ORDER    ZEN_LITTLE_ENDIAN
#endif

#ifndef ZEN_SWAP_UINT16
#define ZEN_SWAP_UINT16(x)  ((((x) & 0xff00) >>  8) | (((x) & 0x00ff) <<  8))
#endif
#ifndef ZEN_SWAP_UINT32
#define ZEN_SWAP_UINT32(x)  ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) | \
	(((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))
#endif
#ifndef ZEN_SWAP_UINT64
#define ZEN_SWAP_UINT64(x)  ((((x) & 0xff00000000000000) >> 56) | (((x) & 0x00ff000000000000) >>  40) | \
	(((x) & 0x0000ff0000000000) >> 24) | (((x) & 0x000000ff00000000) >>  8) | \
	(((x) & 0x00000000ff000000) << 8 ) | (((x) & 0x0000000000ff0000) <<  24) | \
	(((x) & 0x000000000000ff00) << 40 ) | (((x) & 0x00000000000000ff) <<  56))
#endif



///MD5的结果数据长度
static const size_t ZEN_MD5_HASH_SIZE   = 16;
///SHA1的结果数据长度
static const size_t ZEN_SHA1_HASH_SIZE  = 20;

namespace ZEN_LIB
{


	/*!
	@brief      求某个内存块的MD5，
	@return     unsigned char* 返回的的结果，
	@param[in]  buf    求MD5的内存BUFFER指针
	@param[in]  size   BUFFER长度
	@param[out] result 结果
	*/
	unsigned char *md5(const unsigned char *buf,
		size_t size,
		unsigned char result[ZEN_MD5_HASH_SIZE]);


	/*!
	@brief      求内存块BUFFER的SHA1值
	@return     unsigned char* 返回的的结果
	@param[in]  buf    求SHA1的内存BUFFER指针
	@param[in]  size   BUFFER长度
	@param[out] result 结果
	*/
	unsigned char *sha1(const unsigned char *buf,
		size_t size,
		unsigned char result[ZEN_SHA1_HASH_SIZE]);
};

int base64_decode( const char * base64, unsigned char * bindata );