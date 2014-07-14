#include "StdAfx.h"
#include "Log.h"
#include "time.h"

LogFile::LogFile( const wstring& filename, File::OpenMode om /*= File::TRUNCATE*/ )
:file_(filename, om)
{

}

void LogFile::log(const wstring& msg)
{
	wstring new_msg = L"\t" + msg;
	writelog(new_msg);
}

void LogFile::log( UINT64 offset, const wstring& msg )
{
	WCHAR buf[20] = {0};
	swprintf_s(buf, L"%08X  ", offset);
	wstring new_msg = buf + msg;
	writelog(new_msg);
}


void LogFile::logWithTime( const wstring& msg )
{
	WCHAR buf[30] = {0};
	time_t time_val = time(NULL);
	tm local_time;
	localtime_s(&local_time, &time_val);
	swprintf_s(buf, L"%04d-%02d-%02d, %02d:%02d:%02d: ",
		local_time.tm_year + 1900, local_time.tm_mon + 1, local_time.tm_mday,
		local_time.tm_hour, local_time.tm_min, local_time.tm_sec);
	wstring new_msg = buf + msg;
	writelog(new_msg);
}

void LogFile::writelog( const wstring& msg )
{

	int count = ::WideCharToMultiByte(CP_ACP, 0, msg.c_str(), msg.size(), NULL, 0, 0, 0);
	if (count > 0)
	{
		char* message = new char[count];
		count = ::WideCharToMultiByte(CP_ACP, 0, msg.c_str(), msg.size(), message, count, 0, 0);
		file_.write(message, count);
		file_.write("\r\n", 2);

		delete[] message;
	}	
}
