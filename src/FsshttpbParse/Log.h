#pragma once
#include "Utils.h"

class Log
{
public:
	virtual void log(UINT64 offset, const wstring& msg) = 0;
	virtual void log(const wstring& msg) = 0;
	virtual void logWithTime(const wstring& msg) = 0;
	virtual ~Log(){}
};

class LogFile: public Log
{
public:
	LogFile(const wstring& filename, File::OpenMode om = File::TRUNCATE);
	virtual void log(const wstring& msg);
	virtual void log(UINT64 offset, const wstring& msg);
	virtual void logWithTime(const wstring& msg);
	void writelog(const wstring& msg);
private:	
	File file_;
};

class LogBlank: public Log
{
public:
	virtual void log(const wstring& msg){}
	virtual void log(UINT64 offset, const wstring& msg){}
	virtual void logWithTime(const wstring& msg) {}
};