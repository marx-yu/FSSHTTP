// FsshttpbParse.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "CommonDefs.h"
#include "Utils.h"
#include "ProtocolParse.h"


int _tmain(int argc, _TCHAR* argv[])
{
	Byte* content = NULL;
	UINT content_size = 0;
	if (argc < 3)
	{
		printf("invalid cmd.use [ -parse/ filepath] cmd.\n");
		return -1;
	}
	if (!readContent(argv[2], &content_size, &content))
	{
		printf("read file failed\n");
		return -1;
	}

	if (!decodeContent(&content_size, &content))
	{
		printf("invalid content bytes\n");
		goto FAILED_END;
	}

	if (wstring(argv[1]) == L"-parse")
	{
		initStreamObjectTypeMap();

		LogFile logfile(wstring(argv[2]) + L"-parse.txt");
		parserSelector(content, content_size, logfile);
	}
	else if (wstring(argv[1]) == L"-split")
	{
		if (argc < 5)
		{
			printf("cmd argument invalid\n");
		}
		else
		{
			size_t offset = wcstoul(argv[3], NULL, 10);
			size_t count = wcstoul(argv[4], NULL, 10);
			if(writeFile(wstring(argv[2]) + L"-split.hex", content + offset, count))
				printf("split successfully\n");

		}
	}
	else
	{
		printf("cmd argument invalid\n");
	}
	
FAILED_END:
	delete[] content;
	
	return 0;
}

