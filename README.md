FSSHTTP
=======

parser tools for protocol FSSHTTP/B/D

usage:

FsshttpbParse.exe -parse filename
filename -the full path of request or response content file
after parsing will create <filename>-parse.txt as the parse result

example:

in windows command line

C:\Users\YUYG>cd/d H:\WOPIHost-demos\wopihost-cwrapper\Debug

H:\WOPIHost-demos\wopihost-cwrapper\Debug>FsshttpbParse.exe -parse "C:\Users\YUYG\Desktop\owa edit\Example.docx\cell-req
uest-01.txt"
ret:1, byte readed:798
parse successfully!!

H:\WOPIHost-demos\wopihost-cwrapper\Debug>FsshttpbParse.exe -parse "C:\Users\YUYG\Desktop\owa edit\Example.docx\cell-bin
-request-02.bin"
ret:1, byte readed:85
parse successfully!!

H:\WOPIHost-demos\wopihost-cwrapper\Debug>FsshttpbParse.exe -parse "C:\Users\YUYG\Desktop\owa edit\Example.docx\cell-bin
-response-02.bin"
ret:1, byte readed:26840
parse successfully!!
