#include "stdafx.h"
#include "JsonParser.h"

namespace
{
	int get_non_white(istream& in)
	{
		for(;!in.eof();)
		{
			int c=in.get();
			if(!isspace(c))
				return c;
		}
		return -1;
	}

	bool contains(const char* str, char c)
	{
		for(; *str != 0; str++)
			if(*str==c)
				return true;
		return false;
	}

	string read_until(istream& in, const char* terminator)
	{
		string ret;
		for(;!in.eof();) {
			int c=in.peek();
			if(contains(terminator, c))
				break;
			else {
				ret+=c;
				in.get();
			}
		}
		return ret;
	}

	string un_escape(const string& in)
	{
		string out;
		for (size_t i=0; i < in.size(); i++)
		{
			char c = in[i];
			if (c == '\\' &&
				++i < in.size()) // shouldn't have reached the end yet
			{
				c = in[i];
				switch (c)
				{
				case '/':      out.push_back('/');     break;
				case '"':      out.push_back('"');     break;
				case '\\':     out.push_back('\\');    break;
				case 'b':      out.push_back('\b');    break;
				case 'f':      out.push_back('\f');    break;
				case 'n':      out.push_back('\n');    break;
				case 'r':      out.push_back('\r');    break;
				case 't':      out.push_back('\t');    break;
					//case 'u':      out.push_back('\u');    break; // TODO: what do we do with this?
				default: 
					{
						throw std::exception("Unrecognized escape sequence found in string: \\");
					}
				}
			}
			else
			{
				out.push_back(c);
			}
		}
		return out;
	};
}

void ParseJason(istream& in, JsObject& obj)
{
	char c=get_non_white(in);
	if(c=='\"')
	{
		string val=read_until(in, "\"");
		in.get(); // skip the last '"'

		obj.type = JsObject::String;
		obj.str_val = un_escape(val);
		return;
	}
	else if(c=='{')
	{
		// it's a object
		obj.type = JsObject::Map;
		for(;;) {
			// test ending
			char d;
			d=get_non_white(in);
			if(d=='}')
				// eof the object
				return;
			in.putback(d);

			// parse the key
			JsObject obj_key;
			ParseJason(in, obj_key);

			if(obj_key.type != JsObject::String)
				throw std::exception("the key must be a string");
			string key = obj_key.str_val;

			d=get_non_white(in);
			if(d != ':')
				throw std::exception("key must be followed with \":\"");

			JsObject obj_value;
			ParseJason(in, obj_value);

			obj.map_val[key] = obj_value;

			d=get_non_white(in);
			if(d==',')
				continue;
			else if(d=='}')
				break;
			else
				throw std::exception("invalid charector found, expect [,}]");
		}
	}
	else if(c=='[')
	{
		// it's an array
		obj.type = JsObject::Array;

		for(;;) {
			char d;
			d=get_non_white(in);
			if(d==']')
				return;

			in.putback(d);

			// parse the object
			JsObject obj_element;
			ParseJason(in, obj_element);
			obj.array_val.push_back(obj_element);

			d=get_non_white(in);
			if(d == ',')
				continue;
			else if(d==']')
				break;
			else
				throw std::exception("invalid charactor found, expect ',' or ']'");
		}
	}
	else
	{
		// whatever charactor, treat it as a string
		in.putback(c);
		string val = read_until(in, ",}");

		obj.type = JsObject::String;
		obj.str_val = val;
	}
}

string& AsString( JsObject& jsObj )
{
	if(jsObj.type != JsObject::String)
		throw exception("Cast Error!");
	return jsObj.str_val;
}

map<string, JsObject>& AsMap( JsObject& jsObj )
{
	if(jsObj.type != JsObject::Map)
		throw exception("Cast Error!");
	return jsObj.map_val;
}

vector<JsObject>& AsArray( JsObject& jsObj )
{
	if(jsObj.type != JsObject::Array)
		throw exception("Cast Error!");
	return jsObj.array_val;
}