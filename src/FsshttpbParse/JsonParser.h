#pragma once

#include <map>
#include <vector>
#include <string>
using namespace std;

class JsObject {
public:
	enum Type {Unknown, String, Array, Map} type;

	string str_val;
	map<string, JsObject> map_val;
	vector<JsObject> array_val;

	JsObject():type(Unknown)
	{}

};

void ParseJason(istream& in, JsObject& obj);

// helper method for type casting
string& AsString(JsObject& jsObj);
map<string, JsObject>& AsMap(JsObject& jsObj);
vector<JsObject>& AsArray(JsObject& jsObj);
