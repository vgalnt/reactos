#ifndef __RBUILD_H
#define __RBUILD_H

#include "pch.h"

#include "ssprintf.h"
#include "exception.h"
#include "XML.h"

class Project;
class Module;
class File;
class Library;

class Project
{
public:
	std::string name;
	std::string makefile;
	std::vector<Module*> modules;

	Project ();
	Project ( const std::string& filename );
	~Project ();
	void ProcessXML ( const XMLElement& e,
	                  const std::string& path );
private:
	void ReadXml ();
	XMLFile xmlfile;
	XMLElement* head;
};


enum ModuleType
{
	BuildTool,
	KernelModeDLL
};

class Module
{
public:
	const XMLElement& node;
	std::string name;
	std::string path;
	ModuleType type;
	std::vector<File*> files;
	std::vector<Library*> libraries;

	Module ( const XMLElement& moduleNode,
	         const std::string& moduleName,
	         const std::string& modulePath );
	ModuleType GetModuleType (const XMLAttribute& attribute );

	~Module();

	void ProcessXML ( const XMLElement& e, const std::string& path );
};


class File
{
public:
	std::string name;

	File ( const std::string& _name );
};


class Library
{
public:
	std::string name;

	Library ( const std::string& _name );
};

#endif /* __RBUILD_H */
