
#include "../../pch.h"

#include "mingw.h"

using std::string;
using std::vector;

#ifdef WIN32
#define EXEPOSTFIX ".exe"
#define SEP "\\"
string FixSep ( const string& s )
{
	string s2(s);
	char* p = strchr ( &s2[0], '/' );
	while ( p )
	{
		*p++ = '\\';
		p = strchr ( p, '/' );
	}
	return s2;
}
#else
#define EXEPOSTFIX
#define SEP "/"
string FixSep ( const string& s )
{
	string s2(s);
	char* p = strchr ( &s2[0], '\\' );
	while ( p )
	{
		*p++ = '/';
		p = strchr ( p, '\\' );
	}
	return s2;
}
#endif

MingwBackend::MingwBackend ( Project& project )
	: Backend ( project )
{
}

void MingwBackend::Process ()
{
	CreateMakefile ();
	GenerateHeader ();
	GenerateAllTarget ();
	for ( size_t i = 0; i < ProjectNode.modules.size (); i++ )
	{
		Module& module = *ProjectNode.modules[i];
		ProcessModule ( module );
	}
	CloseMakefile ();
}

void MingwBackend::CreateMakefile ()
{
	fMakefile = fopen ( ProjectNode.makefile.c_str (), "w" );
	if ( !fMakefile )
		throw AccessDeniedException ( ProjectNode.makefile );
}

void MingwBackend::CloseMakefile ()
{
	if (fMakefile)
		fclose ( fMakefile );
}

void MingwBackend::GenerateHeader ()
{
	fprintf ( fMakefile, "# THIS FILE IS AUTOMATICALLY GENERATED, EDIT 'ReactOS.xml' INSTEAD\n\n" );
}

void MingwBackend::GenerateAllTarget ()
{
	fprintf ( fMakefile, "all: " );
	for ( size_t i = 0; i < ProjectNode.modules.size (); i++ )
	{
		Module& module = *ProjectNode.modules[i];
		fprintf ( fMakefile,
		          " %s" SEP "%s" EXEPOSTFIX,
		          FixSep(module.path).c_str (),
		          module.name.c_str () );
	}
	fprintf ( fMakefile, "\n\n" );
}

void MingwBackend::ProcessModule ( Module& module )
{
	MingwModuleHandlerList moduleHandlers;
	GetModuleHandlers ( moduleHandlers );
	for (size_t i = 0; i < moduleHandlers.size (); i++)
	{
		MingwModuleHandler& moduleHandler = *moduleHandlers[i];
		if (moduleHandler.CanHandleModule ( module ) )
		{
			moduleHandler.Process ( module );
			return;
		}
	}
}

void MingwBackend::GetModuleHandlers ( MingwModuleHandlerList& moduleHandlers )
{
	moduleHandlers.push_back ( new MingwKernelModuleHandler ( fMakefile ) );
}
