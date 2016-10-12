//********************************************************************************
//
//     main.cpp
//
// Copyright (c) 2016, Juha T Nikkanen <nikkej@gmail.com>
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
// ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// The views and conclusions contained in the software and documentation are those
// of the authors and should not be interpreted as representing official policies,
// either expressed or implied, of the FreeBSD Project.
//
//********************************************************************************

#include "elfModel.hpp"
#include <iostream>
#include <iomanip>
#include <unordered_map>

#include <boost/iostreams/device/mapped_file.hpp> // for mmap
#include <boost/program_options.hpp>


void usage( const char* progName, const boost::program_options::options_description& options ) {
    std::cerr << "Usage: " << progName << " [options] file" << std::endl;
    std::cerr << options;
    exit( 0 );
}

int main( int argc, char ** argv ) {

    try {
        boost::program_options::options_description desc( "Allowed options" );
        desc.add_options()
            ( "help,h", "Display this help message" )
            ( "check,c", "Perform various tests to check file correctness" )
            ( "hex-dump,x", boost::program_options::value<std::string>(), \
              "Dump the uninterpreted contents of SECTION, by number or name" )
            ( "bin-dump,b", boost::program_options::value<std::string>(), \
              "Dump the raw bytes of SECTION, by number or name" )
            ( "asm-dump,q", boost::program_options::value<std::string>(), \
              "Dump the gas compatible comma separated .byte expressions of SECTION, arg as number or name" )
            ( "relocs,r", boost::program_options::value<std::string>()->implicit_value( "implicit" ), \
              "Display relocations, arg as filter for type \'t:NUM|NAME\', default is all" )
            ( "symbols,s", boost::program_options::value<std::string>()->implicit_value( "implicit" ), \
              "Display the symbol table, arg as filter for type, binding, visibility and index of related section \'t:NUM|NAME,b:NUM|NAME,v:NUM|NAME,l:NUM|NAME\', default is all" )
            ( "section-headers,S", "Display the section headers" )
            ( "disassemble,d", boost::program_options::value<std::string>(), \
              "Display assembler mnemonics for the machine instructions, arg as SECTION number or name" )
            ( "disassemble-file,D", \
              "Display assembler mnemonics for the machine instructions, over entire file" )
            ( "", "For end of options marker, if positional input file is omitted" )
            ( "input-file", boost::program_options::value<std::string>(), "input file\n" )
        ;

        boost::program_options::positional_options_description p;
        p.add( "input-file", -1 );

        boost::program_options::variables_map vm;
        boost::program_options::store( boost::program_options::command_line_parser( argc, argv ).options( desc ).positional( p ).run(), vm );
        boost::program_options::notify( vm );

        if( vm.count( "help" ) ) {
            usage( argv[ 0 ], desc );
        }

        if( vm.count( "input-file" ) ) {
            boost::iostreams::mapped_file mmap( vm[ "input-file" ].as<std::string>().c_str(), boost::iostreams::mapped_file::readonly );
            auto elfFile = mmap.const_data();
            auto length = mmap.size();
            std::unique_ptr<ElfFileModel> em( new ElfFileModel( elfFile, length ) );

            // Do the trick here !!
            if( vm.count( "check" ) )
                em->impl()->CheckFile();
            if( vm.count( "relocs" ) )
                em->impl()->IterateRelocations( vm[ "relocs" ].as<std::string>() );
            if( vm.count( "section-headers" ) )
                em->impl()->IterateSections();
            if( vm.count( "symbols" ) )
                //ElfIterateSymbols( elfFile, vm[ "symbols" ].as<std::string>() );
                em->impl()->IterateSymbols();
            if( vm.count( "hex-dump" ) )
                em->impl()->DumpSection( vm[ "hex-dump" ].as<std::string>(), DumpHex );
            if( vm.count( "bin-dump" ) )
                em->impl()->DumpSection( vm[ "bin-dump" ].as<std::string>(), DumpRaw );
            if( vm.count( "asm-dump" ) )
                em->impl()->DumpSection( vm[ "asm-dump" ].as<std::string>(), DumpAsm );
            if( vm.count( "disassemble" ) )
                //em->impl()->DisassembleSection( vm[ "disassemble" ].as<std::string>(), false );
                em->impl()->DisassembleSection( vm[ "disassemble" ].as<std::string>(), true );
            if( vm.count( "disassemble-file" ) )
                em->impl()->DisassembleFile( true );
        } else {
            usage( argv[ 0 ], desc );
        }

    }
    catch( std::exception& e ) {
        std::cerr << e.what() << std::endl;
        //return( -1 );
    }

    return( 0 );
}
