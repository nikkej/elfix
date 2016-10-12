//********************************************************************************
//
//     elfModel.cpp
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

#include <sstream>
#include <iostream>
#include <iomanip>
#include <limits.h>
#include <string>
#include <cstring>

//#include <inttypes.h>
#include <capstone/capstone.h>

#include <map>
#include "asmDump.hpp"
#include "hexDump.hpp"
#include "elfModel.hpp"
#include "elfDefs.hpp"


ElfFileModel::ElfFileModel( const char* objFile, const long length ) throw()
    : _objFile( objFile ), _length( length ), _objFileModelImpl( NULL ) {
    Elf32_Ehdr* hdr = (Elf32_Ehdr*)_objFile;
    if( hdr->e_ident[ EI_MAG0 ] == ELFMAG0 \
     && hdr->e_ident[ EI_MAG1 ] == ELFMAG1 \
     && hdr->e_ident[ EI_MAG2 ] == ELFMAG2 \
     && hdr->e_ident[ EI_MAG3 ] == ELFMAG3 ) {
        if( hdr->e_ident[ EI_CLASS ] == ELFCLASS32 ) {
            _objFileModelImpl = new ElfModelImpl32( _objFile, _length );
        } else if( hdr->e_ident[ EI_CLASS ] == ELFCLASS64 ) {
            _objFileModelImpl = new ElfModelImpl64( (Elf64_Ehdr*)_objFile, _length );
        } else {
            throw elfClassException();
        }
    } else {
        throw elfMagicException();
    }
}

ElfFileModel::~ElfFileModel() {
    if( _objFileModelImpl ) {
        delete _objFileModelImpl;
        _objFileModelImpl = NULL;
    }
}

const std::string ElfFileModelBase::parseSectionFlags( Elf64_Xword flags ) {
    std::ostringstream strBuf;
    uint64_t mask = 1;

    while( mask < ( (uint64_t)1 << 31 ) ) {
        if( Elf::SHdr::sh_flags.find( mask ) != Elf::SHdr::sh_flags.end() ) {
            if( flags & mask )
                strBuf << Elf::SHdr::sh_flags.at( mask );
            else
                strBuf << ' ';
        }
        mask <<= 1;
    }
    return strBuf.str();
}

void ElfFileModelBase::parseSectionDescription( const std::string& sectionDescr, long& index ) {
    char* endPtr;

    // Assume numerical value first
    errno = 0;
    index = strtol( sectionDescr.c_str(), &endPtr, 10 );
    if( ( errno == ERANGE && ( index == LONG_MAX || index == LONG_MIN ) ) || ( errno != 0 && index == 0 ) ) {
        std::cerr << __func__ << ", ";
        perror( "strtol" );
        return;
    }
    // Section name as a string
    if( endPtr == sectionDescr.c_str() ) {
        index = -1;
    }
}

size_t ElfFileModelBase::numberFieldWidth( const unsigned int& number ) {
    char nrAsc[ 10 ] = { 0 };
    char* p = nrAsc;
    size_t nrWidth = 0;
    snprintf( nrAsc, 8, "%u", number );
    while( *p++ ) nrWidth++;
    return( nrWidth );
}

ElfModelImpl32::ElfModelImpl32( const char* objFile, const long fileLength )
    : _ehdr( (Elf32_Ehdr*)objFile ), _fileLength( fileLength ) {

}

bool ElfModelImpl32::Elf32HaveSectionTable() {
    if( _ehdr->e_shoff != 0 )
        return( true );
    else {
        std::cerr << "No section header table" << std::endl;
        return( false );
    }
}

char* ElfModelImpl32::Elf32GetName( const Elf32_Word sh_name, const Elf32_Shdr* strtable ) {
    if( sh_name < strtable->sh_size )
        return( (char*)( (char*)_ehdr + strtable->sh_offset + sh_name ) );
    else
        return( (char*)"" );
}

Elf32_Shdr* ElfModelImpl32::Elf32GetSection( const Elf32_Half index, ElfItemFilter* eif ) {
    if( index < _ehdr->e_shnum ) {
        Elf32_Shdr* section = (Elf32_Shdr*)( (char*)_ehdr + _ehdr->e_shoff + index * _ehdr->e_shentsize );
        if( eif ) {
            if( (*eif)[ byType ].test( section->sh_type )
             && (*eif)[ byLink ].test( section->sh_link ) ) {
                return( section );
            }
        }
        else {
            return( section );
        }
    }

    return( NULL );
}

Elf32_Sym* ElfModelImpl32::Elf32GetSymbol( const Elf32_Shdr* symtab, const Elf32_Half index, ElfItemFilter* eif ) {
    if( symtab != NULL && index < (symtab->sh_size / symtab->sh_entsize) ) {
        Elf32_Sym* symbol = (Elf32_Sym*)((char*)_ehdr + symtab->sh_offset + index * symtab->sh_entsize );
        if( eif ) {
            if( (*eif)[ byType ].test( ELF32_ST_TYPE( symbol->st_info ) )
             && (*eif)[ byRelatedIndex ].test( symbol->st_shndx ) ) {
                return( symbol );
            }
        }
        else {
            return( symbol );
        }
    }

    return( NULL );
}

Elf32_Rel* ElfModelImpl32::Elf32GetRelEntry( const Elf32_Shdr* reltab, const Elf32_Half index, ElfItemFilter* eif ) {
    if( reltab != NULL && index < (reltab->sh_size / reltab->sh_entsize) ) {
        Elf32_Rel* reloc = (Elf32_Rel*)((char*)_ehdr + reltab->sh_offset + index * reltab->sh_entsize );
        if( eif ) {
            if( (*eif)[ byType ].test( ELF32_R_TYPE( reloc->r_info ) )
             && (*eif)[ byRelatedIndex ].test( ELF32_R_SYM( reloc->r_info ) ) )
                return( reloc );
        }
        else {
            return( reloc );
        }
    }

    return( NULL );
}

Elf32_Rela* ElfModelImpl32::Elf32GetRelaEntry( const Elf32_Shdr* relatab, const Elf32_Half index, ElfItemFilter* eif ) {
    if( relatab != NULL && index < (relatab->sh_size / relatab->sh_entsize) ) {
        Elf32_Rela* reloc_a = (Elf32_Rela*)((char*)_ehdr + relatab->sh_offset + index * relatab->sh_entsize );
        if( eif ) {
            if( (*eif)[ byType ].test( ELF32_R_TYPE( reloc_a->r_info ) )
             && (*eif)[ byRelatedIndex ].test( ELF32_R_SYM( reloc_a->r_info ) ) )
                return( reloc_a );
        }
        else {
            return( reloc_a );
        }
    }

    return( NULL );
}

void ElfModelImpl32::Elf32GetSectionByIndex( const Elf32_Half index, Elf32_Shdr*& shdr ) {
    if( index < _ehdr->e_shnum )
        shdr = (Elf32_Shdr*)( (char*)_ehdr + _ehdr->e_shoff + index * _ehdr->e_shentsize );
    else
        shdr = NULL;
}

Elf32_Half ElfModelImpl32::Elf32GetSectionByType( const Elf32_Half startIndex, const Elf32_Word type, Elf32_Shdr*& shdr ) {
    shdr = NULL;

    if( startIndex < _ehdr->e_shnum ) {
        for( Elf32_Half index = startIndex; index < _ehdr->e_shnum; index++ ) {
            if( type ==  ( (Elf32_Shdr*)( (char*)_ehdr + _ehdr->e_shoff + index * _ehdr->e_shentsize ) )->sh_type ) {
                shdr = (Elf32_Shdr*)( (char*)_ehdr + _ehdr->e_shoff + index * _ehdr->e_shentsize );
                return( index );
            }
        }
    }

    return( 0 );
}

Elf32_Half ElfModelImpl32::Elf32GetSectionByName( const Elf32_Half startIndex, const char *section, Elf32_Shdr*& shdr ) {
    Elf32_Shdr* shstrtable;
    Elf32_Shdr* tmp_section;

    Elf32GetSectionByIndex ( _ehdr->e_shstrndx, shstrtable );
    shdr = NULL;

    if( startIndex < _ehdr->e_shnum ) {
        for( Elf32_Half index = 0; index < _ehdr->e_shnum; index++ ) {
            Elf32GetSectionByIndex( index, tmp_section );

            if ( !strcmp( Elf32GetName( tmp_section->sh_name, shstrtable ), section ) ) {
                shdr = (Elf32_Shdr*)( (char*)_ehdr + _ehdr->e_shoff + index * _ehdr->e_shentsize );
                return( index );
            }
        }
    }

    return( 0 );
}

void ElfModelImpl32::Elf32GetSectionOffsetAndSize( const std::string& sectionDescr, long& offset, long& size ) {
    long sectionIndex;

    parseSectionDescription( sectionDescr, sectionIndex );
    Elf32_Shdr* section;
    if( sectionIndex != -1 ) {
        Elf32GetSectionByIndex( (Elf32_Half)sectionIndex, section );
    } else {
        Elf32GetSectionByName( 1, sectionDescr.c_str(), section );
    }
    if( section ) {
        offset = section->sh_offset;
        size = section->sh_size;
    } else {
        offset = 0;
        size = 0;
        std::cerr << "Invalid section definition: " << sectionDescr << std::endl;
        return;
    }
}

void ElfModelImpl32::Elf32GetSectionOffsetAndSize( const Elf32_Half& sectionIndex, long& offset, long& size ) {
    Elf32_Shdr* section;
    Elf32GetSectionByIndex( sectionIndex, section );
    if( section ) {
        offset = section->sh_offset;
        size = section->sh_size;
    } else {
        offset = 0;
        size = 0;
        std::cerr << "Invalid section definition: " << sectionIndex << std::endl;
        return;
    }
}

void ElfModelImpl32::Elf32GetTotalSize( long& totalSize ) {
    totalSize = _ehdr->e_ehsize;
    totalSize += _ehdr->e_shnum * _ehdr->e_shentsize;

    for( Elf32_Half index = 0; index < _ehdr->e_shnum; index++ ) {
        if( SHT_NOBITS != ( (Elf32_Shdr*)( (char*)_ehdr + _ehdr->e_shoff + index * _ehdr->e_shentsize ) )->sh_type )
            totalSize += ( (Elf32_Shdr*)( (char*)_ehdr + _ehdr->e_shoff + index * _ehdr->e_shentsize ) )->sh_size;
    }
}

void ElfModelImpl32::CheckFile() {
    if( Elf32HaveSectionTable() ) {
        long sectionsSize = 0;

        Elf32GetTotalSize( sectionsSize );

        if( sectionsSize == _fileLength ) {
            std::cout << "Size of sections and file header matches file size" << std::endl;
        } else {
            std::cout << "There are " << _fileLength - sectionsSize << " bytes of bogus data in file" << std::endl;
        }
    }
}

void ElfModelImpl32::DisassembleSection( const std::string& sectionDescr, const bool showAddr = true ) {
    std::map<Elf32_Addr, Elf32_Sym*> elf32FuncSyms;
    std::map<Elf32_Addr, Elf32_Sym*> elf32NoTypeSyms;
    std::map<Elf32_Addr, Elf32_Rel*> elf32Relocs;
    Elf32_Shdr* strtab;

    if( Elf32HaveSectionTable() ) {
        long offset, size, sectionIndex;

        parseSectionDescription( sectionDescr, sectionIndex );
        Elf32GetSectionOffsetAndSize( sectionDescr, offset, size );

        if( sectionIndex == -1 ) {
            Elf32_Shdr* dummySection;
            sectionIndex = Elf32GetSectionByName( 1, sectionDescr.c_str(), dummySection );
        }

        // Get all func & notype symbols for this section
        Elf32_Sym* symbol;
        Elf32_Shdr* symtab;
        ElfItemFilter ef;
        Elf32GetSectionByName( 1, ".strtab", strtab );
        Elf32GetSectionByType( 1, SHT_SYMTAB, symtab );
        ef[ byType ].resize( STT_FUNC +1 ).set( STT_NOTYPE ).set( STT_FUNC );
        ef[ byRelatedIndex ].resize( symtab->sh_size / symtab->sh_entsize ).set( sectionIndex );
        for( Elf32_Word index = 0; index < symtab->sh_size / symtab->sh_entsize; index++ ) {
            if( ( symbol = Elf32GetSymbol( symtab, index, &ef ) ) != NULL ) {
                if( ELF32_ST_TYPE( symbol->st_info ) == STT_NOTYPE )
                    elf32NoTypeSyms.insert( std::make_pair( symbol->st_value, symbol ) );
                if( ELF32_ST_TYPE( symbol->st_info ) == STT_FUNC )
                    elf32FuncSyms.insert( std::make_pair( symbol->st_value, symbol ) );
            }
        }

        // Get all relocations for this section
        Elf32_Rel* reloc;
        Elf32_Shdr* reltab;
        for( Elf32_Half index = 1; index < _ehdr->e_shnum; index++ ) {
            Elf32GetSectionByType( index, SHT_REL, reltab );
            if( reltab && reltab->sh_info == sectionIndex ) {
                for( Elf32_Word index = 0; index < reltab->sh_size / reltab->sh_entsize; index++ ) {
                    if( ( reloc = Elf32GetRelEntry( reltab, index ) ) != NULL )
                        elf32Relocs.insert( std::make_pair( reloc->r_offset, reloc ) );
                }
            }
        }

        if( offset && size ) {
            csh handle;
            cs_arch arch;
            cs_mode mode;
            cs_insn *insn;
            size_t count;

            if( _ehdr->e_machine == EM_ARM ) {
                arch = CS_ARCH_ARM;
                mode = CS_MODE_ARM;
            } else {
                std::cerr << "With 32bit Elf relocatables, only ARM supported for now" << std::endl;
                return;
            }

            try {
                if ( cs_open( arch, mode, &handle ) != CS_ERR_OK ) {
                    std::cerr << "Cannot open capstone handle" << std::endl;
                    return;
                }
                if ( cs_option( handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK ) {
                    std::cerr << "Cannot set more detailed instruction decomposition, giving up" << std::endl;
                    return;
                }

                for( const auto& functionSym: elf32FuncSyms ) {
                    const uint64_t codeBlockAddress = (functionSym.second)->st_value;
                    uint64_t subBlockAddress = 0;
                    const size_t codeBlockSize = (size_t)(functionSym.second)->st_size;
                    size_t subBlockSize;
                    Elf_ARM_adt subBlockType;
                    typedef std::vector<struct Block> blockv;
                    blockv blocks;
                    std::map<Elf32_Addr, Elf32_Sym*>::iterator itBlockBegin, itBlockNext;

                    // Now assume mapping symbol '$d' is always after function begin if exist at all, so it
                    // should be safe to get upper bound iterator to figure out presence of '$d' in function
                    itBlockBegin = elf32NoTypeSyms.upper_bound( codeBlockAddress );
                    if( itBlockBegin != elf32NoTypeSyms.end() && itBlockBegin->first < ( codeBlockAddress + codeBlockSize ) ) {
                        // Okay, we have found '$d' inside a function, divide it to sub blocks
                        subBlockSize = itBlockBegin->first - codeBlockAddress;
                        // First block
                        blocks.push_back( Block( ARMCode, codeBlockAddress, subBlockSize ) );
                        do {
                            if( strncmp( "$d", Elf32GetName( (itBlockBegin->second)->st_name, strtab ), 2 ) == 0 ) {
                                subBlockType = ARMData;
                            }
                            if( strncmp( "$a", Elf32GetName( (itBlockBegin->second)->st_name, strtab ), 2 ) == 0 ) {
                                subBlockType = ARMCode;
                            }
                            subBlockAddress = itBlockBegin->first;
                            itBlockNext = itBlockBegin;
                            if( ++itBlockNext != elf32NoTypeSyms.end() && itBlockNext->first < ( codeBlockAddress + codeBlockSize ) )
                                subBlockSize = itBlockNext->first - itBlockBegin->first;
                            else
                                subBlockSize = ( codeBlockAddress + codeBlockSize ) - itBlockBegin->first;
                            blocks.push_back( Block( subBlockType, subBlockAddress, subBlockSize ) );

                        } while( ++itBlockBegin != elf32NoTypeSyms.end() && itBlockBegin->first < ( codeBlockAddress + codeBlockSize ) );
                    } else {
                        // Only one block, i.e. function itself
                        blocks.push_back( Block( ARMCode, codeBlockAddress, codeBlockSize ) );
                    }

                    blockv::const_iterator blockIt = blocks.begin();
                    for( ; blockIt != blocks.end(); ++blockIt ) {
                        if( blockIt->type == ARMCode ) {
                            count = cs_disasm( handle, (const uint8_t*)( (char*)_ehdr + offset + blockIt->address ), blockIt->size, blockIt->address, 0, &insn );

                            if ( count > 0 ) {
                                for( size_t j = 0; j < count; j++ ) {
                                    if( elf32FuncSyms.find( insn[j].address ) != elf32FuncSyms.end() )
                                        std::cout << Elf32GetName( elf32FuncSyms.at( insn[j].address )->st_name, strtab ) << ":" << std::endl;
                                    showAddr ? std::cout << std::setw( 8 ) << std::setfill( ' ' ) << std::hex << std::right << insn[j].address << ": " : std::cout << std::setw( 10 ) << std::setfill( ' ' ) << "";
                                    std::cout << std::setw( 16 ) << std::setfill( ' ' ) << std::left << insn[j].mnemonic;
                                    if( elf32Relocs.find( insn[j].address ) != elf32Relocs.end() ) {
                                        Elf32_Sym* symbol = Elf32GetSymbol( symtab, ELF32_R_SYM( elf32Relocs.at( insn[j].address )->r_info ) );
                                        std::string symName = Elf32GetName( symbol->st_name, strtab );
                                        if( symName.empty() )
                                            symName = "<no name>";
                                        std::cout << std::setw( 8 ) << std::setfill( ' ' ) << std::left << symName << std::endl;
                                    } else {
                                        std::cout << std::setw( 8 ) << std::setfill( ' ' ) << std::left << insn[j].op_str << std::endl;
                                    }
                                }
                                cs_err errorCode = cs_errno( handle );
                                if( errorCode != CS_ERR_OK )
                                    std::cerr << "Disasm engine reports: " << cs_strerror( errorCode ) << std::endl;

                                cs_free( insn, count );
                            } else {
                                printf( "ERROR: Failed to disassemble given code!\n" );
                            }

                        } else if( blockIt->type == ARMData ) {
                            uint64_t dataBlockAddr = blockIt->address;
                            uint64_t dataBlockSize = blockIt->size;

                            while( dataBlockSize ) {
                                if( dataBlockSize % 4 != 0 ) {
                                    std::cerr << "Weird aligment error?" << std::endl;
                                    break;
                                }
                                showAddr ? std::cout << std::setw( 8 ) << std::setfill( ' ' ) << std::hex << std::right << dataBlockAddr << ": " : std::cout << std::setw( 10 ) << std::setfill( ' ' ) << "";
                                std::cout << std::setw( 16 ) << std::setfill( ' ' ) << std::left << ".word";
                                if( elf32Relocs.find( dataBlockAddr ) != elf32Relocs.end() ) {
                                    Elf32_Sym* symbol = Elf32GetSymbol( symtab, ELF32_R_SYM( elf32Relocs.at( dataBlockAddr )->r_info ) );
                                    std::string symName = Elf32GetName( symbol->st_name, strtab );
                                    if( symName.empty() )
                                        symName = "<no name>";
                                    std::cout << std::setw( 8 ) << std::setfill( ' ' ) << std::left << symName;
                                    std::cout << ' ' << "@ 0x" << std::hex << *(uint32_t*)((char*)_ehdr + offset + dataBlockAddr);
                                    std::cout << ", " << Elf::ARM::Reloc::type.at( ELF32_R_TYPE( elf32Relocs.at( dataBlockAddr )->r_info ) ) << std::endl;
                                } else {
                                    std::cout << "0x" << std::setw( 8 ) << std::setfill( '0' ) << std::left << std::hex << *(uint32_t*)((char*)_ehdr + offset + dataBlockAddr) << std::endl;
                                }
                                dataBlockAddr += 4;
                                dataBlockSize -= 4;
                            }
                        }
                    }
                }
                cs_close( &handle );

            } catch( std::exception &e ) {
                std::cerr << e.what() << std::endl;
                return;
            }
        }
#if 0
        // Iterate and print keys and values of unordered_map
        std::cout << "Reloc map32: " << elf32Relocs.size() << " entries" << std::endl;
        std::cout << "Func Sym map32: " << elf32FuncSyms.size() << " entries" << std::endl;
        for( const auto& n : elf32FuncSyms ) {
            std::cout << "Key:[" << n.first << "], shndx: " << (n.second)->st_shndx << ", value: ";
            std::cout << std::hex << (n.second)->st_value << ", size: ";
            std::cout << std::hex << (n.second)->st_size <<  ", Name:[" << Elf32GetName( (n.second)->st_name, strtab ) << "]" << std::endl;
        }
#endif
    }
}

void ElfModelImpl32::DisassembleFile( const bool showAddr = true ) {
    //unordered_map<Elf32_Addr, Elf32_Sym*> elf32Syms;
    std::unique_ptr<std::map<Elf32_Addr, Elf32_Sym*>> elf32Syms( new std::map<Elf32_Addr, Elf32_Sym*>() );
    std::map<Elf32_Addr, Elf32_Rel*> elf32Relocs;
    std::map<Elf32_Section, Elf32_Shdr*> elf32Progbits;

    Elf32_Shdr* strtab;
    Elf32_Shdr* shstrtab;
    Elf32GetSectionByIndex ( _ehdr->e_shstrndx, shstrtab );

    if( Elf32HaveSectionTable() ) {
        long offset, size;
        Elf32_Half machine;

        // Get all program bit sections
        Elf32_Shdr* tmpSection;
        for( Elf32_Half index = 0; index < _ehdr->e_shnum; index++ ) {
            Elf32GetSectionByIndex( index, tmpSection );
            if( tmpSection && tmpSection->sh_type == SHT_PROGBITS ) {
                elf32Progbits.insert( std::make_pair( index, tmpSection ) );
            }
        }

        // Get all relocations
        Elf32_Rel* reloc;
        Elf32_Shdr* reltab;
        ElfItemFilter ef;
        Elf32GetSectionByType( 1, SHT_REL, reltab );
        if( reltab ) {
            for( Elf32_Word index = 0; index < reltab->sh_size / reltab->sh_entsize; index++ ) {
                if( ( reloc = Elf32GetRelEntry( reltab, index, &ef ) ) != NULL )
                    elf32Relocs.insert( std::make_pair( reloc->r_offset, reloc ) );
            }
        }
#if 1
        csh handle;
        cs_arch arch;
        cs_mode mode;
        cs_insn *insn;
        size_t count;

        machine = _ehdr->e_machine;
        if( machine == EM_ARM ) {
            arch = CS_ARCH_ARM;
            mode = CS_MODE_ARM;
        } else if( machine == EM_X86_64 ) {
            arch = CS_ARCH_X86;
            mode = CS_MODE_64;
        } else
            return;

        Elf32_Sym* symbol;
        Elf32_Shdr* symtab;
        Elf32GetSectionByName( 1, ".strtab", strtab );
        Elf32GetSectionByType( 1, SHT_SYMTAB, symtab );
        try {
            if ( cs_open( arch, mode, &handle ) != CS_ERR_OK )
                return;

            for( const auto& section: elf32Progbits ) {
                // Get all function symbols for this section
                elf32Syms->clear();
                ef[ byType ].resize( 3 ).set( STT_FUNC );
                ef[ byRelatedIndex ].resize( section.first + 1 ).set( section.first );
                for( Elf32_Word index = 0; index < symtab->sh_size / symtab->sh_entsize; index++ ) {
                    if( ( symbol = Elf32GetSymbol( symtab, index, &ef ) ) != NULL )
                        elf32Syms->insert( std::make_pair( symbol->st_value, symbol ) );
                }

                Elf32GetSectionOffsetAndSize( section.first, offset, size );
                if( offset && size ) {
                    std::cout << "Disassembly of section " << Elf32GetName( (section.second)->sh_name, shstrtab ) << std::endl;
                    count = cs_disasm( handle, (const uint8_t*)( (char*)_ehdr + offset ), (size_t)size, 0, 0, &insn );

                    if ( count > 0 ) {
                        for( size_t j = 0; j < count; j++ ) {
                            showAddr ? std::cout << "0x" << std::hex << insn[j].address << ":" : std::cout << "";
                            if( elf32Syms->find( insn[j].address ) != elf32Syms->end() )
                                std::cout << Elf32GetName( (*elf32Syms)[ insn[j].address ]->st_name, strtab ) << ":" << std::endl;
                            std::cout << "\t\t" << insn[j].mnemonic;
                            if( elf32Relocs.find( insn[j].address ) != elf32Relocs.end() ) {
                                Elf32_Sym*  symbol = Elf32GetSymbol( symtab, ELF32_R_SYM( elf32Relocs[ insn[j].address ]->r_info ) );
                                std::cout << "\t" << Elf32GetName( symbol->st_name, strtab ) << std::endl;
                            }
                            else
                                std::cout << "\t" << insn[j].op_str << std::endl;
                        }

                        cs_free( insn, count );
                    } else
                        printf( "ERROR: Failed to disassemble given code!\n" );
                }
            }
            cs_close( &handle );

        } catch( std::exception &e ) {
            std::cerr << e.what() << std::endl;
            return;
        }
#endif
        // Iterate and print keys and values of unordered_map
        std::cout << "Reloc map32: " << elf32Relocs.size() << " entries" << std::endl;
        std::cout << "Sym map32: " << elf32Syms->size() << " entries" << std::endl;
        Elf32_Shdr* section;
        size_t nrWidth = numberFieldWidth( _ehdr->e_shnum );
        size_t longestName = 0;
        for( Elf32_Half index = 0; index < _ehdr->e_shnum; index++ ) {
            Elf32GetSectionByIndex( index, section );
            size_t tmpLen = strlen( Elf32GetName( section->sh_name, shstrtab ) );
            if( longestName < tmpLen )
                longestName = tmpLen;
        }
        for( const auto& sec : elf32Progbits ) {
            //std::cout << "Key:[" << sec.first << "] Name:[" << Elf32GetName( (sec.second)->st_name, strtab ) << "]\n";
            try {
                Elf32GetSectionByIndex( sec.first, section );
                std::cout << " [" << std::setw( nrWidth ) << std::setfill( ' ' ) << std::dec << std::right << sec.first << ']';
                std::cout << ' ' << std::setw( longestName + 2 ) << std::setfill( ' ' ) << std::left << Elf32GetName( section->sh_name, shstrtab );
                std::cout << ' ' << std::setw( 15 ) << std::setfill( ' ' ) << std::left << Elf::SHdr::sh_type.at( section->sh_type );
                std::cout << " 0x" << std::setw( sizeof( section->sh_offset ) * 2 ) << std::setfill( '0' ) << std::hex << std::right << section->sh_offset;
                std::cout << " 0x" << std::setw( sizeof( section->sh_size ) * 2 ) << std::setfill( '0' ) << std::hex << std::right << section->sh_size;
                std::cout << ' ' << std::setw( 2 ) << std::setfill( ' ' ) << std::dec << std::right << section->sh_entsize;
                std::cout << ' ' << std::right << parseSectionFlags( section->sh_flags );
                std::cout << ' ' << std::setw( nrWidth ) << std::setfill( ' ' ) << std::dec << std::right << section->sh_link;
                std::cout << ' ' << std::setw( nrWidth ) << std::setfill( ' ' ) << std::dec << std::right << section->sh_info;
                std::cout << ' ' << std::setw( 2 ) << std::setfill( ' ' ) << std::dec << std::right << section->sh_addralign;
                std::cout << std::endl;
            } catch( std::exception& e ) {
                std::cerr << e.what() << ", error in matching section header numerical values to text" << std::endl;
                std::cerr << "Probable cause, definitions for section header num to text are outdated" << std::endl;
            }
        }
    }
}

void ElfModelImpl32::DumpSection( const std::string& sectionDescr, const Dump_mode mode ) {
    if( Elf32HaveSectionTable() ) {
        long offset, size;

        Elf32GetSectionOffsetAndSize( sectionDescr, offset, size );

        switch( mode ) {
            case DumpAsm: {
                asmDump ad( ( (char*)_ehdr + offset ), size );
                std::cout << ad;
                break;
            }
            case DumpHex: {
                hexDump hd( ( (char*)_ehdr + offset ), size );
                std::cout << hd;
                break;
            }
            case DumpRaw: {
                std::cout.write( ( (char*)_ehdr + offset ), size );
                std::cout.flush();
                break;
            }
        }
    }
}

void ElfModelImpl32::IterateRelocations( const std::string& s ) {
//    vector<Elf32_Rel*> elf32Relocs;
//    vector<Elf32_Rela*> elf32Relocs_a;

    boost::dynamic_bitset<> rel_bset( R_ARM_NUM );
    boost::dynamic_bitset<> rela_bset( R_ARM_NUM );
    Elf32_Rel* reloc;
    Elf32_Rela* reloc_a;
    Elf32_Shdr* strtab;
    Elf32_Shdr* shstrtab;
    Elf32GetSectionByIndex ( _ehdr->e_shstrndx, shstrtab );

    if( Elf32HaveSectionTable() ) {
        // Get all rel & rela entries
        Elf32_Shdr* reltab;
        for( Elf32_Half index = 0; index < _ehdr->e_shnum; index++ ) {
            Elf32GetSectionByIndex( index, reltab );
            if( reltab && reltab->sh_type == SHT_REL ) {
                for( Elf32_Word index = 0; index < reltab->sh_size / reltab->sh_entsize; index++ ) {
                    if( ( reloc = Elf32GetRelEntry( reltab, index ) ) != NULL ) {
//                        elf32Relocs.push_back( reloc );
                        rel_bset.set( ELF32_R_TYPE( reloc->r_info ) );
                    }
                }
            }
            if( reltab && reltab->sh_type == SHT_RELA ) {
                for( Elf32_Word index = 0; index < reltab->sh_size / reltab->sh_entsize; index++ ) {
                    if( ( reloc_a = Elf32GetRelaEntry( reltab, index ) ) != NULL ) {
//                        elf32Relocs_a.push_back( reloc_a );
                        rela_bset.set( ELF32_R_TYPE( reloc_a->r_info ) );
                    }
                }
            }
        }
    }
    if( rel_bset.count() ) {
        std::cout << "There are " << rel_bset.count() << " rel types:" << std::endl;
        for( size_t i = 0; i < rel_bset.size(); i++ ) {
            if( rel_bset.test( i ) )
                std::cout << "  " << Elf::ARM::Reloc::type.at( i ) << std::endl;
        }
    }
    if( rela_bset.count() ) {
        std::cout << "There are " << rela_bset.count() << " rela types" << std::endl;
    }
//    for( const auto& rel: elf32Relocs ) { }
}

void ElfModelImpl32::IterateSections() {
    Elf32_Shdr* section;
    Elf32_Shdr* shstrtab;

    Elf32GetSectionByIndex( _ehdr->e_shstrndx, shstrtab );

    std::cout << "There are " << _ehdr->e_shnum << " section headers, starting at offset 0x" << std::hex << _ehdr->e_shoff << ':' << std::endl;
    std::cout << "Section headers:" << std::endl;

    // Resolve longest section name string
    size_t longestName = 0;
    for( Elf32_Half index = 0; index < _ehdr->e_shnum; index++ ) {
        Elf32GetSectionByIndex( index, section );
        size_t tmpLen = strlen( Elf32GetName( section->sh_name, shstrtab ) );
        if( longestName < tmpLen )
            longestName = tmpLen;
    }

    // Resolve width for Nr field
    size_t nrWidth = numberFieldWidth( _ehdr->e_shnum );

    try {
        for( Elf32_Half index = 0; index < _ehdr->e_shnum; index++ ) {
            Elf32GetSectionByIndex( index, section );
            std::cout << " [" << std::setw( nrWidth ) << std::setfill( ' ' ) << std::dec << std::right << index << ']';
            std::cout << ' ' << std::setw( longestName + 2 ) << std::setfill( ' ' ) << std::left << Elf32GetName( section->sh_name, shstrtab );
            std::cout << ' ' << std::setw( 15 ) << std::setfill( ' ' ) << std::left << Elf::SHdr::sh_type.at( section->sh_type );
            std::cout << " 0x" << std::setw( sizeof( section->sh_offset ) * 2 ) << std::setfill( '0' ) << std::hex << std::right << section->sh_offset;
            std::cout << " 0x" << std::setw( sizeof( section->sh_size ) * 2 ) << std::setfill( '0' ) << std::hex << std::right << section->sh_size;
            std::cout << ' ' << std::setw( 2 ) << std::setfill( ' ' ) << std::dec << std::right << section->sh_entsize;
            std::cout << ' ' << std::right << parseSectionFlags( section->sh_flags );
            std::cout << ' ' << std::setw( nrWidth ) << std::setfill( ' ' ) << std::dec << std::right << section->sh_link;
            std::cout << ' ' << std::setw( nrWidth ) << std::setfill( ' ' ) << std::dec << std::right << section->sh_info;
            std::cout << ' ' << std::setw( 2 ) << std::setfill( ' ' ) << std::dec << std::right << section->sh_addralign;
            std::cout << std::endl;
        }
    } catch( std::exception& e ) {
        std::cerr << e.what() << ", error in matching section header numerical values to text" << std::endl;
        std::cerr << "Probable cause, definitions for section header num to text are outdated" << std::endl;
    }
}

// Iterate 32bit elf file symbol table
//
void ElfModelImpl32::IterateSymbols() {
    Elf32_Shdr* symtab;
    Elf32_Shdr* shstrtab;

    Elf32GetSectionByIndex( _ehdr->e_shstrndx, shstrtab );
    Elf32GetSectionByType( 1, SHT_SYMTAB, symtab );

    if( symtab != NULL ) {
        size_t nrWidth = numberFieldWidth( symtab->sh_size / symtab->sh_entsize );
        std::cout << "Symbol table " << Elf32GetName( symtab->sh_name, shstrtab ) << " contains " << symtab->sh_size / symtab->sh_entsize << " entries:" << std::endl;
        Elf32_Shdr* strtab;
        Elf32GetSectionByName( 1, ".strtab", strtab );
        if( strtab ) {
            std::cout << "  " << std::setw( nrWidth > strlen( "Num:") ? nrWidth : strlen( "Num:" ) ) << std::setfill( ' ' ) << std::right << "Num:";
            std::cout << ' ' << std::setw( sizeof( Elf32_Addr ) * 2 ) << std::setfill( ' ' ) << std::right << "Value";
            std::cout << ' ' << std::setw( 4 ) << std::setfill( ' ' ) << std::right << "Size";
            std::cout << ' ' << std::setw( 10 ) << std::setfill( ' ' ) << std::left << "Type";
            std::cout << ' ' << std::setw( 11 ) << std::setfill( ' ' ) << std::left << "Binding";
            std::cout << ' ' << std::setw( 10 ) << std::setfill( ' ' ) << std::left << "Visib";
            std::cout << ' ' << std::setw( 6 ) << std::setfill( ' ' ) << std::right << "Ndx";
            std::cout << ' ' << std::left << "Name";
            std::cout << std::endl;
            Elf32_Sym* symbol = (Elf32_Sym*)((char*)_ehdr + symtab->sh_offset );

            try {
                for( Elf32_Word index = 0; index < symtab->sh_size / symtab->sh_entsize; index++, symbol++ ) {
                    std::cout << ' ' << std::setw( nrWidth > strlen( "Num:") ? nrWidth : strlen( "Num:" ) ) << std::setfill( ' ' ) << std::dec << std::right << index << ':';
                    std::cout << ' ' << std::setw( sizeof( Elf32_Addr ) * 2 ) << std::setfill( '0' ) << std::hex << std::right << symbol->st_value;
                    std::cout << ' ' << std::setw( 4 ) << std::setfill( ' ' ) << std::hex << std::right << symbol->st_size;
                    std::cout << ' ' << std::setw( 10 ) << std::setfill( ' ' ) << std::left << Elf::Sym::sym_type.at( ELF32_ST_TYPE( symbol->st_info ) );
                    std::cout << ' ' << std::setw( 11 ) << std::setfill( ' ' ) << std::left << Elf::Sym::sym_bind.at( ELF32_ST_BIND( symbol->st_info ) );
                    std::cout << ' ' << std::setw( 10 ) << std::setfill( ' ' ) << std::left << Elf::Sym::sym_visib.at( ELF32_ST_VISIBILITY( symbol->st_other ) );
                    std::cout << ' ' << std::setw( 6 ) << std::setfill( ' ' );
                    ( symbol->st_shndx != 0 && symbol->st_shndx < SHN_LOPROC ) ? std::cout << std::dec << std::right << symbol->st_shndx : std::cout << std::right << Elf::Sym::sym_special_ndx.at( symbol->st_shndx );
                    std::cout << ' ' << Elf32GetName( symbol->st_name, strtab );
                    std::cout << std::endl;
                }
            } catch( std::exception& e ) {
                std::cerr << e.what() << ", error in matching symbol header numerical values to text" << std::endl;
                std::cerr << "Probable cause, definitions for symbol header num to text are outdated" << std::endl;
            }
        }
    }
}

// 64 bit elf helper functions
//
bool ElfModelImpl64::Elf64HaveSectionTable() {
    if( _ehdr->e_shoff != 0 )
        return( true );
    else {
        std::cerr << "No section header table" << std::endl;
        return( false );
    }
}

char* ElfModelImpl64::Elf64GetName( const Elf64_Word sh_name, const Elf64_Shdr* strtable ) {
    if( sh_name < strtable->sh_size )
        return( (char*)( (char*)_ehdr + strtable->sh_offset + sh_name ) );
    else
        return( NULL );
}

Elf64_Sym* ElfModelImpl64::Elf64GetSymbol(const Elf64_Shdr* symtab, const Elf64_Half index ) {
    if( symtab != NULL && index < (symtab->sh_size / symtab->sh_entsize) ) {
        Elf64_Sym* symbol = (Elf64_Sym*)((char*)_ehdr + symtab->sh_offset + index * symtab->sh_entsize );
        return( symbol );
    }

    return( NULL );
}

Elf64_Rel* ElfModelImpl64::Elf64GetRelEntry( const Elf64_Shdr* reltab, const Elf64_Half index, const Elf64_Section section ) {
    if( reltab != NULL && index < (reltab->sh_size / reltab->sh_entsize) ) {
        Elf64_Rel* reloc = (Elf64_Rel*)((char*)_ehdr + reltab->sh_offset + index * reltab->sh_entsize );
        return( reloc );
    }

    return( NULL );
}

void ElfModelImpl64::Elf64GetSectionByIndex( const Elf64_Half index, Elf64_Shdr*& shdr ) {
    if( index < _ehdr->e_shnum )
        shdr = (Elf64_Shdr*)( (char*)_ehdr + _ehdr->e_shoff + index * _ehdr->e_shentsize );
    else
        shdr = NULL;
}

Elf64_Half ElfModelImpl64::Elf64GetSectionByType( const Elf64_Half startIndex, const Elf64_Word type, Elf64_Shdr*& shdr ) {
    shdr = NULL;

    if( startIndex < _ehdr->e_shnum ) {
        for( Elf64_Half index = 0; index < _ehdr->e_shnum; index++ ) {
            if( type == ( (Elf64_Shdr*)( (char*)_ehdr + _ehdr->e_shoff + index * _ehdr->e_shentsize ) )->sh_type ) {
                shdr = (Elf64_Shdr*)( (char*)_ehdr + _ehdr->e_shoff + index * _ehdr->e_shentsize );
                return( index );
            }
        }
    }

    return( 0 );
}

Elf64_Half ElfModelImpl64::Elf64GetSectionByName( const Elf64_Half startIndex, const char *section, Elf64_Shdr*& shdr ) {
    Elf64_Shdr* shstrtable;
    Elf64_Shdr* tmp_section;

    Elf64GetSectionByIndex ( _ehdr->e_shstrndx, shstrtable );
    shdr = NULL;

    if( startIndex < _ehdr->e_shnum ) {
        for( Elf64_Half index = 0; index < _ehdr->e_shnum; index++ ) {
            Elf64GetSectionByIndex( index, tmp_section );

            if ( !strcmp( Elf64GetName( tmp_section->sh_name, shstrtable ), section ) ) {
                shdr = (Elf64_Shdr*)( (char*)_ehdr + _ehdr->e_shoff + index * _ehdr->e_shentsize );
                return( index );
            }
        }
    }

    return( 0 );
}

void ElfModelImpl64::Elf64GetSectionOffsetAndSize( const std::string& sectionDescr, long& offset, long& size ) {
    long sectionIndex;

    parseSectionDescription( sectionDescr, sectionIndex );
    Elf64_Shdr* section;
    if( sectionIndex != -1 ) {
        Elf64GetSectionByIndex( (Elf64_Half)sectionIndex, section );
    } else {
        Elf64GetSectionByName( 1, sectionDescr.c_str(), section );
    }
    if( section ) {
        offset = section->sh_offset;
        size = section->sh_size;
    } else {
        offset = 0;
        size = 0;
        std::cerr << "Invalid section definition: " << sectionDescr << std::endl;
        return;
    }
}

void ElfModelImpl64::Elf64GetSectionOffsetAndSize( const Elf64_Half& sectionIndex, long& offset, long& size ) {
    Elf64_Shdr* section;
    Elf64GetSectionByIndex( sectionIndex, section );
    if( section ) {
        offset = section->sh_offset;
        size = section->sh_size;
    } else {
        offset = 0;
        size = 0;
        std::cerr << "Invalid section definition: " << sectionIndex << std::endl;
        return;
    }
}

void ElfModelImpl64::Elf64GetTotalSize( long& totalSize ) {
    totalSize = _ehdr->e_ehsize;
    totalSize += _ehdr->e_shnum * _ehdr->e_shentsize;

    for( Elf64_Half index = 0; index < _ehdr->e_shnum; index++ ) {
        if( SHT_NOBITS != ( (Elf64_Shdr*)( (char*)_ehdr + _ehdr->e_shoff + index * _ehdr->e_shentsize ) )->sh_type )
            totalSize += ( (Elf64_Shdr*)( (char*)_ehdr + _ehdr->e_shoff + index * _ehdr->e_shentsize ) )->sh_size;
    }
}

void ElfModelImpl64::CheckFile() {
    if( Elf64HaveSectionTable() ) {
        long sectionsSize = 0;

        Elf64GetTotalSize( sectionsSize );

        if( sectionsSize == _fileLength ) {
            std::cout << "Size of sections and file header matches file size" << std::endl;
        } else {
            std::cout << "There are " << _fileLength - sectionsSize << " bytes of bogus data in file" << std::endl;
        }
    }
}

void ElfModelImpl64::DisassembleSection( const std::string& sectionDescr, const bool showAddr = true ) {
    std::unordered_map<Elf64_Addr, Elf64_Sym*> elf64Syms;
    Elf64_Shdr* strtab;

    if( Elf64HaveSectionTable() ) {
        long offset, size, sectionIndex;
        Elf64_Half machine;

        parseSectionDescription( sectionDescr, sectionIndex );
        Elf64GetSectionOffsetAndSize( sectionDescr, offset, size );

        machine = _ehdr->e_machine;
        Elf64_Sym* symbol;
        Elf64_Shdr* symtab;

        if( sectionIndex == -1 ) {
            Elf64_Shdr* dummySection;
            sectionIndex = Elf64GetSectionByName( 1, sectionDescr.c_str(), dummySection );
        }

        Elf64GetSectionByName( 1, ".strtab", strtab );
        Elf64GetSectionByType( 1, SHT_SYMTAB, symtab );
        for( Elf64_Word index = 0; index < symtab->sh_size / symtab->sh_entsize; index++ ) {
            if( ( symbol = Elf64GetSymbol( symtab, index ) ) != NULL )
                elf64Syms.insert( std::make_pair( symbol->st_value, symbol ) );
        }

        if( offset && size ) {
            csh handle;
            cs_arch arch;
            cs_mode mode;
            cs_insn *insn;
            size_t count;

            if( machine == EM_ARM ) {
                arch = CS_ARCH_ARM;
                mode = CS_MODE_ARM;
            } else if( machine == EM_X86_64 ) {
                arch = CS_ARCH_X86;
                mode = CS_MODE_64;
            } else
                // Unsupported machine
                return;

            try {
                if ( cs_open( arch, mode, &handle ) != CS_ERR_OK )
                    return;

                count = cs_disasm( handle, (const uint8_t*)( (char*)_ehdr + offset ), (size_t)size, 0, 0, &insn );

                if ( count > 0 ) {
                    for( size_t j = 0; j < count; j++ ) {
                        showAddr ? std::cout << "0x" << std::hex << insn[j].address << ":" : std::cout << "";
                        if( elf64Syms.find( insn[j].address ) != elf64Syms.end() )
                            std::cout << Elf64GetName( elf64Syms[ insn[j].address ]->st_name, strtab ) << ":" << std::endl;
                        std::cout << "\t\t" << insn[j].mnemonic;
                        std::cout << "\t" << insn[j].op_str << std::endl;
                    }

                    cs_free( insn, count );
                } else
                    printf( "ERROR: Failed to disassemble given code!\n" );

                cs_close( &handle );

            } catch( std::exception &e ) {
                std::cerr << e.what() << std::endl;
                return;
            }
        }
        // Iterate and print keys and values of unordered_map
//        std::cout << "Sym map64: " << elf64Syms.size() << " entries" << std::endl;
//        for( const auto& n : elf64Syms ) {
//            std::cout << "Key:[" << n.first << "] Value:[" << (n.second)->st_name << "]\n";
//        }
    }
}

void ElfModelImpl64::DisassembleFile( const bool showAddr = true ) {
#if 0
    unordered_map<Elf64_Addr, Elf64_Sym*> elf64Syms;
    Elf64_Shdr* strtab;

    if( Elf64HaveSectionTable() ) {
        long offset, size, sectionIndex;
        Elf64_Half machine;

        parseSectionDescription( sectionDescr, sectionIndex );
        Elf64GetSectionOffsetAndSize( sectionDescr, offset, size );

        machine = _ehdr->e_machine;
        Elf64_Sym* symbol;
        Elf64_Shdr* symtab;

        if( sectionIndex == -1 ) {
            Elf64_Shdr* dummySection;
            sectionIndex = Elf64GetSectionByName( 1, sectionDescr.c_str(), dummySection );
        }

        Elf64GetSectionByName( 1, ".strtab", strtab );
        Elf64GetSectionByType( 1, SHT_SYMTAB, symtab );
        for( Elf64_Word index = 0; index < symtab->sh_size / symtab->sh_entsize; index++ ) {
            if( ( symbol = Elf64GetSymbol( symtab, index ) ) != NULL )
                elf64Syms.insert( make_pair( symbol->st_value, symbol ) );
        }

        if( offset && size ) {
            csh handle;
            cs_arch arch;
            cs_mode mode;
            cs_insn *insn;
            size_t count;

            if( machine == EM_ARM ) {
                arch = CS_ARCH_ARM;
                mode = CS_MODE_ARM;
            } else if( machine == EM_X86_64 ) {
                arch = CS_ARCH_X86;
                mode = CS_MODE_64;
            } else
                // Unsupported machine
                return;

            try {
                if ( cs_open( arch, mode, &handle ) != CS_ERR_OK )
                    return;

                count = cs_disasm( handle, (const uint8_t*)( (char*)_ehdr + offset ), (size_t)size, 0, 0, &insn );

                if ( count > 0 ) {
                    for( size_t j = 0; j < count; j++ ) {
                        showAddr ? std::cout << "0x" << std::hex << insn[j].address << ":" : std::cout << "";
                        if( elf64Syms.find( insn[j].address ) != elf64Syms.end() )
                            std::cout << Elf64GetName( elf64Syms[ insn[j].address ]->st_name, strtab ) << ":" << std::endl;
                        std::cout << "\t\t" << insn[j].mnemonic;
                        std::cout << "\t" << insn[j].op_str << std::endl;
                    }

                    cs_free( insn, count );
                } else
                    printf( "ERROR: Failed to disassemble given code!\n" );

                cs_close( &handle );

            } catch( exception &e ) {
                std::cerr << e.what() << std::endl;
                return;
            }
        }
        // Iterate and print keys and values of unordered_map
        std::cout << "Sym map64: " << elf64Syms.size() << " entries" << std::endl;
//        for( const auto& n : elf64Syms ) {
//            std::cout << "Key:[" << n.first << "] Value:[" << (n.second)->st_name << "]\n";
//        }
    }
#endif
}

void ElfModelImpl64::DumpSection( const std::string& sectionDescr, const Dump_mode mode ) {
    if( Elf64HaveSectionTable() ) {
        long offset, size;

        Elf64GetSectionOffsetAndSize( sectionDescr, offset, size );

        switch( mode ) {
            case DumpAsm: {
                asmDump ad( ( (char*)_ehdr + offset ), size );
                std::cout << ad;
                break;
            }
            case DumpHex: {
                hexDump hd( ( (char*)_ehdr + offset ), size );
                std::cout << hd;
                break;
            }
            case DumpRaw: {
                std::cout.write( ( (char*)_ehdr + offset ), size );
                std::cout.flush();
                break;
            }
        }
    }
}

void ElfModelImpl64::IterateRelocations( const std::string& s ) {

}

// Iterate 64bit elf file sections
//
void ElfModelImpl64::IterateSections() {
    Elf64_Shdr* section;
    Elf64_Shdr* shstrtab;

    Elf64GetSectionByIndex( _ehdr->e_shstrndx, shstrtab );

    std::cout << "There are " << _ehdr->e_shnum << " section headers, starting at offset 0x" << std::hex << _ehdr->e_shoff << ':' << std::endl;

    // Resolve longest section name string
    size_t longestName = 0;
    for( Elf64_Half index = 0; index < _ehdr->e_shnum; index++ ) {
        Elf64GetSectionByIndex( index, section );
        size_t tmpLen = strlen( Elf64GetName( section->sh_name, shstrtab ) );
        if( longestName < tmpLen )
            longestName = tmpLen;
    }

    // Resolve width for Nr field
    size_t nrWidth = numberFieldWidth( _ehdr->e_shnum );

    try {
        for( Elf64_Half index = 0; index < _ehdr->e_shnum; index++ ) {
            Elf64GetSectionByIndex( index, section );
            std::cout << " [" << std::setw( nrWidth ) << std::setfill( ' ' ) << std::dec << std::right << index << ']';
            std::cout << ' ' << std::setw( longestName + 2 ) << std::setfill( ' ' ) << std::left << Elf64GetName( section->sh_name, shstrtab );
            std::cout << ' ' << std::setw( 15 ) << std::setfill( ' ' ) << std::left << Elf::SHdr::sh_type.at( section->sh_type );
            std::cout << " 0x" << std::setw( sizeof( section->sh_offset ) * 2 ) << std::setfill( '0' ) << std::hex << std::right << section->sh_offset;
            std::cout << " 0x" << std::setw( sizeof( section->sh_size ) * 2 ) << std::setfill( '0' ) << std::hex << std::right << section->sh_size;
            std::cout << ' ' << std::setw( 2 ) << std::setfill( ' ' ) << std::dec << std::right << section->sh_entsize;
            std::cout << ' ' << std::right << parseSectionFlags( section->sh_flags );
            std::cout << ' ' << std::setw( nrWidth ) << std::setfill( ' ' ) << std::dec << std::right << section->sh_link;
            std::cout << ' ' << std::setw( nrWidth ) << std::setfill( ' ' ) << std::dec << std::right << section->sh_info;
            std::cout << ' ' << std::setw( 2 ) << std::setfill( ' ' ) << std::dec << std::right << section->sh_addralign;
            std::cout << std::endl;
        }
    } catch( std::exception& e ) {
        std::cerr << e.what() << ", error in matching section header numerical values to text" << std::endl;
        std::cerr << "Probable cause, definitions for section header num to text are outdated" << std::endl;
    }
}

// Iterate 64bit elf file symbol table
//
void ElfModelImpl64::IterateSymbols() {
    // Iterate symbol table
    Elf64_Shdr* symtab;
    Elf64_Shdr* shstrtab;

    Elf64GetSectionByIndex( _ehdr->e_shstrndx, shstrtab );
    Elf64GetSectionByType( 1, SHT_SYMTAB, symtab );

    if( symtab != NULL ) {
        size_t nrWidth = numberFieldWidth( symtab->sh_size / symtab->sh_entsize );
        std::cout << "Symbol table " << Elf64GetName( symtab->sh_name, shstrtab ) << " contains " << symtab->sh_size / symtab->sh_entsize << " entries:" << std::endl;
        Elf64_Shdr* strtab;
        Elf64GetSectionByName( 1, ".strtab", strtab );
        if( strtab != NULL ) {
            std::cout << "  " << std::setw( nrWidth > strlen( "Num:") ? nrWidth : strlen( "Num:" ) ) << std::setfill( ' ' ) << std::right << "Num:";
            std::cout << ' ' << std::setw( sizeof( Elf64_Addr ) * 2 ) << std::setfill( ' ' ) << std::right << "Value";
            std::cout << ' ' << std::setw( 5 ) << std::setfill( ' ' ) << std::right << "Size";
            std::cout << ' ' << std::setw( 10 ) << std::setfill( ' ' ) << std::left << "Type";
            std::cout << ' ' << std::setw( 11 ) << std::setfill( ' ' ) << std::left << "Binding";
            std::cout << ' ' << std::setw( 10 ) << std::setfill( ' ' ) << std::left << "Visib";
            std::cout << ' ' << std::setw( 6 ) << std::setfill( ' ' ) << std::right << "Ndx";
            std::cout << ' ' << std::left << "Name";
            std::cout << std::endl;
            Elf64_Sym* symbol = (Elf64_Sym*)((char*)_ehdr + symtab->sh_offset );

            try {
                for( Elf64_Word index = 0; index < symtab->sh_size / symtab->sh_entsize; index++, symbol++ ) {
                    std::cout << ' ' << std::setw( nrWidth > strlen( "Num:") ? nrWidth : strlen( "Num:" ) ) << std::setfill( ' ' ) << std::dec << std::right << index << ':';
                    std::cout << ' ' << std::setw( sizeof( Elf64_Addr ) * 2 ) << std::setfill( '0' ) << std::hex << std::right << symbol->st_value;
                    std::cout << ' ' << std::setw( 5 ) << std::setfill( ' ' ) << std::hex << std::right << symbol->st_size;
                    std::cout << ' ' << std::setw( 10 ) << std::setfill( ' ' ) << std::left << Elf::Sym::sym_type.at( ELF64_ST_TYPE( symbol->st_info ) );
                    std::cout << ' ' << std::setw( 11 ) << std::setfill( ' ' ) << std::left << Elf::Sym::sym_bind.at( ELF64_ST_BIND( symbol->st_info ) );
                    std::cout << ' ' << std::setw( 10 ) << std::setfill( ' ' ) << std::left << Elf::Sym::sym_visib.at( ELF64_ST_VISIBILITY( symbol->st_other ) );
                    std::cout << ' ' << std::setw( 6 ) << std::setfill( ' ' );
                    ( symbol->st_shndx != 0 && symbol->st_shndx < SHN_LOPROC ) ? std::cout << std::dec << std::right << symbol->st_shndx : std::cout << std::right << Elf::Sym::sym_special_ndx.at( symbol->st_shndx );
                    std::cout << ' ' << Elf64GetName( symbol->st_name, strtab );
                    std::cout << std::endl;
                }
            } catch( std::exception& e ) {
                std::cerr << e.what() << ", error in matching symbol header numerical values to text" << std::endl;
                std::cerr << "Probable cause, definitions for symbol header num to text are outdated" << std::endl;
            }
        }
    }
}




