//********************************************************************************
//
//     elfModel.hpp
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

#ifndef ELFMODEL_HPP
#define ELFMODEL_HPP

#include <string>
#include <boost/dynamic_bitset.hpp>
#include <elf.h>


class ElfFileModelInterface;

// ARM code & data separation, see mapping symbols from IHI0044F_aaelf
enum Elf_ARM_adt {
    ARMData,
    ARMCode,
    ARMThumb
};

// Ops for section content dump modes
enum Dump_mode {
    DumpAsm,
    DumpHex,
    DumpRaw
};

// Filter container entities
enum Elf_Item_Filter_Entities {
    byType,
    byBind,
    byInfo,
    byLink,
    byRelatedIndex,
    numFilters
};

// A struct to contain block of code or data, for any arch
struct Block {
    Block( int t, uint64_t a, uint64_t s) : type( t ), address( a ), size( s ) {}
    const int type;
    const uint64_t address;
    const uint64_t size;
};

class ElfItemFilter;
class ElfItemFilterProxy {
public:
    ElfItemFilterProxy( ElfItemFilter* f, boost::dynamic_bitset<>& bsRef  ) : _f( f ), _bsPtr( &bsRef ) {}
    ElfItemFilterProxy& set( size_t n, bool val = true ) { _bsPtr->set( n, val ); return( *this ); }
    ElfItemFilterProxy& set() { _bsPtr->set(); return( *this ); }
    ElfItemFilterProxy& reset( size_t n ) { _bsPtr->reset( n ); return( *this ); }
    ElfItemFilterProxy& reset() { _bsPtr->reset(); return( *this ); }
    bool test( size_t n ) const {
        if( n < _bsPtr->size() )
            return( _bsPtr->test( n ) );
        else if( 0 == _bsPtr->size() )
            // Note! this is the default 'include all' case where no spesific include filters are
            // applied, thus, mask bitset size is zero and here we return true to include any item
            return( true );
        else
            return( false );
    }
    ElfItemFilterProxy& resize( size_t num_bits, bool value = false ) { _bsPtr->resize( num_bits, value ); return( *this ); }
    size_t size() { return( _bsPtr->size() ); }
private:
    ElfItemFilter* _f;
    boost::dynamic_bitset<>* _bsPtr;
};

class ElfItemFilter {
public:
    ElfItemFilterProxy operator[]( Elf_Item_Filter_Entities ei ) { return ElfItemFilterProxy( this, *filter[ ei ] ); }
private:
    boost::dynamic_bitset<> b_type = boost::dynamic_bitset<>( 0 );
    boost::dynamic_bitset<> b_bind = boost::dynamic_bitset<>( 0 );
    boost::dynamic_bitset<> b_info = boost::dynamic_bitset<>( 0 );
    boost::dynamic_bitset<> b_link = boost::dynamic_bitset<>( 0 );
    boost::dynamic_bitset<> b_index = boost::dynamic_bitset<>( 0 );
    boost::dynamic_bitset<>* filter[ numFilters ] = {
        &b_type,
        &b_bind,
        &b_info,
        &b_link,
        &b_index
    };
};

// Model containing plain ponter to memory image of the object file,
// and file length. In instantiation, checks object file legitimity
class ElfFileModel {
public:
    ElfFileModel( const char* objFile, const long length ) throw();
    ~ElfFileModel();

    ElfFileModelInterface* impl() { return( _objFileModelImpl ); }

protected:
    struct elfMagicException : public std::exception {
        const char* what() const throw() { return "On checking Elf magic : not an ELF object!"; }
    };
    struct elfClassException : public std::exception {
        const char* what() const throw() { return "On checking supported class : no match!"; }
    };
    struct elfModelImplInstatiationException : public std::exception {
        const char* what() const throw() { return "On instatiating model impl : no match!"; }
    };

    const char* _objFile;
    const long  _length;
    ElfFileModelInterface*   _objFileModelImpl;

private:
    // No copying
    ElfFileModel( const ElfFileModel& );
    ElfFileModel& operator=( const ElfFileModel& );

};

// Pure virtual interface class
class ElfFileModelInterface {
public:
    virtual ~ElfFileModelInterface() {}
    virtual void CheckFile() = 0;
    virtual void DisassembleSection( const std::string&, const bool ) = 0;
    virtual void DisassembleFile( const bool ) = 0;
    virtual void DumpSection( const std::string&, const Dump_mode ) = 0;
    virtual void IterateRelocations( const std::string& s = std::string( "" ) ) = 0;
    virtual void IterateSections() = 0;
    virtual void IterateSymbols() = 0;
};

class ElfFileModelBase: public ElfFileModelInterface {
public:
    //ElfModelBase( const char* elfFile, const long length ) throw();
    virtual ~ElfFileModelBase() {}

protected:
    const std::string parseSectionFlags( Elf64_Xword );
    void parseSectionDescription( const std::string&, long& );
    size_t numberFieldWidth( const unsigned int& );
};

class ElfModelImpl32: public ElfFileModelBase {
public:
    ElfModelImpl32( const char* objFile, const long fileLength );
    void CheckFile();
    void DisassembleSection( const std::string&, const bool );
    void DisassembleFile( const bool );
    void DumpSection( const std::string&, const Dump_mode );
    void IterateRelocations( const std::string& s = std::string( "" ) );
    void IterateSections();
    void IterateSymbols();

private:
    bool Elf32HaveSectionTable();
    char* Elf32GetName( const Elf32_Word, const Elf32_Shdr* );
    Elf32_Shdr* Elf32GetSection( const Elf32_Half, ElfItemFilter* eif = NULL );
    Elf32_Sym* Elf32GetSymbol(const Elf32_Shdr*, const Elf32_Half, ElfItemFilter* eif = NULL );
    Elf32_Rel* Elf32GetRelEntry( const Elf32_Shdr*, const Elf32_Half, ElfItemFilter* eif = NULL );
    Elf32_Rela* Elf32GetRelaEntry( const Elf32_Shdr*, const Elf32_Half, ElfItemFilter* eif = NULL );
    void Elf32GetSectionByIndex( const Elf32_Half, Elf32_Shdr*& );
    Elf32_Half Elf32GetSectionByType( const Elf32_Half, const Elf32_Word, Elf32_Shdr*& );
    Elf32_Half Elf32GetSectionByName( const Elf32_Half, const char*, Elf32_Shdr*& );
    void Elf32GetSectionOffsetAndSize( const std::string&, long&, long& );
    void Elf32GetSectionOffsetAndSize( const Elf32_Half&, long&, long& );
    void Elf32GetTotalSize( long& );

private:
    const Elf32_Ehdr* _ehdr;
    const long _fileLength;

private:
    // No copying
    ElfModelImpl32( const ElfModelImpl32& );
    ElfModelImpl32& operator=( const ElfModelImpl32& );
};

class ElfModelImpl64: public ElfFileModelBase {
public:
    ElfModelImpl64( const Elf64_Ehdr* ehdr, const long fileLength )
        : _ehdr( ehdr ), _fileLength( fileLength ) {}
    void CheckFile();
    void DisassembleSection( const std::string&, const bool );
    void DisassembleFile( const bool );
    void DumpSection( const std::string&, const Dump_mode );
    void IterateRelocations( const std::string& s = std::string( "" ) );
    void IterateSections();
    void IterateSymbols();

private:
    bool Elf64HaveSectionTable();
    char* Elf64GetName( const Elf64_Word, const Elf64_Shdr* );
    Elf64_Sym* Elf64GetSymbol( const Elf64_Shdr*, const Elf64_Half );
    Elf64_Rel* Elf64GetRelEntry( const Elf64_Shdr*, const Elf64_Half, const Elf64_Section );
    void Elf64GetSectionByIndex( const Elf64_Half, Elf64_Shdr*& );
    Elf64_Half Elf64GetSectionByType( const Elf64_Half, const Elf64_Word, Elf64_Shdr*& );
    Elf64_Half Elf64GetSectionByName( const Elf64_Half, const char*, Elf64_Shdr*& );
    void Elf64GetSectionOffsetAndSize( const std::string&, long&, long& );
    void Elf64GetSectionOffsetAndSize( const Elf64_Half&, long&, long& );
    void Elf64GetTotalSize( long& );

private:
    const Elf64_Ehdr* _ehdr;
    const long _fileLength;

private:
    // No copying
    ElfModelImpl64( const ElfModelImpl64& );
    ElfModelImpl64& operator=( const ElfModelImpl64& );
};


#endif // ELFMODEL_HPP
