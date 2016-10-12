//********************************************************************************
//
//     hexDump.hpp
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

#ifndef HEXDUMP_HPP
#define HEXDUMP_HPP

#include <iostream>
#include <iomanip>

const char hexChar[] = "0123456789abcdef";

class hexDump {

public:
    hexDump( const char* buf = NULL, long length = 0, int rowSz = 16, int groupSz = 1, bool ascii = true )
        : _buf( buf ), _length( length ), _rowSz( rowSz ), _groupSz( groupSz ), _ascii( ascii ) { }

    std::ostream& print( std::ostream& stream ) {
        char asc[ _rowSz + 1 ];
        long i = 0;

        // If groupSz is not smaller than or equal to 8 and it isn't 2^n. Or row not modulo group?
        if( !( _groupSz <= 8 && __builtin_popcount( _groupSz ) == 1 ) || ( _rowSz % _groupSz != 0 ) ) {
            std::cerr << "Sanity check: group size forced to one octet, were not 2^n what asked. " << std::endl;
            _groupSz = 1;
        }

        stream << ' ' << std::hex << std::setw( 8 ) << std::setfill( '0' ) << i << "  ";
        if( _length == 0)
            stream << std::endl;

        while( _length-- ) {
            char ch = *_buf++;
            if( i % _groupSz == 0 && i > 0 ) {
                stream << ' ';
            }
            stream << hexChar[ ( ch & 0xf0 ) >> 4 ] << hexChar[ ch & 0xf ];
            isprint( ch ) ? asc[ i % _rowSz ] = ch : asc[ i % _rowSz ] = '.';
            asc[ i % _rowSz + 1 ] = 0;
            if( ++i % _rowSz == 0 ) {
                stream << "  " << ( _ascii ? asc : "" ) << std::endl;
                if( _length > 1 )
                    stream << ' ' << std::hex << std::setw( 8 ) << std::setfill( '0' ) << i << ' ';
            }
        }

        // Spit out the remainder of printable ascii, padded
        if( _ascii && i % _rowSz != 0 ) {
            while( i % _rowSz != 0 ) {
                if( i % _groupSz == 0 ) {
                    stream << ' ';
                }
                stream << "  "; i++;
            }
            stream << "  " << asc << std::endl;
        }
        return stream;
    }

private:
    friend std::ostream& operator<<( std::ostream& o, hexDump& hd );
    const char* _buf;
    long _length;
    int  _rowSz;
    int  _groupSz;
    bool _ascii;
};

std::ostream& operator<<( std::ostream& o, hexDump& hd ) {
    hd.print( o );
    return( o );
}

#endif // HEXDUMP_HPP
