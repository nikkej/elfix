#********************************************************************************
#
#     elfModel.cpp
#
# Copyright (c) 2016, Juha T Nikkanen <nikkej@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation are those
# of the authors and should not be interpreted as representing official policies,
# either expressed or implied, of the FreeBSD Project.
#
#********************************************************************************

if( "${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}" )
    message( "  In-source build detected, please consider using" )
    message( "  separate build subdir and invoke cmake from there" )
endif()

project( elfix )
cmake_minimum_required( VERSION 2.8 )
aux_source_directory( . SRC_LIST )
set( CXX_ADDITIONAL_COMPILE_FLAGS "-g -Wall -Weffc++ -Wextra -std=c++14" )
set( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${CXX_ADDITIONAL_COMPILE_FLAGS}" )
set( Boost_USE_STATIC_LIBS OFF )
set( Boost_USE_MULTITHREADED ON )
set( Boost_USE_STATIC_RUNTIME OFF )
set( Boost_MIN_VERSION "1.44.0" )

if ( CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT )
    set ( CMAKE_INSTALL_PREFIX "/bin" CACHE PATH "default path for executables" FORCE )
endif()

find_package( Boost COMPONENTS iostreams program_options )
find_package( PkgConfig )
pkg_search_module( Capstone REQUIRED capstone )

if(NOT Boost_FOUND )
    message( FATAL_ERROR "Could not find required Boost components!" )
elseif(NOT Capstone_FOUND )
    message( FATAL_ERROR "Could not find required Capstone engine!" )
else()
    include_directories( ${Boost_INCLUDE_DIRS} )
    add_executable( ${PROJECT_NAME} ${SRC_LIST} )
    target_link_libraries( ${PROJECT_NAME} ${Boost_LIBRARIES} ${Capstone_LIBRARIES} )
    install( FILES ${CMAKE_BINARY_DIR}/${PROJECT_NAME} PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ DESTINATION ${CMAKE_INSTALL_PREFIX} )
endif()
