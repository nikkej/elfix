//********************************************************************************
//
//     elfDefs.hpp
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

#ifndef ELFDEFS_HPP
#define ELFDEFS_HPP

#include <elf.h>
#include <unordered_map>

//#define SHF_COMPRESSED      (1u << 11)  // Flag for compressed section

namespace Elf {
    namespace EHdr {
        static std::unordered_map<uint8_t, const char*> eh_ident_class = {
            { ELFCLASSNONE, "CLASS NONE" },
            { ELFCLASS32, "CLASS 32" },
            { ELFCLASS64, "CLASS 64" }
        };
        static std::unordered_map<uint8_t, const char*> eh_ident_data = {
            { ELFDATANONE, "DATA NONE" },
            { ELFDATA2LSB, "DATA 2LSB" },
            { ELFDATA2MSB, "DATA 2MSB" }
        };
        static std::unordered_map<uint8_t, const char*> eh_ident_abi = {
            { ELFOSABI_SYSV, "OS ABI SYSV" },
            { ELFOSABI_HPUX, "OS ABI HPUX" },
            { ELFOSABI_NETBSD, "OS ABI NETBSD" },
            { ELFOSABI_LINUX, "OS ABI LINUX" },
            { ELFOSABI_SOLARIS, "OS ABI SOLARIS" },
            { ELFOSABI_AIX, "OS ABI AIX" },
            { ELFOSABI_IRIX, "OS ABI IRIX" },
            { ELFOSABI_FREEBSD, "OS ABI FREEBSD" },
            { ELFOSABI_TRU64, "OS ABI TRU64" },
            { ELFOSABI_MODESTO, "OS ABI MODESTO" },
            { ELFOSABI_OPENBSD, "OS ABI OPENBSD" },
            { ELFOSABI_ARM_AEABI, "OS ABI ARM AEABI" },
            { ELFOSABI_ARM, "OS ABI ARM" },
            { ELFOSABI_STANDALONE, "OS ABI STANDALONE" }
        };

        static std::unordered_map<int, const char*> eh_type = {
            { ET_NONE, "ET NONE" },
            { ET_REL, "ET REL" },
            { ET_EXEC, "ET EXEC" },
            { ET_DYN, "ET DYN" },
            { ET_CORE, "ET CORE" },
         //   { ET_NUM, "ET NUM" },
         //   { ET_LOOS, "ET LOOS" },
         //   { ET_HIOS, "ET HIOS" },
         //   { ET_LOPROC, "ET LOPROC" },
         //   { ET_HIPROC, "ET HIPROC" }
        };
        static std::unordered_map<int, const char*> eh_machine = {
            { EM_NONE, "NONE" },
            { EM_M32, "M32" },
            { EM_SPARC, "SPARC" },
            { EM_386, "386" },
            { EM_68K, "68K" },
            { EM_88K, "88K" },
            { EM_860, "860" },
            { EM_MIPS, "MIPS" },
            { EM_S370, "S370" },
            { EM_MIPS_RS3_LE, "MIPS_RS3_LE" },
            { EM_PARISC, "PARISC" },
            { EM_VPP500, "VPP500" },
            { EM_SPARC32PLUS, "SPARC32PLUS" },
            { EM_960, "960" },
            { EM_PPC, "PPC" },
            { EM_PPC64, "PPC64" },
            { EM_S390, "S390" },
            { EM_V800, "V800" },
            { EM_FR20, "FR20" },
            { EM_RH32, "RH32" },
            { EM_RCE, "RCE" },
            { EM_ARM, "ARM" },
            { EM_FAKE_ALPHA, "FAKE_ALPHA" },
            { EM_SH, "SH" },
            { EM_SPARCV9, "SPARCV9" },
            { EM_TRICORE, "TRICORE" },
            { EM_ARC, "ARC" },
            { EM_H8_300, "H8_300" },
            { EM_H8_300H, "H8_300H" },
            { EM_H8S, "H8S" },
            { EM_H8_500, "H8_500" },
            { EM_IA_64, "IA_64" },
            { EM_MIPS_X, "MIPS_X" },
            { EM_COLDFIRE, "COLDFIRE" },
            { EM_68HC12, "68HC12" },
            { EM_MMA, "MMA" },
            { EM_PCP, "PCP" },
            { EM_NCPU, "NCPU" },
            { EM_NDR1, "NDR1" },
            { EM_STARCORE, "STARCORE" },
            { EM_ME16, "ME16" },
            { EM_ST100, "ST100" },
            { EM_TINYJ, "TINYJ" },
            { EM_X86_64, "X86_64" },
            { EM_PDSP, "PDSP" },
            { EM_FX66, "FX66" },
            { EM_ST9PLUS, "ST9PLUS" },
            { EM_ST7, "ST7" },
            { EM_68HC16, "68HC16" },
            { EM_68HC11, "68HC11" },
            { EM_68HC08, "68HC08" },
            { EM_68HC05, "68HC05" },
            { EM_SVX, "SVX" },
            { EM_ST19, "ST19" },
            { EM_VAX, "VAX" },
            { EM_CRIS, "CRIS" },
            { EM_JAVELIN, "JAVELIN" },
            { EM_FIREPATH, "FIREPATH" },
            { EM_ZSP, "ZSP" },
            { EM_MMIX, "MMIX" },
            { EM_HUANY, "HUANY" },
            { EM_PRISM, "PRISM" },
            { EM_AVR, "AVR" },
            { EM_FR30, "FR30" },
            { EM_D10V, "D10V" },
            { EM_D30V, "D30V" },
            { EM_V850, "V850" },
            { EM_M32R, "M32R" },
            { EM_MN10300, "MN10300" },
            { EM_MN10200, "MN10200" },
            { EM_PJ, "PJ" },
            { EM_OPENRISC, "OPENRISC" },
            { EM_ARC_A5, "ARC_A5" },
            { EM_XTENSA, "XTENSA" },
            { EM_ALTERA_NIOS2, "ALTERA_NIOS2" },
            { EM_AARCH64, "AARCH64" },
            { EM_TILEPRO, "TILEPRO" },
            { EM_MICROBLAZE, "MICROBLAZE" },
            { EM_TILEGX, "TILEGX" }
        };
    }

    namespace SHdr {
        static std::unordered_map<Elf32_Word, const char*> sh_type = {
            { SHT_NULL, "NULL" },
            { SHT_PROGBITS, "PROGBITS" },
            { SHT_SYMTAB, "SYMTAB" },
            { SHT_STRTAB, "STRTAB" },
            { SHT_RELA, "RELA" },
            { SHT_HASH, "HASH" },
            { SHT_DYNAMIC, "DYNAMIC" },
            { SHT_NOTE, "NOTE" },
            { SHT_NOBITS, "NOBITS" },
            { SHT_REL, "REL" },
            { SHT_SHLIB, "SHLIB" },
            { SHT_DYNSYM, "DYNSYM" },
            { SHT_INIT_ARRAY, "INIT_ARRAY" },
            { SHT_FINI_ARRAY, "FINI_ARRAY" },
            { SHT_PREINIT_ARRAY, "PREINIT_ARRAY" },
            { SHT_GROUP, "GROUP" },
            { SHT_SYMTAB_SHNDX, "SYMTAB_SHNDX" },
            { SHT_NUM, "NUM" },
            { SHT_LOOS, "LOOS" },
            { SHT_GNU_ATTRIBUTES, "GNU_ATTRIBUTES" },
            { SHT_GNU_HASH, "GNU_HASH" },
            { SHT_GNU_LIBLIST, "GNU_LIBLIST" },
            { SHT_CHECKSUM, "CHECKSUM" },
            { SHT_LOSUNW, "LOSUNW" },
            { SHT_SUNW_COMDAT, "SUNW_COMDAT" },
            { SHT_SUNW_syminfo, "SUNW_syminfo" },
            { SHT_GNU_verdef, "GNU_verdef" },
            { SHT_GNU_verneed, "GNU_verneed" },
            { SHT_GNU_versym, "GNU_versym" },
            { SHT_LOPROC, "LOPROC" },
            { SHT_LOPROC + 1, "ARM_EXIDX" },
            { SHT_LOPROC + 2, "ARM_PREEMPTMAP" },
            { SHT_LOPROC + 3, "ARM_ATTRIBUTES" },
            { SHT_HIPROC, "HIPROC" },
            { SHT_LOUSER, "LOUSER" },
            { SHT_HIUSER, "HIUSER" }
        };

        static std::unordered_map<int, const char> sh_flags = {
            { SHF_WRITE, 'W' },
            { SHF_ALLOC, 'A' },
            { SHF_EXECINSTR, 'X' },
            { SHF_MERGE, 'M' },
            { SHF_STRINGS, 'S' },
            { SHF_INFO_LINK, 'I' },
            { SHF_LINK_ORDER, 'L' },
            { SHF_OS_NONCONFORMING, 'N' },
            { SHF_GROUP, 'G' },
            { SHF_TLS, 'T' },
            { SHF_COMPRESSED, 'C' },
            { SHF_ARM_ENTRYSECT, 'e' },
            { SHF_ARM_COMDEF, 'c' }
        };

        static std::unordered_map<int, const char*> sh_info;
    }

    namespace Sym {
        static std::unordered_map<int, const char*> sym_bind = {
            { STB_LOCAL, "LOCAL" },
            { STB_GLOBAL, "GLOBAL" },
            { STB_WEAK, "WEAK" },
            { STB_NUM, "NUM" },
         //   { STB_LOOS, "LOOS" },
            { STB_GNU_UNIQUE, "GNU_UNIQUE" },
            { STB_HIOS, "HIOS" },
            { STB_LOPROC, "LOPROC" },
            { STB_HIPROC, "HIPROC" }
        };

        static std::unordered_map<int, const char*> sym_type = {
            { STT_NOTYPE, "NOTYPE" },
            { STT_OBJECT, "OBJECT" },
            { STT_FUNC, "FUNC" },
            { STT_SECTION, "SECTION" },
            { STT_FILE, "FILE" },
            { STT_COMMON, "COMMON" },
            { STT_TLS, "TLS" },
            { STT_NUM, "NUM" },
         //   { STT_LOOS, "LOOS" },
            { STT_GNU_IFUNC, "GNU_IFUNC" },
            { STT_HIOS, "HIOS" },
            { STT_LOPROC, "LOPROC" },
            { STT_HIPROC, "HIPROC" }
        };

        static std::unordered_map<int, const char*> sym_visib = {
            { STV_DEFAULT, "DEFAULT" },
            { STV_INTERNAL, "INTERNAL" },
            { STV_HIDDEN, "HIDDEN" },
            { STV_PROTECTED, "PROTECTED" }
        };

        static std::unordered_map<int, const char*> sym_special_ndx = {
            { SHN_UNDEF, "UNDEF" },
         //   { SHN_LORESERVE, "LORESERVE" },
            { SHN_LOPROC, "LOPROC" },
         //   { SHN_BEFORE, "BEFORE" },
            { SHN_AFTER, "AFTER" },
            { SHN_HIPROC, "HIPROC" },
            { SHN_LOOS, "LOOS" },
            { SHN_HIOS, "HIOS" },
            { SHN_ABS, "ABS" },
            { SHN_COMMON, "COMMON" },
            { SHN_XINDEX, "XINDEX" },
         //   { SHN_HIRESERVE, "HIRESERVE" }
        };
    }

    namespace ARM {
        namespace Reloc {
            static std::unordered_map<int, const char*> type = {
                { R_ARM_NONE, "R_ARM_NONE" },
                { R_ARM_PC24, "R_ARM_PC24" },
                { R_ARM_ABS32, "R_ARM_ABS32" },
                { R_ARM_REL32, "R_ARM_REL32" },
                { R_ARM_PC13, "R_ARM_PC13" },
                { R_ARM_ABS16, "R_ARM_ABS16" },
                { R_ARM_ABS12, "R_ARM_ABS12" },
                { R_ARM_THM_ABS5, "R_ARM_THM_ABS5" },
                { R_ARM_ABS8, "R_ARM_ABS8" },
                { R_ARM_SBREL32, "R_ARM_SBREL32" },
                { R_ARM_THM_PC22, "R_ARM_THM_PC22" },
                { R_ARM_THM_PC8, "R_ARM_THM_PC8" },
                { R_ARM_AMP_VCALL9, "R_ARM_AMP_VCALL9" },
                { R_ARM_SWI24, "R_ARM_SWI24" },
                { R_ARM_TLS_DESC, "R_ARM_TLS_DESC" },
                { R_ARM_THM_SWI8, "R_ARM_THM_SWI8" },
                { R_ARM_XPC25, "R_ARM_XPC25" },
                { R_ARM_THM_XPC22, "R_ARM_THM_XPC22" },
                { R_ARM_TLS_DTPMOD32, "R_ARM_TLS_DTPMOD32" },
                { R_ARM_TLS_DTPOFF32, "R_ARM_TLS_DTPOFF32" },
                { R_ARM_TLS_TPOFF32, "R_ARM_TLS_TPOFF32" },
                { R_ARM_COPY, "R_ARM_COPY" },
                { R_ARM_GLOB_DAT, "R_ARM_GLOB_DAT" },
                { R_ARM_JUMP_SLOT, "R_ARM_JUMP_SLOT" },
                { R_ARM_RELATIVE, "R_ARM_RELATIVE" },
                { R_ARM_GOTOFF, "R_ARM_GOTOFF" },
                { R_ARM_GOTPC, "R_ARM_GOTPC" },
                { R_ARM_GOT32, "R_ARM_GOT32" },
                { R_ARM_PLT32, "R_ARM_PLT32" },
                { R_ARM_CALL, "R_ARM_CALL" },
                { R_ARM_JUMP24, "R_ARM_JUMP24" },
                { R_ARM_THM_JUMP24, "R_ARM_THM_JUMP24" },
                { R_ARM_BASE_ABS, "R_ARM_BASE_ABS" },
                { R_ARM_ALU_PCREL_7_0, "R_ARM_ALU_PCREL_7_0" },
                { R_ARM_ALU_PCREL_15_8, "R_ARM_ALU_PCREL_15_8" },
                { R_ARM_ALU_PCREL_23_15, "R_ARM_ALU_PCREL_23_15" },
                { R_ARM_LDR_SBREL_11_0, "R_ARM_LDR_SBREL_11_0" },
                { R_ARM_ALU_SBREL_19_12, "R_ARM_ALU_SBREL_19_12" },
                { R_ARM_ALU_SBREL_27_20, "R_ARM_ALU_SBREL_27_20" },
                { R_ARM_TARGET1, "R_ARM_TARGET1" },
                { R_ARM_SBREL31, "R_ARM_SBREL31" },
                { R_ARM_V4BX, "R_ARM_V4BX" },
                { R_ARM_TARGET2, "R_ARM_TARGET2" },
                { R_ARM_PREL31, "R_ARM_PREL31" },
                { R_ARM_MOVW_ABS_NC, "R_ARM_MOVW_ABS_NC" },
                { R_ARM_MOVT_ABS, "R_ARM_MOVT_ABS" },
                { R_ARM_MOVW_PREL_NC, "R_ARM_MOVW_PREL_NC" },
                { R_ARM_MOVT_PREL, "R_ARM_MOVT_PREL" },
                { R_ARM_THM_MOVW_ABS_NC, "R_ARM_THM_MOVW_ABS_NC" },
                { R_ARM_THM_MOVT_ABS, "R_ARM_THM_MOVT_ABS" },
                { R_ARM_THM_MOVW_PREL_NC, "R_ARM_THM_MOVW_PREL_NC" },
                { R_ARM_THM_MOVT_PREL, "R_ARM_THM_MOVT_PREL" },
                { R_ARM_THM_JUMP19, "R_ARM_THM_JUMP19" },
                { R_ARM_THM_JUMP6, "R_ARM_THM_JUMP6" },
                { R_ARM_THM_ALU_PREL_11_0, "R_ARM_THM_ALU_PREL_11_0" },
                { R_ARM_THM_PC12, "R_ARM_THM_PC12" },
                { R_ARM_ABS32_NOI, "R_ARM_ABS32_NOI" },
                { R_ARM_REL32_NOI, "R_ARM_REL32_NOI" },
                { R_ARM_ALU_PC_G0_NC, "R_ARM_ALU_PC_G0_NC" },
                { R_ARM_ALU_PC_G0, "R_ARM_ALU_PC_G0" },
                { R_ARM_ALU_PC_G1_NC, "R_ARM_ALU_PC_G1_NC" },
                { R_ARM_ALU_PC_G1, "R_ARM_ALU_PC_G1" },
                { R_ARM_ALU_PC_G2, "R_ARM_ALU_PC_G2" },
                { R_ARM_LDR_PC_G1, "R_ARM_LDR_PC_G1" },
                { R_ARM_LDR_PC_G2, "R_ARM_LDR_PC_G2" },
                { R_ARM_LDRS_PC_G0, "R_ARM_LDRS_PC_G0" },
                { R_ARM_LDRS_PC_G1, "R_ARM_LDRS_PC_G1" },
                { R_ARM_LDRS_PC_G2, "R_ARM_LDRS_PC_G2" },
                { R_ARM_LDC_PC_G0, "R_ARM_LDC_PC_G0" },
                { R_ARM_LDC_PC_G1, "R_ARM_LDC_PC_G1" },
                { R_ARM_LDC_PC_G2, "R_ARM_LDC_PC_G2" },
                { R_ARM_ALU_SB_G0_NC, "R_ARM_ALU_SB_G0_NC" },
                { R_ARM_ALU_SB_G0, "R_ARM_ALU_SB_G0" },
                { R_ARM_ALU_SB_G1_NC, "R_ARM_ALU_SB_G1_NC" },
                { R_ARM_ALU_SB_G1, "R_ARM_ALU_SB_G1" },
                { R_ARM_ALU_SB_G2, "R_ARM_ALU_SB_G2" },
                { R_ARM_LDR_SB_G0, "R_ARM_LDR_SB_G0" },
                { R_ARM_LDR_SB_G1, "R_ARM_LDR_SB_G1" },
                { R_ARM_LDR_SB_G2, "R_ARM_LDR_SB_G2" },
                { R_ARM_LDRS_SB_G0, "R_ARM_LDRS_SB_G0" },
                { R_ARM_LDRS_SB_G1, "R_ARM_LDRS_SB_G1" },
                { R_ARM_LDRS_SB_G2, "R_ARM_LDRS_SB_G2" },
                { R_ARM_LDC_SB_G0, "R_ARM_LDC_SB_G0" },
                { R_ARM_LDC_SB_G1, "R_ARM_LDC_SB_G1" },
                { R_ARM_LDC_SB_G2, "R_ARM_LDC_SB_G2" },
                { R_ARM_MOVW_BREL_NC, "R_ARM_MOVW_BREL_NC" },
                { R_ARM_MOVT_BREL, "R_ARM_MOVT_BREL" },
                { R_ARM_MOVW_BREL, "R_ARM_MOVW_BREL" },
                { R_ARM_THM_MOVW_BREL_NC, "R_ARM_THM_MOVW_BREL_NC" },
                { R_ARM_THM_MOVT_BREL, "R_ARM_THM_MOVT_BREL" },
                { R_ARM_THM_MOVW_BREL, "R_ARM_THM_MOVW_BREL" },
                { R_ARM_TLS_GOTDESC, "R_ARM_TLS_GOTDESC" },
                { R_ARM_TLS_CALL, "R_ARM_TLS_CALL" },
                { R_ARM_TLS_DESCSEQ, "R_ARM_TLS_DESCSEQ" },
                { R_ARM_THM_TLS_CALL, "R_ARM_THM_TLS_CALL" },
                { R_ARM_PLT32_ABS, "R_ARM_PLT32_ABS" },
                { R_ARM_GOT_ABS, "R_ARM_GOT_ABS" },
                { R_ARM_GOT_PREL, "R_ARM_GOT_PREL" },
                { R_ARM_GOT_BREL12, "R_ARM_GOT_BREL12" },
                { R_ARM_GOTOFF12, "R_ARM_GOTOFF12" },
                { R_ARM_GOTRELAX, "R_ARM_GOTRELAX" },
                { R_ARM_GNU_VTENTRY, "R_ARM_GNU_VTENTRY" },
                { R_ARM_GNU_VTINHERIT, "R_ARM_GNU_VTINHERIT" },
                { R_ARM_THM_PC11, "R_ARM_THM_PC11" },
                { R_ARM_THM_PC9, "R_ARM_THM_PC9" },
                { R_ARM_TLS_GD32, "R_ARM_TLS_GD32" },
                { R_ARM_TLS_LDM32, "R_ARM_TLS_LDM32" },
                { R_ARM_TLS_LDO32, "R_ARM_TLS_LDO32" },
                { R_ARM_TLS_IE32, "R_ARM_TLS_IE32" },
                { R_ARM_TLS_LE32, "R_ARM_TLS_LE32" },
                { R_ARM_TLS_LDO12, "R_ARM_TLS_LDO12" },
                { R_ARM_TLS_LE12, "R_ARM_TLS_LE12" },
                { R_ARM_TLS_IE12GP, "R_ARM_TLS_IE12GP" },
                { R_ARM_ME_TOO, "R_ARM_ME_TOO" },
                { R_ARM_THM_TLS_DESCSEQ, "R_ARM_THM_TLS_DESCSEQ" },
                { R_ARM_THM_TLS_DESCSEQ16, "R_ARM_THM_TLS_DESCSEQ16" },
                { R_ARM_THM_TLS_DESCSEQ32, "R_ARM_THM_TLS_DESCSEQ32" },
                { R_ARM_THM_GOT_BREL12, "R_ARM_THM_GOT_BREL12" },
                { R_ARM_IRELATIVE, "R_ARM_IRELATIVE" },
                { R_ARM_RXPC25, "R_ARM_RXPC25" },
                { R_ARM_RSBREL32, "R_ARM_RSBREL32" },
                { R_ARM_THM_RPC22, "R_ARM_THM_RPC22" },
                { R_ARM_RREL32, "R_ARM_RREL32" },
                { R_ARM_RABS22, "R_ARM_RABS22" },
                { R_ARM_RPC24, "R_ARM_RPC24" },
                { R_ARM_RBASE, "R_ARM_RBASE" }
            };

            // Tags extracted from document ARM IHI 0045E, doc.ver.E, ABI rev r2.10, 24th November 2015
            enum Tags {
                Tag_File = 1,
                Tag_Section = 2,
                Tag_Symbol = 3,
                Tag_CPU_raw_name = 4,
                Tag_CPU_name = 5,
                Tag_CPU_arch = 6,
                Tag_CPU_arch_profile = 7,
                Tag_ARM_ISA_use = 8,
                Tag_THUMB_ISA_use = 9,
                Tag_FP_arch = 10,
                Tag_WMMX_arch = 11,
                Tag_Advanced_SIMD_arch = 12,
                Tag_PCS_config = 13,
                Tag_ABI_PCS_R9_use = 14,
                Tag_ABI_PCS_RW_data = 15,
                Tag_ABI_PCS_RO_data = 16,
                Tag_ABI_PCS_GOT_use = 17,
                Tag_ABI_PCS_wchar_t = 18,
                Tag_ABI_FP_rounding = 19,
                Tag_ABI_FP_denormal = 20,
                Tag_ABI_FP_exceptions = 21,
                Tag_ABI_FP_user_exceptions = 22,
                Tag_ABI_FP_number_model = 23,
                Tag_ABI_align_needed = 24,
                Tag_ABI_align8_preserved = 25,
                Tag_ABI_enum_size = 26,
                Tag_ABI_HardFP_use = 27,
                Tag_ABI_VFP_args = 28,
                Tag_ABI_WMMX_args = 29,
                Tag_ABI_optimization_goals = 30,
                Tag_ABI_FP_optimization_goals = 31,
                Tag_compatibility = 32,
                Tag_CPU_unaligned_access = 34,
                Tag_FP_HP_extension = 36,
                Tag_ABI_FP_16bit_format = 38,
                Tag_MPextension_use = 42,
                Tag_DIV_use = 44,
                Tag_nodefaults = 64,
                Tag_also_compatible_with = 65,
                Tag_T2EE_use = 66,
                Tag_conformance = 67,
                Tag_Virtualization_use = 68,
                Tag_MPextension_use_obsoleted = 70
            };

            static std::unordered_map<int, const char*> tag_names = {
                { Tag_File, "Tag_File" },
                { Tag_Section, "Tag_Section" },
                { Tag_Symbol, "Tag_Symbol" },
                { Tag_CPU_raw_name, "Tag_CPU_raw_name" },
                { Tag_CPU_name, "Tag_CPU_name" },
                { Tag_CPU_arch, "Tag_CPU_arch" },
                { Tag_CPU_arch_profile, "Tag_CPU_arch_profile" },
                { Tag_ARM_ISA_use, "Tag_ARM_ISA_use" },
                { Tag_THUMB_ISA_use, "Tag_THUMB_ISA_use" },
                { Tag_FP_arch, "Tag_FP_arch" },
                { Tag_WMMX_arch, "Tag_WMMX_arch" },
                { Tag_Advanced_SIMD_arch, "Tag_Advanced_SIMD_arch" },
                { Tag_PCS_config, "Tag_PCS_config" },
                { Tag_ABI_PCS_R9_use, "Tag_ABI_PCS_R9_use" },
                { Tag_ABI_PCS_RW_data, "Tag_ABI_PCS_RW_data" },
                { Tag_ABI_PCS_RO_data, "Tag_ABI_PCS_RO_data" },
                { Tag_ABI_PCS_GOT_use, "Tag_ABI_PCS_GOT_use" },
                { Tag_ABI_PCS_wchar_t, "Tag_ABI_PCS_wchar_t" },
                { Tag_ABI_FP_rounding, "Tag_ABI_FP_rounding" },
                { Tag_ABI_FP_denormal, "Tag_ABI_FP_denormal" },
                { Tag_ABI_FP_exceptions, "Tag_ABI_FP_exceptions" },
                { Tag_ABI_FP_user_exceptions, "Tag_ABI_FP_user_exceptions" },
                { Tag_ABI_FP_number_model, "Tag_ABI_FP_number_model" },
                { Tag_ABI_align_needed, "Tag_ABI_align_needed" },
                { Tag_ABI_align8_preserved, "Tag_ABI_align8_preserved" },
                { Tag_ABI_enum_size, "Tag_ABI_enum_size" },
                { Tag_ABI_HardFP_use, "Tag_ABI_HardFP_use" },
                { Tag_ABI_VFP_args, "Tag_ABI_VFP_args" },
                { Tag_ABI_WMMX_args, "Tag_ABI_WMMX_args" },
                { Tag_ABI_optimization_goals, "Tag_ABI_optimization_goals" },
                { Tag_ABI_FP_optimization_goals, "Tag_ABI_FP_optimization_goals" },
                { Tag_compatibility, "Tag_compatibility" },
                { Tag_CPU_unaligned_access, "Tag_CPU_unaligned_access" },
                { Tag_FP_HP_extension, "Tag_FP_HP_extension" },
                { Tag_ABI_FP_16bit_format, "Tag_ABI_FP_16bit_format" },
                { Tag_MPextension_use, "Tag_MPextension_use" },
                { Tag_DIV_use, "Tag_DIV_use" },
                { Tag_nodefaults, "Tag_nodefaults" },
                { Tag_also_compatible_with, "Tag_also_compatible_with" },
                { Tag_T2EE_use, "Tag_T2EE_use" },
                { Tag_conformance, "Tag_conformance" },
                { Tag_Virtualization_use, "Tag_Virtualization_use" },
                { Tag_MPextension_use_obsoleted, "Tag_MPextension_use" }
            };
        }
    }

    namespace x86_64 {
        // todo
    }
}

#endif // ELFDEFS_HPP

