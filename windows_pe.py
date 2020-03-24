from construct import Struct, Const, Int16ul, Int32ul, Array

"""
FROM WINNT.H:

    typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
        WORD   e_magic;                     // Magic number
        WORD   e_cblp;                      // Bytes on last page of file
        WORD   e_cp;                        // Pages in file
        WORD   e_crlc;                      // Relocations
        WORD   e_cparhdr;                   // Size of header in paragraphs
        WORD   e_minalloc;                  // Minimum extra paragraphs needed
        WORD   e_maxalloc;                  // Maximum extra paragraphs needed
        WORD   e_ss;                        // Initial (relative) SS value
        WORD   e_sp;                        // Initial SP value
        WORD   e_csum;                      // Checksum
        WORD   e_ip;                        // Initial IP value
        WORD   e_cs;                        // Initial (relative) CS value
        WORD   e_lfarlc;                    // File address of relocation table
        WORD   e_ovno;                      // Overlay number
        WORD   e_res[4];                    // Reserved words
        WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
        WORD   e_oeminfo;                   // OEM information; e_oemid specific
        WORD   e_res2[10];                  // Reserved words
        LONG   e_lfanew;                    // File address of new exe header
    } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

"""
ImageDosHeader = Struct(
    "e_magic" / Const("MZ"),
    "e_cblp" / Int16ul,
    "e_cp" / Int16ul, 
    "e_crlc" / Int16ul,
    "e_cparhdr" / Int16ul,
    "e_minalloc" / Int16ul,
    "e_maxalloc" / Int16ul,
    "e_ss" / Int16ul,
    "e_sp" / Int16ul,
    "e_csum" / Int16ul,
    "e_ip" / Int16ul,
    "e_cs" / Int16ul,
    "e_lfarlc" / Int16ul,
    "e_ovno" / Int16ul,
    "e_res"  / Array(4, Int16ul),
    "e_oemid" / Int16ul,
    "e_oeminfo" / Int16ul,
    "e_res2" / Array(10, Int16ul),
    "e_lfanew" / Int32ul,
)