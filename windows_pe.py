import construct

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
ImageDosHeader = construct.Struct(
    "e_magic" / construct.Const("MZ"),
    "e_cblp" / construct.Int16ul,
    "e_cp" / construct.Int16ul, 
    "e_crlc" / construct.Int16ul,
    "e_cparhdr" / construct.Int16ul,
    "e_minalloc" / construct.Int16ul,
    "e_maxalloc" / construct.Int16ul,
    "e_ss" / construct.Int16ul,
    "e_sp" / construct.Int16ul,
    "e_csum" / construct.Int16ul,
    "e_ip" / construct.Int16ul,
    "e_cs" / construct.Int16ul,
    "e_lfarlc" / construct.Int16ul,
    "e_ovno" / construct.Int16ul,
    "e_res"  / construct.Array(4, construct.Int16ul),
    "e_oemid" / construct.Int16ul,
    "e_oeminfo" / construct.Int16ul,
    "e_res2" / construct.Array(10, construct.Int16ul),
    "e_lfanew" / construct.Int32ul,
)

"""
FROM WINNT.H:

    typedef struct _IMAGE_FILE_HEADER {
        WORD    Machine;
        WORD    NumberOfSections;
        DWORD   TimeDateStamp;
        DWORD   PointerToSymbolTable;
        DWORD   NumberOfSymbols;
        WORD    SizeOfOptionalHeader;
        WORD    Characteristics;
    } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

"""
ImageFileHeader = construct.Struct(
    "machine" / construct.Int16ul,
    "section_count" / construct.Int16ul,
    "timestamp" / construct.Int32ul,
    "symbol_table_ptr" / construct.Int32ul,
    "symbol_count" / construct.Int32ul,
    "optional_header_size" / construct.Int16ul,
    "characteristics" / construct.Int16ul
)

ImageNtHeader = construct.Struct(
    "pe_magic" / construct.Const("PE"),
    "file_header" / ImageFileHeader, 
    #"optional_header" /
)

def dos_stub(lfanew):
    return construct.Bytes(lfanew - ImageDosHeader.sizeof())

PeFile = construct.Struct(
    "dos_header" / ImageDosHeader,
    "dos_stub_program" / dos_stub(construct.this.dos_header.e_lfanew),
    "pe_header" / 
)

def test():
    exe = ""
    with open(r"C:\Projects\Playground\Playground\Debug\Playground.exe", "rb") as my_file:
        exe = my_file.read()

    parsed = PeFile.parse(exe)

    return 0

test()

class PeFixChecksum(construct.Adapter):
    def _decode(self, obj, context, path):
        # Parsing - Probably irrelevant!
        return obj

    def _encode(self, obj, context, path):
        # Building
        return obj