
//  brainf*ck compiler, for x86/windows
//	bfc.cpp
//	copyright 2013 naoki.kp

#define _CRT_SECURE_NO_WARNINGS

#include <cstdio>
#include <ctime>
#include <string>
#include <vector>
#include <map>
#include <windows.h>

#define EXE_IMAGE_BASE  0x00400000
#define ALIGNSIZE       0x1000
#define FILEALIGNSIZE   0x0200
#define HEADER_SIZE     0x0200
#define DATA_SEC_SIZE   0x0000000c
#define LOOPSTACK_MAX   128
#define OPTIMIZE        1

// ネイティブコード
BYTE NativeBuffer[] = {
    0x8D,0x1D,0x7C,0x10,0x40,0x00,0x6A,0xF6,0xFF,0x15,0x7C,0x10,0x40,0x00,0x89,0x03,
    0x6A,0xF5,0xFF,0x15,0x7C,0x10,0x40,0x00,0x89,0x43,0x04,0x6A,0x04,0x68,0x00,0x10,
    0x10,0x00,0x68,0x00,0x00,0x01,0x00,0x6A,0x00,0xFF,0x15,0x7C,0x10,0x40,0x00,0x89,
    0xC7,0xE8,0x45,0x00,0x00,0x00,0xEB,0x3A,0x6A,0x00,0x8D,0x1D,0x7C,0x10,0x40,0x00,
    0x8D,0x4B,0x08,0x51,0x6A,0x01,0x57,0xFF,0x33,0xFF,0x15,0x7C,0x10,0x40,0x00,0x80,
    0x3F,0x0D,0x0F,0x84,0xE0,0xFF,0xFF,0xFF,0xC3,0x6A,0x00,0x8D,0x1D,0x7C,0x10,0x40,
    0x00,0x8D,0x4B,0x08,0x51,0x6A,0x01,0x57,0xFF,0x73,0x04,0xFF,0x15,0x7C,0x10,0x40,
    0x00,0xC3,0x6A,0x00,0xFF,0x15,0x7C,0x10,0x40,0x00,0xC3,
};
const int pos_getchar = 0x38;
const int pos_putchar = 0x59;

struct _RelocationTable {
    unsigned int offset;
    const char *procname;
} RelocationTable[] = {
    { 0x0002, ".data" },
    { 0x000a, "kernel32.dll:GetStdHandle" },
    { 0x0014, "kernel32.dll:GetStdHandle" },
    { 0x002b, "kernel32.dll:VirtualAlloc" },
    { 0x003c, ".data" },
    { 0x004b, "kernel32.dll:ReadFile" },
    { 0x005d, ".data" },
    { 0x006d, "kernel32.dll:WriteFile" },
    { 0x0076, "kernel32.dll:ExitProcess" },
};

BYTE Native_incptr[]        = { 0x47 };
BYTE Native_decptr[]        = { 0x4f };
BYTE Native_incptrind[]     = { 0xfe, 0x07 };
BYTE Native_decptrind[]     = { 0xfe, 0x0f };
BYTE Native_incptr_mul[]    = { 0x83, 0xc7, 0xcc };
BYTE Native_decptr_mul[]    = { 0x83, 0xef, 0xcc };
BYTE Native_incptrind_mul[] = { 0x80, 0x07, 0xcc };
BYTE Native_decptrind_mul[] = { 0x80, 0x2f, 0xcc };
BYTE Native_call[]          = { 0xe8, 0xcc, 0xcc, 0xcc, 0xcc };
BYTE Native_cmpjmp[]        = { 0x80, 0x3f, 0x00, 0x0f, 0x84, 0xcc, 0xcc, 0xcc, 0xcc };
BYTE Native_jmp[]           = { 0xe9, 0xcc, 0xcc, 0xcc, 0xcc };
const int pos_mul_ptr       = 2;
const int pos_call_ptr      = 1;
const int pos_cmpjmp_ptr    = 5;
const int pos_jmp_ptr       = 1;

std::vector<BYTE> BFCode;

struct IMPORT_DLL_INFO {
    const char *dllname;
    const char **import_hint;
};

const char *ImportDLL_user32[] = {
    "MessageBoxA",
    NULL,   // Terminater
};
const char *ImportDLL_kernel32[] = {
    "GetStdHandle",
    "ReadFile",
    "WriteFile",
    "ExitProcess",
    "VirtualAlloc",
    NULL,   // Terminater
};
struct IMPORT_DLL_INFO ImportDllInfo[] = {
    { "user32.dll",     ImportDLL_user32 },
    { "kernel32.dll",   ImportDLL_kernel32 },
};

//初期済みデータ（データセクションに保存されるバイナリ）
//BYTE InitBuffer[] = "Hello World";
BYTE InitBuffer[] = "";

std::map<std::string, DWORD> IAT;

BYTE DosCodeBuffer[16] = {
    0xb8, 0x01, 0x4c,   // mov ax, 4c01
    0xcd, 0x21,         // int 21
};

int align(int n, int m){ return (n + m - 1) / m * m; }

struct loopstack{
    int pos;
    int nextpos;
    int relpos;
} stack[LOOPSTACK_MAX];
int stackpos = 0;
int hdrcodesize = sizeof(NativeBuffer);

int setnative(int ch, BYTE *addbuf, int filepos, int pos, int param){
    int addlen = 0;

#ifdef _DEBUG
    printf("pos = %3d, filepos = %3d : ", pos, filepos);
    if(ch == EOF) printf("EOF\n"); else printf("'%c' %d\n",  ch, param);
#endif

    switch(ch){
    case '>':
        if(param > 1){
            addlen = sizeof(Native_incptr_mul);
            memcpy(addbuf, Native_incptr_mul, addlen);      // add edi, xx
            *(char *)&(addbuf[pos_mul_ptr]) = param;
            break;
        }
        addlen = sizeof(Native_incptr);
        memcpy(addbuf, Native_incptr, addlen);      // inc edi
        break;
    case '<':
        if(param > 1){
            addlen = sizeof(Native_decptr_mul);
            memcpy(addbuf, Native_decptr_mul, addlen);      // sub edi, xx
            *(char *)&(addbuf[pos_mul_ptr]) = param;
            break;
        }
        addlen = sizeof(Native_decptr);
        memcpy(addbuf, Native_decptr, addlen);      // inc edi
        break;
    case '+':
        if(param > 1){
            addlen = sizeof(Native_incptrind_mul);
            memcpy(addbuf, Native_incptrind_mul, addlen);   // add byte [edi], xx
            *(char *)&(addbuf[pos_mul_ptr]) = param;
            break;
        }
        addlen = sizeof(Native_incptrind);
        memcpy(addbuf, Native_incptrind, addlen);   // inc byte ptr [edi]
        break;
    case '-':
        if(param > 1){
            addlen = sizeof(Native_decptrind_mul);
            memcpy(addbuf, Native_decptrind_mul, addlen);   // sub byte [edi], xx
            *(char *)&(addbuf[pos_mul_ptr]) = param;
            break;
        }
        addlen = sizeof(Native_decptrind);
        memcpy(addbuf, Native_decptrind, addlen);   // inc byte ptr [edi]
        break;

    case '.':
        addlen = sizeof(Native_call);
        memcpy(addbuf, Native_call, addlen);        // call putchar
        *(DWORD *)&(addbuf[pos_call_ptr]) = pos_putchar - (hdrcodesize + pos + addlen);
        break;
    case ',':
        addlen = sizeof(Native_call);
        memcpy(addbuf, Native_call, addlen);        // call getchar
        *(DWORD *)&(addbuf[pos_call_ptr]) = pos_getchar - (hdrcodesize + pos + addlen);
        break;
    case '[':
        addlen = sizeof(Native_cmpjmp);
        memcpy(addbuf, Native_cmpjmp, addlen);      // cmp byte ptr[edi],0; jz xxx
        stack[stackpos].pos = pos;
        stack[stackpos].nextpos = pos + addlen;
        stack[stackpos].relpos = pos + pos_cmpjmp_ptr;
        stackpos++;
        break;
    case ']':
        addlen = sizeof(Native_jmp);
        memcpy(addbuf, Native_jmp, addlen);        // jmp xxx
        if(stackpos > 0){
            stackpos--;
            *(DWORD *)&(BFCode[stack[stackpos].relpos]) = (pos + addlen) - stack[stackpos].nextpos;
            *(DWORD *)&(addbuf[pos_jmp_ptr]) = stack[stackpos].pos - (pos + addlen);
        } else {
            printf("対応する'['がありません。 filepos = %d\n", filepos);
            exit(1);
        }
        break;

    case EOF:
        addlen = 1;
        addbuf[0] = 0xc3;   // ret
        break;
    }
    return addlen;
}

bool checkch(int ch){
    switch(ch){
    case '>': case '<': case '+': case '-':
    case '.': case ',': case '[': case ']':
    case EOF:
        return true;
    }
    return false;
}

int bfc_compile(FILE *ifp){
    int filepos = 0;
    int pos = 0;
#if OPTIMIZE
    int optch = 0;
    int optnum = 0;
#endif

    while(1){
        int ch = fgetc(ifp);
        BYTE addbuf[16];
        int addlen = 0;
        filepos++;

        if(!checkch(ch)) continue;

#if OPTIMIZE
        if(optch){
            if(optch != ch || optnum >= 127){
                addlen = setnative(optch, addbuf, filepos, pos, optnum);
            } else {
                optnum++;
                continue;
            }
            BFCode.resize(pos + addlen);
            memcpy(&(BFCode[pos]), addbuf, addlen);
            pos += addlen;
            optch = 0;
        }
        if(ch == '>' || ch == '<' || ch == '+' || ch == '-'){
            optch = ch; optnum = 1; continue;
        }
#endif
        addlen = setnative(ch, addbuf, filepos, pos, 0);
        if(!addlen) continue;

        BFCode.resize(pos + addlen);
        memcpy(&(BFCode[pos]), addbuf, addlen);
        pos += addlen;
        if(ch == EOF) break;
    }
    return pos;
}

size_t fwrite_byte(BYTE byte, size_t size, FILE *fp){
    std::vector<BYTE> buf(size);
    memset(buf.data(), byte, size);
    return fwrite(buf.data(), 1, size, fp);
}


int bfc_ouptput_exe(FILE *ofp){
#ifdef _DEBUG
    {
        int size = BFCode.size();
        if(sizeof(NativeBuffer) + size <= ALIGNSIZE){
            int addsize = align(sizeof(NativeBuffer) + size, ALIGNSIZE) - sizeof(NativeBuffer) - size;
            BFCode.resize(BFCode.size() + addsize);
            memset(BFCode.data() + size, 0xdd, addsize);
        }
    }
#endif
    int size_codesec_raw = sizeof(NativeBuffer) + BFCode.size();
    int size_codesec = align(size_codesec_raw, ALIGNSIZE);
    int size_datasec = align(max(sizeof(InitBuffer), DATA_SEC_SIZE), ALIGNSIZE);
    int pos_codesec  = align(HEADER_SIZE, ALIGNSIZE);
    int pos_imptsec  = pos_codesec + size_codesec;

    int size_codesec_file = align(sizeof(NativeBuffer) + BFCode.size(), FILEALIGNSIZE);
    int size_datasec_file = align(sizeof(InitBuffer), FILEALIGNSIZE);
    int pos_codesec_file  = align(HEADER_SIZE, FILEALIGNSIZE);
    int pos_imptsec_file  = pos_codesec_file + size_codesec_file;

    if(sizeof(InitBuffer) == 1 && InitBuffer[0] == 0){
        size_datasec_file = 0;
    }

    int Import_DLL_Num = sizeof(ImportDllInfo) / sizeof(ImportDllInfo[0]);
    int Import_Proc_Num = 0;
    for(int i = 0; i < Import_DLL_Num; i++){
        const char **import_hint = ImportDllInfo[i].import_hint;
        for(int j = 0; ;j++){
            if(import_hint[j] != NULL) Import_Proc_Num++; else break;
        }
    }
    // メモリ確保
    int size_ImportDesc = sizeof(IMAGE_IMPORT_DESCRIPTOR) * (Import_DLL_Num + 1);
    IMAGE_IMPORT_DESCRIPTOR *ImportDesc = (IMAGE_IMPORT_DESCRIPTOR *)malloc(size_ImportDesc);
    memset(ImportDesc, 0, size_ImportDesc);

    int pos_LookupTable = pos_imptsec + size_ImportDesc;
    int size_LookupTable = sizeof(DWORD) * (Import_Proc_Num + Import_DLL_Num);
    DWORD *LookupTable = (DWORD *)malloc(size_LookupTable);
    memset(LookupTable, 0, size_LookupTable);
    int index_LookupTable = 0;

    int pos_HintTable = pos_LookupTable + size_LookupTable * 2;
    std::vector<char> HintTable;

    // インポートセクション生成
    for(int i = 0; i < Import_DLL_Num; i++){
        ImportDesc[i].OriginalFirstThunk    = pos_LookupTable + sizeof(DWORD) * index_LookupTable;
        ImportDesc[i].TimeDateStamp         = 0;
        ImportDesc[i].ForwarderChain        = 0;
        ImportDesc[i].Name                  = pos_HintTable + HintTable.size();
        ImportDesc[i].FirstThunk            = pos_LookupTable + sizeof(DWORD) * index_LookupTable + size_LookupTable;
        int htpos = HintTable.size();
        HintTable.resize(htpos + strlen(ImportDllInfo[i].dllname) + 1);
        strcpy(&(HintTable[htpos]), ImportDllInfo[i].dllname);
        if(HintTable.size() % 2) HintTable.resize(HintTable.size()+1);

        const char **import_hint = ImportDllInfo[i].import_hint;
        for(int j = 0; ;j++){
            if(import_hint[j] == NULL){
                LookupTable[index_LookupTable++] = 0;
                break;
            }
            int htpos = HintTable.size();
            LookupTable[index_LookupTable] = pos_HintTable + htpos;
            HintTable.resize(htpos + 2 + strlen(import_hint[j]) + 1);
            *(WORD*)&(HintTable[htpos]) = 0;
            strcpy(&(HintTable[htpos]) + 2, import_hint[j]);
            if(HintTable.size() % 2) HintTable.resize(HintTable.size()+1);

            DWORD IATAddr = EXE_IMAGE_BASE + pos_LookupTable + sizeof(DWORD) * index_LookupTable + size_LookupTable;
#ifdef _DEBUG
            printf("%s:%s IAT = 0x%08x\n", ImportDllInfo[i].dllname, import_hint[j], IATAddr);
#endif
            std::string procname = ImportDllInfo[i].dllname;
            procname += ":"; procname += import_hint[j];
            IAT.insert(make_pair(procname, IATAddr));

            index_LookupTable++;
        }
    }

    int size_imptsec_raw = size_ImportDesc + size_LookupTable * 2 + HintTable.size();
    int size_imptsec = align(size_imptsec_raw, ALIGNSIZE);
    int pos_datasec  = pos_imptsec + size_imptsec;

    int size_imptsec_file = align(size_imptsec_raw, FILEALIGNSIZE);;
    int pos_datasec_file  = pos_imptsec_file + size_imptsec_file;
    if(size_datasec_file == 0){
        pos_datasec_file = 0;
    }
    IAT.insert(make_pair(std::string(".data"), (DWORD)(EXE_IMAGE_BASE + pos_datasec)));

    // リロケーション
    for(int i = 0; i < sizeof(RelocationTable)/sizeof(RelocationTable[0]); i++){
        auto it = IAT.find(RelocationTable[i].procname);
        if(it != IAT.end()){
            *(DWORD *)(&NativeBuffer[RelocationTable[i].offset]) = it->second;
        }
    }

    IMAGE_DOS_HEADER ImageDosHeader;
    memset(&ImageDosHeader, 0, sizeof(ImageDosHeader));
    ImageDosHeader.e_magic      = 0x5A4D;
    ImageDosHeader.e_cblp       = 0x0040;
    ImageDosHeader.e_cp         = 0x0001;
    ImageDosHeader.e_crlc       = 0x0000;
    ImageDosHeader.e_cparhdr    = 0x0002;
    ImageDosHeader.e_minalloc   = 0x0000;
    ImageDosHeader.e_maxalloc   = 0xFFFF;
    ImageDosHeader.e_ss         = 0x0000;
    ImageDosHeader.e_sp         = 0x0000;
    ImageDosHeader.e_csum       = 0x0000;
    ImageDosHeader.e_ip         = 0x0000;
    ImageDosHeader.e_cs         = 0x0000;
    ImageDosHeader.e_lfarlc     = 0x0000;
    ImageDosHeader.e_ovno       = 0x0000;
    ImageDosHeader.e_lfanew     = sizeof(ImageDosHeader);
    memcpy(((char*)&ImageDosHeader) + 0x0020 + ImageDosHeader.e_ip, DosCodeBuffer, sizeof(DosCodeBuffer));

    IMAGE_NT_HEADERS ImagePeHeader;
    memset(&ImagePeHeader, 0, sizeof(ImagePeHeader));
    ImagePeHeader.Signature                         = IMAGE_NT_SIGNATURE;

    ImagePeHeader.FileHeader.Machine                = IMAGE_FILE_MACHINE_I386;
    ImagePeHeader.FileHeader.NumberOfSections       = 3;
    ImagePeHeader.FileHeader.TimeDateStamp          = (DWORD)time(NULL);
    ImagePeHeader.FileHeader.PointerToSymbolTable   = 0;
    ImagePeHeader.FileHeader.NumberOfSymbols        = 0;
    ImagePeHeader.FileHeader.SizeOfOptionalHeader   = sizeof(ImagePeHeader.OptionalHeader);
    ImagePeHeader.FileHeader.Characteristics        =
        IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE | IMAGE_FILE_RELOCS_STRIPPED;

    ImagePeHeader.OptionalHeader.Magic                          = 0x010B;
    ImagePeHeader.OptionalHeader.MajorLinkerVersion             = 10;
    ImagePeHeader.OptionalHeader.MinorLinkerVersion             = 0;
    ImagePeHeader.OptionalHeader.SizeOfCode                     = align(sizeof(NativeBuffer) + BFCode.size(), ALIGNSIZE);
    ImagePeHeader.OptionalHeader.SizeOfInitializedData          = size_imptsec + size_datasec;
    ImagePeHeader.OptionalHeader.SizeOfUninitializedData        = 0;
    ImagePeHeader.OptionalHeader.AddressOfEntryPoint            = pos_codesec;
    ImagePeHeader.OptionalHeader.BaseOfCode                     = pos_codesec;
    ImagePeHeader.OptionalHeader.BaseOfData                     = pos_imptsec;
    ImagePeHeader.OptionalHeader.ImageBase                      = EXE_IMAGE_BASE;
    ImagePeHeader.OptionalHeader.SectionAlignment               = ALIGNSIZE;
    ImagePeHeader.OptionalHeader.FileAlignment                  = FILEALIGNSIZE;
    ImagePeHeader.OptionalHeader.MajorOperatingSystemVersion    = 4;
    ImagePeHeader.OptionalHeader.MinorOperatingSystemVersion    = 0;
    ImagePeHeader.OptionalHeader.MajorImageVersion              = 0;
    ImagePeHeader.OptionalHeader.MinorImageVersion              = 0;
    ImagePeHeader.OptionalHeader.MajorSubsystemVersion          = 4;
    ImagePeHeader.OptionalHeader.MinorSubsystemVersion          = 0;
    ImagePeHeader.OptionalHeader.Win32VersionValue              = 0;
    ImagePeHeader.OptionalHeader.SizeOfImage                    = align(HEADER_SIZE, ALIGNSIZE) + size_codesec + size_imptsec + size_datasec;
    ImagePeHeader.OptionalHeader.SizeOfHeaders                  = HEADER_SIZE;
    ImagePeHeader.OptionalHeader.CheckSum                       = 0;
    ImagePeHeader.OptionalHeader.Subsystem                      = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    ImagePeHeader.OptionalHeader.DllCharacteristics             = IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_NO_SEH | IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE;
    ImagePeHeader.OptionalHeader.SizeOfStackReserve             = 0x00100000;
    ImagePeHeader.OptionalHeader.SizeOfStackCommit              = 0x00001000;
    ImagePeHeader.OptionalHeader.SizeOfHeapReserve              = 0x00100000;
    ImagePeHeader.OptionalHeader.SizeOfHeapCommit               = 0x00001000;
    ImagePeHeader.OptionalHeader.LoaderFlags                    = 0;
    ImagePeHeader.OptionalHeader.NumberOfRvaAndSizes            = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    // データ ディクショナリ //
    //  [1]インポートテーブル
    ImagePeHeader.OptionalHeader.DataDirectory[1].VirtualAddress    = pos_imptsec;
    ImagePeHeader.OptionalHeader.DataDirectory[1].Size              = size_imptsec_raw;
    //  [12]インポートアドレステーブル
    ImagePeHeader.OptionalHeader.DataDirectory[12].VirtualAddress   = pos_LookupTable + size_LookupTable;
    ImagePeHeader.OptionalHeader.DataDirectory[12].Size             = size_LookupTable;

    // コードセクションヘッダ
    IMAGE_SECTION_HEADER CodeSectionHeader;
    memset(&CodeSectionHeader, 0, sizeof(CodeSectionHeader));
    strcpy((char *)CodeSectionHeader.Name, ".text");
    CodeSectionHeader.Misc.VirtualSize      = size_codesec_raw;                     // メモリ上のサイズ
    CodeSectionHeader.VirtualAddress        = pos_codesec;                          // メモリ上の開始アドレス
    CodeSectionHeader.SizeOfRawData         = align(sizeof(NativeBuffer) + BFCode.size(), FILEALIGNSIZE);
                                                                                    // ファイル上のサイズ
    CodeSectionHeader.PointerToRawData      = pos_codesec_file;                     // ファイル上の開始アドレス
    CodeSectionHeader.PointerToRelocations  = 0;
    CodeSectionHeader.PointerToLinenumbers  = 0;
    CodeSectionHeader.NumberOfRelocations   = 0;
    CodeSectionHeader.NumberOfLinenumbers   = 0;
    CodeSectionHeader.Characteristics       = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;

    // インポートセクションヘッダ
    IMAGE_SECTION_HEADER ImptSectionHeader;
    memset(&ImptSectionHeader, 0, sizeof(ImptSectionHeader));
    strcpy((char *)ImptSectionHeader.Name, ".idata");
    ImptSectionHeader.Misc.VirtualSize      = size_imptsec_raw;
    ImptSectionHeader.VirtualAddress        = pos_imptsec;
    ImptSectionHeader.SizeOfRawData         = size_imptsec_file;
    ImptSectionHeader.PointerToRawData      = pos_imptsec_file;
    ImptSectionHeader.PointerToRelocations  = 0;
    ImptSectionHeader.PointerToLinenumbers  = 0;
    ImptSectionHeader.NumberOfRelocations   = 0;
    ImptSectionHeader.NumberOfLinenumbers   = 0;
    ImptSectionHeader.Characteristics       = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

    // データセクションヘッダ
    IMAGE_SECTION_HEADER DataSectionHeader;
    memset(&DataSectionHeader, 0, sizeof(DataSectionHeader));
    strcpy((char *)DataSectionHeader.Name, ".data");
    DataSectionHeader.Misc.VirtualSize      = DATA_SEC_SIZE;
    DataSectionHeader.VirtualAddress        = pos_datasec;
    DataSectionHeader.SizeOfRawData         = size_datasec_file;
    DataSectionHeader.PointerToRawData      = pos_datasec_file;
    DataSectionHeader.PointerToRelocations  = 0;
    DataSectionHeader.PointerToLinenumbers  = 0;
    DataSectionHeader.NumberOfRelocations   = 0;
    DataSectionHeader.NumberOfLinenumbers   = 0;
    DataSectionHeader.Characteristics       = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    int ofs = 0;
    // DOS Header
    ofs += fwrite(&ImageDosHeader,      1, sizeof(ImageDosHeader), ofp);
//  ofs += fwrite(&DosCodeBuffer,       1, sizeof(DosCodeBuffer), ofp);
    ofs += fwrite_byte(0x00,            ImageDosHeader.e_lfanew - ofs, ofp);
    // PE Header
    ofs += fwrite(&ImagePeHeader,       1, sizeof(ImagePeHeader), ofp);
    // Section Header
    ofs += fwrite(&CodeSectionHeader,   1, sizeof(CodeSectionHeader), ofp);
    ofs += fwrite(&ImptSectionHeader,   1, sizeof(ImptSectionHeader), ofp);
    ofs += fwrite(&DataSectionHeader,   1, sizeof(DataSectionHeader), ofp);
    ofs += fwrite_byte(0x00,            HEADER_SIZE - ofs, ofp);

    // Code Section
    ofs += fwrite(NativeBuffer,         1, sizeof(NativeBuffer), ofp);
    if(BFCode.size() > 0)
    ofs += fwrite(&(BFCode[0]),         1, BFCode.size(), ofp);
    ofs += fwrite_byte(0x00,            align(ofs, FILEALIGNSIZE) - ofs, ofp);

    // Import Section
    ofs += fwrite(ImportDesc,           1, size_ImportDesc, ofp);
    ofs += fwrite(LookupTable,          1, size_LookupTable, ofp);  // import name table
    ofs += fwrite(LookupTable,          1, size_LookupTable, ofp);  // import address table
    ofs += fwrite(&(HintTable[0]),      1, HintTable.size(), ofp);
    ofs += fwrite_byte(0x00,            align(ofs, FILEALIGNSIZE) - ofs, ofp);

    // Data Section
    if(size_datasec_file){
    ofs += fwrite(InitBuffer,           1, sizeof(InitBuffer), ofp);
    ofs += fwrite_byte(0x00,            align(ofs, FILEALIGNSIZE) - ofs, ofp);
    }

    return 0;
}


int bfc(const char *ifn, const char *ofn){

    FILE *ifp = NULL;
    FILE *ofp = NULL;

    ifp = fopen(ifn, "rb");
    if(!ifp) goto end;
    int len = bfc_compile(ifp);
    if(len){
        ofp = fopen(ofn, "wb");
        if(!ofp) goto end;
        bfc_ouptput_exe(ofp);
    }

end:
    if(ifp) fclose(ifp);
    if(ofp) fclose(ofp);

    return 0;
}

int main(int argc, char **argv){
    if(argc != 2){
        puts("bfc.exe");
        puts(" usage: bfc.exe <*.bf>");
        return 0;
    }
    const char *ifn = argv[1];
    char ofn[_MAX_PATH];

    // 出力ファイル名生成
    strcpy(ofn, ifn);
    int len = strlen(ofn);
    if(len >= 4 && strcmp(ofn+len-3, ".bf") == 0){
        strcpy(ofn+len-3, ".exe");
    } else {
        strcat(ofn, ".exe");
    }

    return bfc(ifn, ofn);
}

