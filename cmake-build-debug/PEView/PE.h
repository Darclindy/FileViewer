//
// Created by dell on 2021/4/13.
//

#ifndef FILEVIEWER_PE_H
#define FILEVIEWER_PE_H

#endif //FILEVIEWER_PE_H

#pragma once
#include<stdio.h>
#include<stdint.h>
#include<stdlib.h>
#include <stdbool.h>

#define IMAGE_DOS_SIGNATURE					0x5A4D	//DOS头的魔数
#define IMAGE_NT_SIGNATURE					0x4550	//NT头的魔数
#define SIZE_OF_DOS_HEADER					0x40	//DOS头的大小
#define SIZE_OF_NT_HEADER					0xF8	//NT头的大小
#define SIZE_OF_SECTION_HEADER				0x28	//节区头大小
#define SIZE_OF_IMPORT_DESTRUCTUER			0x14	//输入表结构体
#define SIZE_OF_THUNK_DATA					0x4		//THUNK共用体大小
#define SIZE_OF_POINT						0x4		//指针大小

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES	0x10	//结构体数组的个数
#define IMAGE_SIZEOF_SHORT_NAME				0x08	//节区名数组值
#define IMAGE_FILE_RELOCS_STRIPPED           0x0001  // Relocation info stripped from file.
#define IMAGE_FILE_EXECUTABLE_IMAGE          0x0002  // File is executable  (i.e. no unresolved external references).
#define IMAGE_FILE_LINE_NUMS_STRIPPED        0x0004  // Line nunbers stripped from file.
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED       0x0008  // Local symbols stripped from file.
#define IMAGE_FILE_AGGRESIVE_WS_TRIM         0x0010  // Aggressively trim working set
#define IMAGE_FILE_LARGE_ADDRESS_AWARE       0x0020  // App can handle >2gb addresses
#define IMAGE_FILE_BYTES_REVERSED_LO         0x0080  // Bytes of machine word are reversed.
#define IMAGE_FILE_32BIT_MACHINE             0x0100  // 32 bit word machine.
#define IMAGE_FILE_DEBUG_STRIPPED            0x0200  // Debugging info stripped from file in .DBG file
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP   0x0400  // If Image is on removable media, copy and run from the swap file.
#define IMAGE_FILE_NET_RUN_FROM_SWAP         0x0800  // If Image is on Net, copy and run from the swap file.
#define IMAGE_FILE_SYSTEM                    0x1000  // System File.
#define IMAGE_FILE_DLL                       0x2000  // File is a DLL.
#define IMAGE_FILE_UP_SYSTEM_ONLY            0x4000  // File should only be run on a UP machine
#define IMAGE_FILE_BYTES_REVERSED_HI         0x8000  // Bytes of machine word are reversed.


typedef int32_t LONG;		//LONG = unsigned 64 bit value
typedef uint32_t DWORD;		// DWORD = unsigned 32 bit value
typedef uint16_t WORD;		// WORD = unsigned 16 bit value
typedef uint8_t BYTE;		// BYTE = unsigned 8 bit value

//节区头中的地址
typedef struct _IMAGE_DATA_DIRECTORY
{
    DWORD   VirtualAddress;                //相对虚拟地址RVA
    DWORD   Size;                          //大小
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

//DOS头
typedef struct _IMAGE_DOS_HEADER {
    WORD	e_magic;                     // DOS魔数：4D5A("MZ")
    WORD	e_cblp;
    WORD	e_cp;
    WORD	e_crlc;
    WORD	e_cparhdr;
    WORD	e_minalloc;
    WORD	e_maxalloc;
    WORD	e_ss;
    WORD	e_sp;
    WORD	e_csum;
    WORD	e_ip;
    WORD	e_cs;
    WORD	e_lfarlc;
    WORD	e_ovno;
    WORD	e_res[4];
    WORD	e_oemid;
    WORD	e_oeminfo;
    WORD	res2[10];
    LONG	e_lfanew;                    // 指向文件头开始,在偏移0x3C处
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;


typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;                         //CPU类型        不可更改
    WORD    NumberOfSections;                //节数量         可以更改
    DWORD   TimeDateStamp;                   //文件创建时间   可以更改
    DWORD   PointerToSymbolTable;            //符号表偏移     可以更改
    DWORD   NumberOfSymbols;                 //符号数量       可以更改
    WORD    SizeOfOptionalHeader;            //指定选项头大小 可以更改
    WORD    Characteristics;                 //文件属性       不可更改
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;



//YES:表示可以改  NO:表示不能改  RES：表示能改但是有限制
typedef struct _IMAGE_OPTIONAL_HEADER
{
    WORD    Magic;							//NO 机器型号,判断是 PE是 32位还是 64位;
    BYTE    MajorLinkerVersion;				//YES 链接器版本号高版本
    BYTE    MinorLinkerVersion;				//YES 链接器版本号低版本,组合起来就是 5.12 其中 5是高版本,C是低版本
    DWORD   SizeOfCode;						//YES 代码节的总大小(512为一个磁盘扇区)
    DWORD   SizeOfInitializedData;			//YES 初始化数据的节的总大小,也就是.data
    DWORD   SizeOfUninitializedData;		//YES 未初始化数据的节的大小,也就是.data?
    DWORD   AddressOfEntryPoint;			//NO 程序执行入口地址(OEP) RVA(相对虚拟偏移地址)
    DWORD   BaseOfCode;						//YES 代码的节的起始 RVA(相对偏移)也就是代码区的偏移,偏移+模块首地址定位代码区
    DWORD   BaseOfData;						//YES 数据结的起始偏移(RVA),同上
    DWORD   ImageBase;						//YES 程序的建议模块基址(意思就是说作参考用的,模块建议基址如果被使用了就会使用别的地址)
    DWORD   SectionAlignment;				//RES 内存中的节对齐 一般是0x1000
    DWORD   FileAlignment;					//RES 文件中的节对齐 一般是0x200
    WORD    MajorOperatingSystemVersion;	//YES 操作系统版本号高位
    WORD    MinorOperatingSystemVersion;	//YES 操作系统版本号低位
    WORD    MajorImageVersion;				//YES PE版本号高位
    WORD    MinorImageVersion;				//YES PE版本号低位
    WORD    MajorSubsystemVersion;			//NO 子系统版本号高位
    WORD    MinorSubsystemVersion;			//YES 子系统版本号低位
    DWORD   Win32VersionValue;				//YES 32位系统版本号值,注意只能修改为4 5 6表示操作系统支持nt4.0 以上,5的话依次类推
    DWORD   SizeOfImage;					//RES 整个程序也就是整PE文件在内存中占用的空间(包含PE映射尺寸)
    DWORD   SizeOfHeaders;					//RES 所有头大小(头的结构体大小)+节表结构体大小，记得值一定是文件对齐值的倍数，也就是到第一节区实际位置的偏移
    DWORD   CheckSum;						//YES 校验和,对于驱动程序,可能会使用
    WORD    Subsystem;						//NO 文件的子系统 :0x02表示窗口程序
    WORD    DllCharacteristics;				//NO DLL文件属性,也可以成为特性,可能DLL文件可以当做驱动程序使用
    DWORD   SizeOfStackReserve;				//RES 预留的栈的大小
    DWORD   SizeOfStackCommit;				//RES 立即申请的栈的大小(分页为单位)
    DWORD   SizeOfHeapReserve;				//RES 预留的堆空间大小
    DWORD   SizeOfHeapCommit;				//RES 立即申请的堆的空间的大小
    DWORD   LoaderFlags;					//YES 与调试有关
    DWORD	NumberOfRvaAndSizes;			//用来指定 数组的个数
    IMAGE_DATA_DIRECTORY	DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];					//结构体数组
}IMAGE_OPTIONAL_HEADER32,*PIMAGE_OPTIONAL_HEADER32;

//NT头
typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;                           //固定值 PE文件标志4个字节
    IMAGE_FILE_HEADER FileHeader;              //文件头结构体
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;    //选项头结构体（注意这个结构体是变长的)所以要偏移到下一个数据段的时候，跳过这个就不能写加sizeof IMAGE_OPTIONAL_HEADER32 （结构体大小为E0）不然读取PE文件格式就出错
} IMAGE_NT_HEADER32, *PIMAGE_NT_HEADER32;



//节区头
typedef struct _IMAGE_SECTION_HEADER
{
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];		//YES 节区的名字 8个字节
    union
    {
        DWORD   PhysicalAddress;
        DWORD   VirtualSize;					//YES 节区在内存的大小，实际值是按内存对齐算
    } Misc;
    DWORD   VirtualAddress;//虚拟地址 节区的 RVA地址(拷到内存中哪个位置)
    DWORD   SizeOfRawData; //在文件中对齐的尺寸（拷多大）
    DWORD   PointerToRawData; //在文件中的偏移FA（从文件哪里开始拷）
    DWORD   PointerToRelocations; //在 OBJ文件中使用
    DWORD   PointerToLinenumbers; //行号表位置,调试使用
    WORD    NumberOfRelocations; //在 OBJ文件中使用
    WORD    NumberOfLinenumbers; //行号表的数量
    DWORD   Characteristics; //节的属性
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

//输入表结构，一个dll一个结构。
typedef	struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD Characteristics;
        DWORD OriginalFirstThunk;		//保存 输入表名结构体 的地址
    };
    DWORD TimeDataStamp;
    DWORD ForwarderChain;
    DWORD Name;							//库名称所在地址（RVA）
    DWORD FirstThunk;					//导入表所在地址（RVA)
} IMAGE_IMPORT_DESCRIPTOR,* PIMAGE_IMPORT_DESCRIPTOR;

//存有输入函数的序数与函数名，载入PE时，用其作为索引查找函数地址
typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD Hint;							//输入表的序号
    BYTE Name[1];						//函数的名字
}IMAGE_IMPORT_BY_NAME;


/*THUNK结构类型，可以装
载入内存后函数的地址
被输入的函数在dll中的序数值
指向IMAGE_IMPORT_BY_NAME的地址
*/
typedef union  _IMAGE_THUNK_DATA{
    DWORD ForwarderString;			//指向一个转向者字符串
    DWORD Function;					//被输入函数内存地址
    DWORD Ordinal;					//被输入的API序数值
    DWORD AddresOfData;				//指向IMAGE_BY_NAME
}IMAGE_THUNK_DATA,*PIMAGE_THUNK_DATA;



typedef struct _IMAGE_IMPORT_INFO {
    DWORD File_Offset;		//输入表结构的文件偏移地址，磁盘中
    DWORD Virtual_Offset;	//输入表结构的相对偏移地址，内存中,RVA
    DWORD RVA_2_RAW;		//偏移量
    int INDEX;				//表结构所在节区
    int NUM;			//输入表结构体个数
}IMAGE_IMPORT_INFO, * PIMAGE_IMPORT_INFO;


//定义的操作函数
void Get_DOS_HEADER(FILE* fp, PIMAGE_DOS_HEADER* );						//初始化DOS头数据
void Get_NT_HEADER(FILE* fp ,PIMAGE_DOS_HEADER, PIMAGE_NT_HEADER32*);	//初始化NT头数据
void Get_SECTION_HERADER(FILE* fp ,PIMAGE_DOS_HEADER,PIMAGE_NT_HEADER32, PIMAGE_SECTION_HEADER**);	//初始化节区头数据
void Get_IMPORT_INFO(FILE* fp, PIMAGE_NT_HEADER32, PIMAGE_SECTION_HEADER*, PIMAGE_IMPORT_INFO*);	//获取导入表信息
void Get_IMPORT_STRUCTURE(FILE* fp, PIMAGE_NT_HEADER32, PIMAGE_SECTION_HEADER*, PIMAGE_IMPORT_DESCRIPTOR**, PIMAGE_IMPORT_INFO);//初始化导入表结构体数组
void Get_THUNK_STRUCTURE(FILE* fp, PIMAGE_IMPORT_DESCRIPTOR* , PIMAGE_IMPORT_INFO , PIMAGE_THUNK_DATA** );//获取THUNK数组指针
bool IsPEFILE(IMAGE_NT_HEADER32* nt_header);							//判断是否是PE文件
void Print_SECTION(PIMAGE_NT_HEADER32 , PIMAGE_SECTION_HEADER* p_sec_eader);		//输出节区头数据
void Print_FUNCTION(FILE* fp, PIMAGE_IMPORT_DESCRIPTOR* , PIMAGE_IMPORT_INFO , PIMAGE_THUNK_DATA* );//输出函数各个
void Print_Optional_Header(PIMAGE_OPTIONAL_HEADER32 optional);
void Print_File_Header(PIMAGE_FILE_HEADER file);
void Print_DOS_Header(PIMAGE_DOS_HEADER dos);