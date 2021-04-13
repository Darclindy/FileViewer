//
// Created by dell on 2021/4/13.
//

#include"PE.h"
#include<stdio.h>

//获取dos头数据
void Get_DOS_HEADER(FILE *fp,PIMAGE_DOS_HEADER* dos_header) {
    if (!(*dos_header = (PIMAGE_DOS_HEADER)malloc(SIZE_OF_DOS_HEADER))) exit(1);
    //整块赋值
    fread(*dos_header, SIZE_OF_DOS_HEADER, 1, fp);
}

//获取nt头数据
void Get_NT_HEADER(FILE* fp,PIMAGE_DOS_HEADER Pdos_header, PIMAGE_NT_HEADER32 *Pnt_header) {
    if (!(*Pnt_header = (PIMAGE_NT_HEADER32)malloc(SIZE_OF_NT_HEADER))) exit(1);
    fseek(fp, Pdos_header->e_lfanew, 0);
    fread(*Pnt_header, SIZE_OF_NT_HEADER, 1, fp);
}

//获取节区头数据
void Get_SECTION_HERADER(FILE* fp,PIMAGE_DOS_HEADER Pdos_header,PIMAGE_NT_HEADER32 Pnt_header, PIMAGE_SECTION_HEADER** Psec_header) {

    int num = Pnt_header->FileHeader.NumberOfSections, i = 0;
    fseek(fp, Pdos_header->e_lfanew + SIZE_OF_NT_HEADER, 0);
    if (!(*Psec_header = (PIMAGE_SECTION_HEADER*)malloc(SIZE_OF_POINT * num))) exit(1);			//按节区头个数，给指针数组分配空间
    for (i = 0; i < num; i++) {
        if (!((*Psec_header)[i] = (PIMAGE_SECTION_HEADER)malloc(SIZE_OF_SECTION_HEADER))) exit(1);//给每一个指针指向的结构体申请空间
        fread((*Psec_header)[i], SIZE_OF_SECTION_HEADER, 1, fp);
    }
}

//获取用输入表结构体中其它成员的信息，方便以后计算
void Get_IMPORT_INFO(FILE* fp, PIMAGE_NT_HEADER32 Pnt_header, PIMAGE_SECTION_HEADER* Psec_header, PIMAGE_IMPORT_INFO* Pimport_info) {
    DWORD File_Offset;		//输入表结构的文件偏移地址，磁盘中
    DWORD Virtual_Offset;	//输入表结构的相对偏移地址，内存中,RVA
    DWORD RVA_2_RAW;		//偏移量
    int index;				//表结构所在节区
    int num = 0;				//节区数

    //计算输入表结构在磁盘中的地址
    Virtual_Offset = Pnt_header->OptionalHeader.DataDirectory[1].VirtualAddress;
    //通过每个节区的内存偏移，计算输入表结构在哪个节区中
    for (index = 0; index < Pnt_header->FileHeader.NumberOfSections; index++) {
        if (Virtual_Offset >= Psec_header[index]->VirtualAddress) continue;
        else break;
    }
    index = index - 1;
    File_Offset = Psec_header[index]->PointerToRawData;
    Virtual_Offset = Psec_header[index]->VirtualAddress;
    RVA_2_RAW = Virtual_Offset - File_Offset;
    fseek(fp, File_Offset, 0);
    PIMAGE_IMPORT_DESCRIPTOR test = (PIMAGE_IMPORT_DESCRIPTOR)malloc(SIZE_OF_IMPORT_DESTRUCTUER);
    if (!test) exit(1);

    do {
        fread(test, SIZE_OF_IMPORT_DESTRUCTUER, 1, fp);
        num += 1;
    } while (test->Characteristics || test->ForwarderChain || test->Name || test->OriginalFirstThunk || test->TimeDataStamp);
    num = num - 1;
    free(test);

    //将求得的信息赋给输入表信息表
    *Pimport_info = (PIMAGE_IMPORT_INFO)malloc(sizeof(IMAGE_IMPORT_INFO));
    (*Pimport_info)->Virtual_Offset = Virtual_Offset;	//计算输入表结构在磁盘中的地址
    (*Pimport_info)->File_Offset = File_Offset;
    (*Pimport_info)->RVA_2_RAW = RVA_2_RAW;
    (*Pimport_info)->NUM = num;
    (*Pimport_info)->INDEX = index;

}

//获取输入表结构
void Get_IMPORT_STRUCTURE(FILE* fp, PIMAGE_NT_HEADER32 Pnt_header,PIMAGE_SECTION_HEADER* Psec_header, PIMAGE_IMPORT_DESCRIPTOR** p_in_table,PIMAGE_IMPORT_INFO info) {

    fseek(fp, info->File_Offset, 0);
    *p_in_table = (PIMAGE_IMPORT_DESCRIPTOR*)malloc(sizeof(PIMAGE_IMPORT_DESCRIPTOR) * info->NUM);//给指针数组分配内存
    if (!(*p_in_table)) exit(1);
    for (int i = 0; i < info->NUM; i++) {
        (*p_in_table)[i] = (PIMAGE_IMPORT_DESCRIPTOR)malloc(SIZE_OF_IMPORT_DESTRUCTUER);
        fread((*p_in_table)[i], SIZE_OF_IMPORT_DESTRUCTUER, 1, fp);
    }

}

//获取THUNK数组
void Get_THUNK_STRUCTURE(FILE* fp, PIMAGE_IMPORT_DESCRIPTOR* table, PIMAGE_IMPORT_INFO info,PIMAGE_THUNK_DATA** p_thunk) {
    (*p_thunk) = (PIMAGE_THUNK_DATA*)malloc(SIZE_OF_POINT * info->NUM);
    IMAGE_THUNK_DATA temp;
    int cnt;
    for (int i = 0; i < info->NUM; i++) {
        fseek(fp, table[i]->OriginalFirstThunk - info->RVA_2_RAW, 0);
        cnt = 0;
        do {
            fread(&temp, SIZE_OF_THUNK_DATA, 1, fp);
            cnt += 1;
        } while (temp.Function);
        (*p_thunk)[i] = (PIMAGE_THUNK_DATA)malloc(SIZE_OF_THUNK_DATA * cnt);
        fseek(fp, table[i]->OriginalFirstThunk - info->RVA_2_RAW, 0);
        fread((*p_thunk)[i], SIZE_OF_THUNK_DATA * cnt, 1, fp);

    }
}