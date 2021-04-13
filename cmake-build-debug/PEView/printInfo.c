//
// Created by dell on 2021/4/13.
//

#include<stdio.h>
#include <stdbool.h>
#include"PE.h"



//判断是否为PE文件
bool IsPEFILE(IMAGE_NT_HEADER32* nt_header) {
    if (nt_header->Signature != IMAGE_NT_SIGNATURE) {
        printf_s("该文件不是PE文件!\n");
        return false;
    }
    return true;
}

void Print_SECTION(PIMAGE_NT_HEADER32 p_nt_header, PIMAGE_SECTION_HEADER* p_sec_header) {
    int i, num = p_nt_header->FileHeader.NumberOfSections;
    printf_s("*************************Sections************************\n");
    printf_s("order\tname\tVirtualSize\tVirtualOffsite\tRawSize\t\tRawOffsite\tCharacteristics\n");
    for (i = 0; i < num; i++) {
        printf_s("%d：\t%.8s\t%.8x\t%.8x\t%.8x\t%.8x\t%.8x\n", i, p_sec_header[i]->Name, p_sec_header[i]->Misc.VirtualSize, p_sec_header[i]->VirtualAddress, p_sec_header[i]->SizeOfRawData, p_sec_header[i]->PointerToRawData, p_sec_header[i]->Characteristics);
    }
    printf_s("*************************Sections************************\n");
}



void Print_FUNCTION(FILE* fp, PIMAGE_IMPORT_DESCRIPTOR* p_import_table, PIMAGE_IMPORT_INFO info,PIMAGE_THUNK_DATA* p_thunk_table) {
    char dllName[20], funcName[35];
    WORD hint, num = info->NUM;
    DWORD R2W = info->RVA_2_RAW;
    printf_s("*************************Functions************************\n");
    for (int i = 0; i < num; i++) {
        //输出DLL名
        fseek(fp, p_import_table[i]->Name - R2W, 0);
        fgets(dllName, 20, fp);
        printf_s("%s:\n", dllName);
        //输出函数名
        for (int j = 0; p_thunk_table[i][j].Function; j++) {
            fseek(fp, p_thunk_table[i][j].Function - R2W, 0);
            fread(&hint, 0x2, 1, fp);
            fgets(funcName, 35, fp);
            printf_s("\t%.4x\t%s\n", hint, funcName);
        }

    }
    printf_s("*************************Functions************************\n\n");
}

void Print_DOS_Header(PIMAGE_DOS_HEADER dos) {
    printf_s("*************************DOS************************\n");
    printf_s("e_magic = % x\n",dos->e_magic );
    printf_s("e_lfanew = % x\n",dos->e_lfanew );
    printf_s("*************************DOS************************\n\n");
}

void  Print_File_Header(PIMAGE_FILE_HEADER file) {
    printf_s("*************************FILE************************\n");
    printf_s("Machine:%x\n",file->Machine);
    printf_s("NumberOfSections:%x\n",file->NumberOfSections);
    printf_s("SizeOfOptionalHeader:%x\n",file->SizeOfOptionalHeader);
    printf_s("Characteristics:%x\n",file->Characteristics);
    printf_s("*************************FILE************************\n\n");
}

void Print_Optional_Header(PIMAGE_OPTIONAL_HEADER32 optional) {
    printf_s("*************************OPTIONAL************************\n");
    printf_s("Magic = %x\n",optional->Magic);
    printf_s("AddressOfEntryPoint = %x\n",optional->AddressOfEntryPoint);
    printf_s("BaseOfCode = %x\n",optional->BaseOfCode);
    printf_s("BaseOfData = %x\n",optional->BaseOfData);
    printf_s("ImageBase = %x\n",optional->ImageBase);
    printf_s("SectionAlignment = %x\n",optional->SectionAlignment);
    printf_s("FileAlignment = %x\n",optional->FileAlignment);
    printf_s("SizeOfImage = %x\n",optional->SizeOfImage);
    printf_s("SizeOfHeaders = %x\n",optional->SizeOfHeaders);
    printf_s("NumberOfRvaAndSizes = % x\n",optional->NumberOfRvaAndSizes);
    printf_s("Import = %x\n", optional->DataDirectory[1]);
    printf_s("*************************OPTIONAL************************\n\n");
}