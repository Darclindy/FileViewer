#include "PE.h"
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

int main(int argc,char *argv[])
{
	//char f1[100];
	setbuf(stdout,0);
	setbuf(stdin,0);
	setbuf(stderr,0);

	char fileName[200];
	FILE* fp;
	PIMAGE_DOS_HEADER P_DOS_HEADER;		//DOS头指针
	PIMAGE_NT_HEADER32 P_NT_HEADER;		//NT头头指针
	PIMAGE_SECTION_HEADER *P_SEC_HEADER;	//节区头的指针数组
	PIMAGE_IMPORT_DESCRIPTOR* P_IN_TABLE;	//导入表
	PIMAGE_IMPORT_INFO P_IN_INFO;			//导入表的参数
	PIMAGE_THUNK_DATA* P_THUNK_TABLE;		//THUNK数组表

    strcpy(fileName,argv[1]);   //FilePath

	int len = strlen(fileName);
	fileName[len] = '\0';
	printf("%s\n", fileName);

	if (!(fp = fopen(fileName, "rb"))) exit(1);
	Get_DOS_HEADER(fp, &P_DOS_HEADER);
	Get_NT_HEADER(fp, P_DOS_HEADER, &P_NT_HEADER);
	if ((IsPEFILE(P_NT_HEADER))){
	    printf("%s\n","This is a PE file");
    } else{
        printf("This is not a PE file\n");
        exit(-1);
	}

	Get_SECTION_HERADER(fp, P_DOS_HEADER, P_NT_HEADER, &P_SEC_HEADER);
	Get_IMPORT_INFO(fp, P_NT_HEADER, P_SEC_HEADER, &P_IN_INFO);
	Get_IMPORT_STRUCTURE(fp, P_NT_HEADER, P_SEC_HEADER,&P_IN_TABLE,P_IN_INFO);
	Get_THUNK_STRUCTURE(fp, P_IN_TABLE, P_IN_INFO, &P_THUNK_TABLE);

	Print_DOS_Header(P_DOS_HEADER);
	Print_File_Header(&(P_NT_HEADER->FileHeader));
	Print_Optional_Header(&(P_NT_HEADER->OptionalHeader));
	Print_SECTION(P_NT_HEADER, P_SEC_HEADER);
	Print_FUNCTION(fp, P_IN_TABLE, P_IN_INFO, P_THUNK_TABLE);
	fclose(fp);
	system("pause");
	return 0;
}