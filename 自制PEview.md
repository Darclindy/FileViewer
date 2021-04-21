---
title: 自制PEView
date: 2020-7-23 11:04:44
tags: [classic]
categories: classic
---

# 自制PEView

## **摘要**

PE文件的全称是Portable Executable，是目前Windows上主流的可执行文件格式。从某种意义上讲，可执行的文件是操作系统本身执行机制的反应。在研究PE文件格式的过程中能够学到大量知识，有助于学习者深刻理解操作系统。掌握可执行文件的数据结构及运行机理，也是研究软件安全的必修课。

PE-Viewer工具可以方便地查看可执行文件的信息，当前流行的PE-Viewer有LordPE,Stud_PE,C32Asm等，都具有不错的功能。许多人在使用工具的同时却忽视了对知识本身的学习。亲手制作PE-Viewer可以学到更多知识，纠正理解上的错误。本次报告就实现PE-Viewer的过程，以及实践中碰到的一些问题以及相应处理方法进行说明。



## **1.文件读取**

二进制文件读写主要用到了fseek(),fread(),fgets()三个函数。fseek()用来调整文件指针指向的位置；fread()用来将文件中的数据块读入到变量中；fgets()用于读取文件中的字符串。读取整个头文件信息时，我们不需要对结构体变量一个一个复制，而是可以利用C语言结构体在内存中存储结构紧邻的特性，将一整块数据直接复制到结构体指针所指的区域中，这样减少指令的数目，提高效率。如下图所示：

![img](自制PEview/wps1.jpg) 

 

![img](自制PEview/wps2.jpg) 

 

## **2.初始化PE头**

《逆向工程核心原理》将PE文件的“头”分为DOS头，NT头，和节区头，其中NT头还包含文件头和可选头。他们都有其自己的结构。由于他们结构体都较大，并且后一个头的初始化会依赖于前几个头的数据，初始化函数需要传递很多参数，这时候传递指针的效率要远高于传递数值。下图是PE文件在磁盘与虚拟内存中的映射，PE头部分主要在下面三块。

![img](自制PEview/wps3.jpg) 

### **初始化DOS头**

DOS头占用了整个文件前0x3F个字节，是固定不变的，所以可以直接将其拷贝到DOS_HEADER结构体中。DOS时代的产物，和本次任务关联不大，所以不深入研究。

DOS头中需要关注的两个字段为：e_magic和e_lfanew，前者的值被设置为0x5A4D（对应ASCII值为’MZ’），可以用它作为判断PE文件的标志；后者字段是NT头的相对偏移，指出真正的PE头的偏移位置。

### **初始化NT头**

PE头部分的数据，它的物理地址偏移与虚拟地址偏移是相同的。所以可以直接通过前面求出的e_lfanew的值确定NT头的偏移位置，然后将其整块读取到结构体中。

![img](自制PEview/wps4.jpg) 

NT头结构体包含三部分，分别是标识，文件头，可选头。

标志的值为0x00004550（ASCII码“00PE”）。

```c
//文件头中以下字段比较重要：

​	WORD  Machine;             //CPU类型     

​	WORD  NumberOfSections;         //节区数量   

​	WORD  SizeOfOptionalHeader;       //指定可选头大小 

​	WORD  Characteristics;         //文件属性
```



 ```C
//可选头中以下几个字段比较重要：

​	WORD  Magic;							//机器型号,判断是 PE是 32位还是 64位;

​	DWORD  AddressOfEntryPoint;			//程序执行入口地址(RVA）

​	DWORD  BaseOfCode;						//代码段的地址（RVA）

​	DWORD  BaseOfData;						//数据段的起始偏移(RVA)

​	DWORD  ImageBase;						//程序的首选载入地址

​	DWORD  SectionAlignment;				//内存中的节对齐 一般是0x1000 

​	DWORD  FileAlignment;					//文件中的节对齐 一般是0x200

​	DWORD	NumberOfRvaAndSizes;			//用来指定 数组的个数

IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];//结构体数组，成员0是输出表，成员1是输入表。
 ```



### **初始化节区头**

节区头的数量可以从文件头的NumberOfSections成员得出。一个节区头对应一个节区，不同节区有不同的功能。最常见的如.data存放数据，.text存放指令。因为节区数一开始并不知道，所以不能直接定义节区头的大小，这里我定义了一个指针数组，确定节区数后先给数组中每个指针分配，在给每个指针所指的节区分配内存。

![img](自制PEview/wps5.jpg) 

后来我想到一种更简单的结构，因为节区头中一个个结构是紧连着的，所以我直接用一个结构体指针就行了。但因为代码已经成型，修改起来非常困难，加上用原来用的方法也不会很差，就保留了原来的实现方式。

节区头以下几项内容比较重要：

```c
BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];	//YES 节区的名字 8个字节

DWORD  VirtualSize;	//YES 节区在内存的大小，实际值是按内存对齐算

DWORD  VirtualAddress;//节区虚拟地址（RVA）

DWORD  SizeOfRawData; //在磁盘中所占空间

DWORD  PointerToRawData; //在磁盘中的偏移

DWORD  Characteristics; //节的属性
```



## **3.节区信息**

初始化节区头后，就可以将各个节区的数据输出了：

![img](自制PEview/wps6.jpg) 

根据各个节区的大小，RVA，RAW，以及可选头中的FileAlignment和SectionAlignment成员计算出任何一处虚拟地址对应的物理地址。

![img](自制PEview/wps7.jpg) 

 

## **4.初始化输入表**

程序运行时需要调用输入函数，而输入函数的代码并不在程序中，他们位于相关的DLL文件中。只有当PE文件载入内存后，Windows加载器才将相关DLL载入，并将调用输入函数的指令和函数实际所处的地址相联系起来。这些输入函数的信息（函数名，序号）都储存在输入表中。输入表结构如下：

 ```c
typedef	struct _IMAGE_IMPORT_DESCRIPTOR {//IID

​	union {

​		DWORD Characteristics;

​		DWORD OriginalFirstThunk;		//保存 输入表名结构体 的地址

​	};

​	DWORD TimeDataStamp;

​	DWORD ForwarderChain;

​	DWORD Name;							//库名称所在地址（RVA）

​	DWORD FirstThunk;					//导入表所在地址（RVA)

} IMAGE_IMPORT_DESCRIPTOR,* PIMAGE_IMPORT_DESCRIPTOR;
//（注释的三个成员比较重要）
 ```



### **函数载入**

![img](自制PEview/wps8.png) 

1. 读取IID“Name”成员，获取库名称字符串“USER32.dll”
2. 装载相应库->LoadLibrary(“USER32.dll”)
3. 读取IID的“OriginalFirstThunk”成员，获取INT地址
4. **逐一读取INT中数组的值，该值指向一个IMPORT_BY_NAME的结构体**
5. **5.利用该结构体的hint或Name项，获取对应函数的起始地址->GetProcAddress(GetCurrentThreadld)**
6. **读取FirstThunk的成员（IAT地址）**
7. **将得到的输入函数的起始地址填入相应的IAT数组中**

8. 重复步骤4~7，直到INT结束（遇到null时）

函数载入完成后，输入表的其它成员就不再重要了，之后调用输入函数只需通过IAT数组获取到其相应的地址即可。了解了输入表的工作原理，就可以获取载入函数的信息了。

### **IMPORT_INFO结构体**

编程过程中，我额外定义了一个结构体：

```c
typedef struct _IMAGE_IMPORT_INFO {

​	DWORD File_Offset;		//输入表结构的文件偏移地址，磁盘中

​	DWORD Virtual_Offset;	//输入表结构的相对偏移地址，内存中,RVA

​	DWORD RVA_2_RAW;		//虚拟偏移 减 物理偏移

​	int INDEX;				//表结构所在节区

​	int NUM;				//输入表结构体个数

}IMAGE_IMPORT_INFO, * PIMAGE_IMPORT_INFO;
```

这个结构体的作用是存放输入表的基本信息，比如偏移量，所在节区，输入表结构体的个数等信息。

其一是因为，在函数实现过程中，要频繁的使用这些值，特别是RVA_2_RAW，倘若每次都调用节区头结构体数组中的成员，如Psec_header[index]->PointerToRawData，Psec_header[index]->VirtualAddress会增加指令的复杂度，且不容易阅读。

其二是因为，输入表所在的节区，输入表结构体的个数等信息很重要，如果分开定义分开传递，会变得很零散，不如直接放在一个结构体中，每次只需将这个结构体的地址传入函数即可。

事实证明这种方法方便的确方便了我后面的编程。

### **获取THUNK数组**

为了更方便地读取信息，我打算先将各个THUNK数组的值提取出来，以指针数组为索引。具体过程是先通过输入表结构体中的OriginalFirstThunk成员减去RVA_2_RAW得到数组的文件偏移地址。这里碰到一个问题是不知道THUNK数组的大小，只知道它的结尾THUNK值为0。

![img](自制PEview/wps9.jpg) 

这里其实可以用链表，用fread扫描，扫到一个THUNK就将它串到链表中，直到扫到一个全零的THUNK值停止。但因为链表要另外定义链表结构体，且这里可能会有很多个链表，到时候得用指针数组作为索引，不是很方便。所以这里我还是用数组处理，方法是设置一个计数器和一个临时变量，将每次fread出来的内容存到临时变量中，令计数器自增一，直到fread到临时变量中的值为0。然后再根据最后计数器的值申请内存，将一整块的数据全部fread数组中（注意，最后面THUNK值为0的部分也要read进来，作为之后遍历时的终止条件）。

### **求输入函数**

完成了前面的工作，输入函数就很容易求了:

![img](自制PEview/wps10.jpg) 

先通过IID中的Name成员即可索引到表示DLL库名的字符串。

利用前面求出的THUNK数组可以索引到IMPORT_BY_NAME的结构体，前一个WORD是函数的序号，用fread读出；后面跟着一串字符串，用fgets读出。将它们打印出来效果如下：

![img](自制PEview/wps11.jpg) 

## **5.其他功能**

### **判断文件格式**

在读入了DOS头和NT头后，应该先判断以下该程序是否是PE文件，倘若不是，那么后续操作就没有意义了。判断方式是通过IMAGE_DOS_SIGNATURE是否为0x5A4D以及IMAGE_NT_SIGNATUR是否为0x4550来确定。

### **计算偏移量**

计算偏移量首先要判断输入的地址处在哪个节区中，找到该节区，再根据该节区的VirtualOffsite以及RawOffsite求出RVA_2_RAW，然后再用输入地址加/减该值即可。

### **其它**

​		跟网上的其它PE查看器相比，目前自己写的功能还比较简陋，PE文件的内容也远远不止文章所讲的那样。但在写的过程中对知识的印象更深刻了，尤其是IAT那一块，写完后对脱壳的技巧也有了更深的体会。之后可以不断地给这个小应用添加新的功能，比如图形界面，PE32+格式地读取，修复导入表等等功能。

 

**6.参考资料**

《加密与加密》

《逆向工程核心原理》

相关文章：https://blog.csdn.net/as14569852/article/details/78120335

变量类型：https://www.coder.work/article/1556102

文件读写：http://c.biancheng.net/c/110/