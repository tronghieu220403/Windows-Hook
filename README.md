# Hooking in Windows usermode
 
Welcome to the "Hooking in Windows usermode" repository! This is an open-source project that aims to provide a modification data of a running usermode process to change it's execution flow.

- [Introdution](#introduction)
- [Techniques](#techniques)
- [Folder structure](#folder-structure)
- [References](#references)
- [Requirements](#requirements)
- [Coding style](#coding-style)

Introduction
----------------

A process, in the simplest terms, is an executing program. Each process provides the resources needed to execute a program. A process has a virtual address space, executable code, open handles to system objects, a security context, a unique process identifier, environment variables, a priority class, minimum and maximum working set sizes, and at least one thread of execution.

A "hook", in a generic sense, is something that will let you, a programmer, view and/or interact with and/or change something that's already going on in a system/program.

This repository will demonstrate two of these hooking techniques:

### IAT (Import address table) hooking

The Import Address Table is a part of Portable Executable (PE) format which **records the addresses of functions imported from other DLLs**. Therefore the `Import Address Table` is a table filled with `function pointers`. This makes it an attractive target for attackers looking to achieve remote code injection, since they can **overwrite** the entry in the Import Address Table (using a write-what-where vulnerability) and redirect a function call to a location of their choosing.

The IAT hooking in Windows usermode **hook the IAT of other processes**, thereby make them launch your injection code. 

### Inline hooking

The inline hooking will **change some bytes in the code section of a running process** to change it flow, launch your injection code with out corrupt the process.

Techniques
----------------

### Get base address of other process

Follow the instruction of [Adam Rosenfield](https://stackoverflow.com/users/9530/adam-rosenfield) on [`Stack Overflow - Get base address of process`](https://stackoverflow.com/questions/14467229/get-base-address-of-process):

> 1. Open the process using [`OpenProcess`](https://learn.microsoft.com/vi-vn/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) -- if successful, the value returned is a handle to the process, which is just an opaque token used by the kernel to identify a kernel object.
> 2. Call [`GetProcessImageFileName`](https://learn.microsoft.com/vi-vn/windows/win32/api/psapi/nf-psapi-getprocessimagefilenamea) to get the name of the main executable module of the process.
> 3. Use [`EnumProcessModules`](https://learn.microsoft.com/vi-vn/windows/win32/api/psapi/nf-psapi-enumprocessmodules) to enumerate the list of all modules in the target process.
> 4. For each module, call [`GetModuleFileNameEx`](https://learn.microsoft.com/vi-vn/windows/win32/api/psapi/nf-psapi-getmodulefilenameexa) to get the filename, and compare it with the executable's filename.
> 5. When you've found the executable's module, call [`GetModuleInformation`](https://learn.microsoft.com/vi-vn/windows/win32/api/psapi/nf-psapi-getmoduleinformation) to get the raw entry point of the executable.

### Create a hooking function

I created a simple hooking function for [`CloseHandle`](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle) that will print to console the value of the handle parameter passed to the function. After doing some stubs, I will made a call back to the orginal `CloseHandle` to make sure the process is not deviated from its flow.

However, there is a problem that we **must not have** any `call` instruction in our hooking function because the call will not true when we move it to the target process. So we will need the below technique to get pointers of needed functions.

### Get Function Addresses of "kernel32.dll"

There are speacial registers in Windows Assembly (MASM), they are `FS` and `GS` register. Both of them point to the current value of the [Thread Information Block (TIB)](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb) structure. In x86 mode `FS:[0]` points to the start of the TIB, in X64 it's `GS:[0]`. The TIB structure contains a pointer to [Process Environment Block (PEB)](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb). In PEB, there is an pointer to [PPEB_LDR_DATA structure](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data), which contains information about the loaded modules for the process. 

In **PPEB_LDR_DATA** structure, there is a field named **InMemoryOrderModuleList** - the head of a doubly-linked list that contains the loaded modules for the process. Each item in the list is a pointer to an **LDR_DATA_TABLE_ENTRY** structure. We will query this doubly-linked list to find the **kernel32.dll** base address then get all the needed functions through it's Export Address Table.

### Manipulate data of other process with the same privilege

We can't just manipulate with other process' data by using direct pointer. We must create a handle using `OpenProcess` function to have access to interact with that process' data. Here are the functions we will need:

* [ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)
* [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
* [VirtualQueryEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex)
* [VirtualProtectEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex)
* [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
* [VirtualFreeEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfreeex)

### Get virtual address on IAT of the hooked function in the target process

Due to the IAT structure, we can easily get the relative VA (RVA) on IAT of the hooked function in the target process. Add that number with the process' base address then we will have the VA of our hooked function in IAT.

### Hooking

#### IAT hooking

We need to allocate a heap with `PAGE_EXECUTE_READWRITE` protection attributes, copy the bytes code of hooking function and the modify the value of the hooked function in the IAT to point to our injection code.

#### Inline hooking

* Hooking function: Allocate a heap with `PAGE_EXECUTE_READWRITE` protection attributes, we will remove the `ret` instruction in the hooking function and append all replaced lines of hooked function into the end of the hooking function. Next, we will append a the jmp instruction to **jump back to right after the last replaced lines in hooked function** to conserve the execution of the original hooked function. Finally, copy the completed bytes code of hooking function into the allocated heap above.

* Hooked function: modify instruction of the code by **replace some first line of the hooked function** by your `jmp` instruction to the hooking function.

More detail in here: [Manually Implementing Inline Function Hooking](https://blog.securehat.co.uk/process-injection/manually-implementing-inline-function-hooking)

Folder structure
----------------
```
.                           
│   │
├── main.cpp
│   │
├── inlucde
│   └── hook
│   │   └── iathook
│   │   │   └── iathook.h
│   │   │   └── iathookclosehandle.h			# IAT hook CloseHandle function in KERNEL32.dll
│   │   └── inlinehook
│   │   │   └── inlinehook.h
│   │   │   └── inlineclosehandle.h			# Inline hook CloseHandle function in KERNEL32.dll
│   └── hook.h
│   └── pestructure                                        
│   │   └── idata					# Provide information about Import Table Address
│   │   │   └── importdirectorytable.h
│   │   │   └── importdirectoryentry.h
│   │   │   └── importlookuptable.h
│   │   │   └── importlookupentry.h
│   │   │   └── hintnameentry.h
│   │   └── pememory					# Portable Execution on physical memory
│   │   │   └── pememory.h
│   └── process
│   │   └── process.h
│   │   └── processinfo.h
│   │   └── processmemory.h				# Manage process memory
│   └── teb
│   │   └── function.h
│   │   └── getfunction.h
│   │   └── teb.h
│   └── ulti
│   │   └── everything.h
│   │
├── target                                              # We need some where to attack
│   └── target.exe
│   └── target.cpp
│   │
────────────	
```

References
----------------

[MSDN - PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)

[MSDN - Processes and Threads](https://learn.microsoft.com/en-us/windows/win32/procthread/processes-and-threads)

[Stack Overflow - Get base address of process](https://stackoverflow.com/questions/14467229/get-base-address-of-process)

[Manually Implementing Inline Function Hooking](https://blog.securehat.co.uk/process-injection/manually-implementing-inline-function-hooking)

Requirements
---
* C++ 20
* Supported Operating Systems
  * Windows

Coding style
------------
[Google C++ Style](https://google.github.io/styleguide/cppguide.html)
