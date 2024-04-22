use core::arch::global_asm;
use std::os::raw::c_void;

use windows::{Wdk::Foundation::OBJECT_ATTRIBUTES, 
    Win32::{
        Foundation::{HANDLE, NTSTATUS},
        System::{
            Threading::{PROCESS_ACCESS_RIGHTS, 
                THREAD_ACCESS_RIGHTS}, 
                WindowsProgramming::CLIENT_ID
        },
    }
};


// Types to make translating C -> rust less verbose.
pub type PVoid     = *mut c_void;       // C void*
pub type CCvoid    = *const c_void;     // C const void*
pub type PUsize    = *mut usize;        // C's PSIZE 


// Syscalls.
// These need to be ported to being dynamically loaded, 
// as the SNN's can change based on versions.
global_asm!("
    zw_read_virtual_memory:
        mov r10, rcx
        mov eax, 0x3F
        syscall
        ret
    nt_write_virtual_memory:
        mov r10, rcx
        mov eax, 0x3A
        syscall
        ret
    zw_allocate_virtual_memory:
        mov r10, rcx
        mov eax, 0x18
        syscall
        ret
    nt_open_process:
        mov r10, rcx
        mov eax, 0x26
        syscall
        ret
    nt_create_thread_ex:
        mov r10, rcx
        mov eax, 0x0C2
        syscall
        ret
    zw_protect_virtual_memory:
        mov r10, rcx
        mov eax, 0x50
        syscall
        ret
");

extern "C" {   
    pub fn zw_read_virtual_memory(
        process_handle: HANDLE,             // [in] Handle                              [HANDLE] 
        base_address: CCvoid,               // [in, opt] Where to start reading         [PVOID]
        buffer_ptr: CCvoid,                 // [out] ptr to buffer to read to           [PVOID]
        buffer_size: usize,                 // [in] buffer size                         [SIZE_T]
        bytes_read: *mut usize              // [out, opt] returns read size.            [PSIZE_T]
    ) -> NTSTATUS;

    pub fn nt_write_virtual_memory(    
        process_handle: HANDLE,             // [in] Handle                              [HANDLE] 
        base_address: CCvoid,               // [in, opt] Where to start writing         [PVOID] 
        buffer_ptr: CCvoid,                 // [in] pointer to buffer to write from     [PVOID] 
        buffer_size:  usize,                // [in] buffer size (write size)            [SIZE_T] 
        bytes_written: *mut usize           // [out, opt] returns size of write         [PSIZE_T] 
    ) -> NTSTATUS;
    
    pub fn zw_allocate_virtual_memory(
        process_handle: HANDLE,             // [in] Handle                              [HANDLE]
        base_address: *mut PVoid,           // [in, out] Where to allocate space        [*PVOID]
        zero_bits: usize,                   // [in] Allocation mask requirements        [ULONG]
        region_size: PUsize,                // [in, out] Region's size                  [PULONG]
        allocation_type: usize,             // [in] Commit, reserve, etc.               [ULONG]
        protection_flags: usize,            // [in] Type, R / W / X                     [ULONG]
    ) -> NTSTATUS;

    pub fn nt_open_process(
        process_handle_ptr: *mut HANDLE,    // [out] Handle will be returned here       [PHANDLE]
        access_mask: PROCESS_ACCESS_RIGHTS, // [in] Access mask, ex: PROCESS_ALL_ACCESS [ACCESS_MASK]
        oa_ptr: OBJECT_ATTRIBUTES,          // [in] Object attributes pointer           [POBJECT_ATTRIBUTES]
        client_id_ptr: CLIENT_ID,           // [in] ClientId struct PID goes in here    [PCLIENT_ID]
    ) -> NTSTATUS;

    pub fn nt_create_thread_ex(
        handle_ptr: *mut HANDLE,            // [out] Handle to thread will be returned  [PHANDLE]
        acces_mask: THREAD_ACCESS_RIGHTS,   // [in] Access mask, ex:THREAD_ALL_ACCESS   [ACCESS_MASK]
        obj_attributes: CCvoid,             // [in, opt] Object attributes              [OBJECT_ATTRIBUTES]
        process_handle: HANDLE,             // [in] Handle for process                  [HANDLE]
        start_routine: CCvoid,              // [in] Thread start address                [PUSER_THREAD_START_ROUTINE]
        arguments: CCvoid,                  // [in, opt] Passed arguments,              [PVOID]
        create_flags: u32,                  // [in, opt] Creation flags, 0x0            [ULONG]
        zerobits: usize,                    // [in] Mask, 0x0 for default.              [SIZE_T]
        stack_size: usize,                  // [in] Stack size, 0x0 for default,        [SIZE_T]
        stack_max: usize,                   // [in] Stack's max size, 0x0 for default   [SIZE_T]
        attribute_list: CCvoid,             // [in, opt] attribute list                 [PPS_ATTRIBUTE_LIST]
    ) -> NTSTATUS;
    
    pub fn zw_protect_virtual_memory(
        process_handle: HANDLE,             // [in] Handle to process.                  [HANDLE]
        base_address: *mut PVoid,           // [in, out] Pointer to start address.      [*PVOID]
        region_size:  PUsize,               // [in, out] Size of alter region           [PSIZE_T]
        proc_flag: usize,                   // [in] New protection flags.               [ULONG]
        flag_old: *mut usize                // [out] Returns old protection flags       [PULONG]
    ) -> NTSTATUS;
}
