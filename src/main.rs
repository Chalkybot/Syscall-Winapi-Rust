#![allow(unused_mut, unused_assignments)]
use std::ops::Deref;
use std::os::raw::c_void;
use std::ptr::null_mut;
use core::arch::global_asm;
use windows::Win32::{
    Foundation::{HANDLE, NTSTATUS, CloseHandle},
    System::{
        ProcessStatus::EnumProcesses,
        Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS},

    },
};
// Types to make translating windows API types to rust.
type PVoid     = *mut c_void;      // C void*
type CCvoid    = *const c_void;   // C const void*
type PUsize    = *mut usize;      // C's PSIZE 

struct SafeHandle(HANDLE);

impl Deref for SafeHandle {
    type Target = HANDLE;
    fn deref (&self) -> &Self::Target { 
        &self.0
    }
}
impl Drop for SafeHandle {
    fn drop(&mut self) {
        unsafe { 
            match CloseHandle(self.0) { 
                Ok(_) => println!("[+] Closed handle."),
                Err(e) => eprintln!("[!] Error closing handle\n-> {}", e),
            }
        }
    }
}

trait WinUtils {
    fn as_mut_cvoid(&mut self) -> PVoid;
    fn as_const_cvoid(&self) -> CCvoid;
}
// Utilities for verbose casts.
impl<T> WinUtils for Vec<T> {
    fn as_mut_cvoid(&mut self) -> PVoid {
        self.as_mut_ptr() as PVoid
    }
    fn as_const_cvoid(&self) -> CCvoid { 
        self.as_ptr() as CCvoid
    }
}
// Syscalls.
global_asm!("
    read_process_memory:
        mov r10, rcx
        mov eax, 0x3F
        syscall
        ret
    write_process_memory:
        mov r10, rcx
        mov eax, 0x3A
        syscall
        ret
    nt_virt_alloc:
        mov r10, rcx
        mov eax, 0x18
        syscall
        ret
");

extern "C" {   
    fn read_process_memory(
        process_handle: HANDLE,             // Handle   
        base_address: CCvoid,               // Where to start reading
        buffer_ptr: CCvoid,                 // ptr to buffer to read to
        buffer_size: usize,                 // buffer size
        bytes_read: *mut usize              // returns read size.
    ) -> NTSTATUS;

    fn write_process_memory(    
        process_handle: HANDLE,             // Handle   
        base_address: CCvoid,               // Where to start writing
        buffer_ptr: CCvoid,                 // ptr to buffer to write from
        buffer_size:  usize,                // buffer size (write size)
        bytes_written: *mut usize           // returns size of write
    ) -> NTSTATUS;
    
    fn nt_virt_alloc(
        process_handle: HANDLE,             // Handle
        base_address: *mut PVoid,           // Where to allocate space (empty for OS chosen)
        zero_bits: usize,                   // ??
        region_size: PUsize,                // How big of a region to allocate.
        allocation_type: usize,             // Commit, reserve, etc.
        protection_flags: usize,            // Type, R / W / X
    ) -> NTSTATUS;
}

fn enumerate_processes() -> Result<Vec<u32>, windows::core::Error> {
    let mut pids = vec![0u32; 1024];
    let mut bytes_returned = 0u32;
    const SIZE_OF_U32: usize = std::mem::size_of::<u32>();
    unsafe {
        EnumProcesses(
            pids.as_mut_ptr(),
            (pids.len() * SIZE_OF_U32) as u32,
            &mut bytes_returned,
        )?;
    }
    // Let's empty out the pids.
    pids.resize(bytes_returned as usize / SIZE_OF_U32, 0);
    Ok(pids)
}

fn get_handle(pid: u32) -> Result<SafeHandle, windows::core::Error> {
    let desired_access = PROCESS_ACCESS_RIGHTS(0xFFFF); //0x0010 | 0x0020 | 0x0008 | 0x0400 <- Correct flags, at the moment, we are using debug flags.
    let mut handle = HANDLE::default();
    unsafe {
        handle = OpenProcess(
            desired_access,
            false,
            pid
        )?;
    }
    Ok(SafeHandle(handle))
}

fn nt_write_process_memory(handle: HANDLE, address: usize, amount_to_read: usize, mut data: Vec<u8>) -> Result<(), NTSTATUS> { 
    let base_address:       CCvoid = address as CCvoid;
    let buffer_ptr:         CCvoid = data.as_mut_ptr() as *mut c_void;
    let mut bytes_written:  usize = 0; 
    let mut written_ptr:    PUsize = &mut bytes_written as PUsize;
    println!("[-] Running WPM.");
    unsafe { 
        let status = write_process_memory(
            handle, 
            base_address, 
            buffer_ptr, 
            1, 
            written_ptr
        ); 
        if status.is_ok() { 
            println!("[+] WPM Succeeded.\n-> Wrote {}", bytes_written);
            return Ok(());
        }
        eprintln!("[!] WPM Failed!\n-> NTSTATUS: {:#x}", status.0);
        return Err(status);
    }
}

fn nt_read_process_memory(handle: HANDLE, address: usize, amount_to_read: usize) -> Result<Vec<u8>, NTSTATUS> { 
    let base_address:   CCvoid = address as CCvoid;
    let mut buffer:     Vec<u8>= vec![0u8; amount_to_read]; 
    let buffer_ptr:     CCvoid = buffer.as_mut_ptr() as PVoid;
    let mut bytes_read: usize  = 0;
    let mut read_ptr:   PUsize = &mut bytes_read as PUsize;
    println!("[-] Running RPM.");
    unsafe { 
        let status = read_process_memory(
            handle, 
            base_address, 
            buffer_ptr, 
            amount_to_read, 
            read_ptr
        );
        if status.is_ok() { 
            println!("[+] RPM Succeeded.\n-> Read {}", bytes_read);
            return Ok(buffer);
        }
        eprintln!("[!] RPM Failed!\n-> NTSTATUS: {:#x}", status.0);
        return Err(status);
    }
}

fn nt_virtual_alloc(handle: HANDLE, address: Option<usize>, protection_flags: Option<usize>) -> Result<PVoid, NTSTATUS> {
    let mut base_address:   PVoid = match address { 
        Some(number)    => number as PVoid,
        None            => null_mut(),
    };
    let zero_bits:          usize = 0;
    let mut region_size:    usize = 4096;
    let allocation_type:    usize = 0x00001000; 
    let protection_flags:   usize = match protection_flags{ 
        Some(flags) => flags,    
        None        => 0x00000004, // PAGE_READWRITE
    };
    println!("[-] Running VirtualAlloc.");
    unsafe { 
        // Let's try ZwAllocateVirtualMemory
        let status = nt_virt_alloc(
            handle,
            &mut base_address,
            zero_bits,
            &mut region_size,
            allocation_type,
            protection_flags,
        );
        if status.is_ok() { 
            println!("[+] VirtualAlloc Succeeded.\n-> {:#x} - {:#x}",  base_address as usize, base_address as usize + region_size);
            return Ok(base_address);
        }
        eprintln!("[!] VirtualAlloc Failed!\n-> NTSTATUS: {:#x}", status.0);
        return Err(status);

    }
}


fn main() {
    let current_process_pid = enumerate_processes().unwrap();
    let current_process_handle = get_handle(*current_process_pid.last().unwrap()).unwrap();
    let variable_to_read = 100u8;
    let variable_location = &variable_to_read as *const _ as *const c_void;
    let buff = nt_read_process_memory(*current_process_handle, variable_location as usize, 1);
    nt_write_process_memory(*current_process_handle, variable_location as usize, 1, vec![64u8]);
    let buff = nt_read_process_memory(*current_process_handle, variable_location as usize, 1);
    let addr_space = nt_virtual_alloc(*current_process_handle, None, None).unwrap();
    nt_virtual_alloc(*current_process_handle, Some(addr_space as usize), Some(0x20));
}
