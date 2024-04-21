#![allow(unused_mut, unused_assignments)]
use std::ops::Deref;
use std::os::raw::c_void;
use std::ptr::null_mut;
use core::arch::global_asm;
use windows::{Wdk::Foundation::OBJECT_ATTRIBUTES, Win32::{
        Foundation::{CloseHandle, HANDLE, HWND, NTSTATUS},
        System::{
            ProcessStatus::EnumProcesses,
            Threading::PROCESS_ACCESS_RIGHTS,
            WindowsProgramming::CLIENT_ID,
        },
    }
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

// Syscalls.
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
");

extern "C" {   
    fn zw_read_virtual_memory(
        process_handle: HANDLE,             // [in] Handle   
        base_address: CCvoid,               // [in] Where to start reading
        buffer_ptr: CCvoid,                 // [out] ptr to buffer to read to
        buffer_size: usize,                 // [in] buffer size
        bytes_read: *mut usize              // [out] returns read size.
    ) -> NTSTATUS;

    fn nt_write_virtual_memory(    
        process_handle: HANDLE,             // [in] Handle   
        base_address: CCvoid,               // [in] Where to start writing
        buffer_ptr: CCvoid,                 // [in] ptr to buffer to write from
        buffer_size:  usize,                // [in] buffer size (write size)
        bytes_written: *mut usize           // [out] returns size of write
    ) -> NTSTATUS;
    
    fn zw_allocate_virtual_memory(
        process_handle: HANDLE,             // [in] Handle
        base_address: *mut PVoid,           // [in, out] Where to allocate space (empty for OS chosen)
        zero_bits: usize,                   // [in] ??
        region_size: PUsize,                // [in, out] How big of a region to allocate.
        allocation_type: usize,             // [in] Commit, reserve, etc.
        protection_flags: usize,            // [in] Type, R / W / X
    ) -> NTSTATUS;

    fn nt_open_process(
        process_handle_ptr: *mut HANDLE,    // [out] Pointer to a handle struct
        access_mask: PROCESS_ACCESS_RIGHTS, // [in] Access mask, ex: PROCESS_ALL_ACCESS 
        oa_ptr: OBJECT_ATTRIBUTES,          // [in] Object attributes pointer
        client_id_ptr: CLIENT_ID,           // [in] ClientId
    ) -> NTSTATUS;

}

fn enumerate_processes() -> Result<Vec<usize>, windows::core::Error> {
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
    let pids_usize = pids.iter().map(|x| *x as usize).collect();
    Ok(pids_usize)
}


fn nt_write_process_memory(handle: HANDLE, address: usize, mut data: Vec<u8>) -> Result<(), NTSTATUS> { 
    let base_address:       CCvoid = address as CCvoid;
    let buffer_ptr:         CCvoid = data.as_mut_ptr() as *mut c_void;
    let mut bytes_written:  usize = 0; 
    let mut written_ptr:    PUsize = &mut bytes_written as PUsize;
    println!("[-] Running WPM.");
    unsafe { 
        let status = nt_write_virtual_memory(
            handle, 
            base_address, 
            buffer_ptr, 
            data.len(), 
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
        let status = zw_read_virtual_memory(
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
        let status = zw_allocate_virtual_memory(
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

fn nt_get_handle(pid: usize) -> Result<SafeHandle, NTSTATUS> {
    let mut handle = HANDLE::default();
    let mut handle_ptr = &mut handle as *mut HANDLE;
    let desired_access = PROCESS_ACCESS_RIGHTS(0xFFFF); //0x0010 | 0x0020 | 0x0008 | 0x0400 <- Correct flags, at the moment, we are using debug flags.
    let oa = OBJECT_ATTRIBUTES::default();
    let client_id: CLIENT_ID = CLIENT_ID{
        UniqueProcess: HANDLE::from(HWND(pid as isize)),
        UniqueThread: HANDLE::default()
    };

    unsafe { 
        let status = nt_open_process(
            handle_ptr,
            desired_access,
            oa,
            client_id,
        );
        if status.is_ok() { 
            println!("[+] OpenProcess Succeeded.\n-> Returned handle <{:?}>", handle.0);
            return Ok(SafeHandle(handle));
        }
        eprintln!("[!] OpenProcess Failed!\n-> NTSTATUS: {:#x}", status.0);
        return Err(status);
    }

}

fn main() {
    
    let current_process_pid = enumerate_processes().unwrap();
    let current_process_handle = nt_get_handle(*current_process_pid.last().unwrap()).unwrap();



    let variable_to_read = 100u8;
    let variable_location = &variable_to_read as *const _ as *const c_void;
    let buff = nt_read_process_memory(*current_process_handle, variable_location as usize, 1);
    nt_write_process_memory(*current_process_handle, variable_location as usize, vec![64u8]);
    let buff = nt_read_process_memory(*current_process_handle, variable_location as usize, 1);

    
    let addr_space = nt_virtual_alloc(*current_process_handle, None, None).unwrap();
    nt_virtual_alloc(*current_process_handle, Some(addr_space as usize), Some(0x20)); 
    
}
