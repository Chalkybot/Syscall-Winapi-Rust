#![allow(unused_mut, unused_assignments, dead_code)]

use std::{ops::Deref, os::raw::c_void};
use core::arch::global_asm;
use std::ptr::null_mut;
use windows::{Wdk::Foundation::OBJECT_ATTRIBUTES, 
    Win32::{
        Foundation::{CloseHandle, HANDLE, HWND, NTSTATUS},
        System::{
            ProcessStatus::EnumProcesses, 
            Threading::{PROCESS_ACCESS_RIGHTS, THREAD_ALL_ACCESS, 
                THREAD_ACCESS_RIGHTS}, 
                WindowsProgramming::CLIENT_ID
        },
    }
};

// --- Windows process struct ---
pub struct WindowsProcess {
    pub pid: usize,
    pub handle: Option<SafeHandle>,
    pub name: Option<String>,
}
impl WindowsProcess {
    pub fn from_pid(pid: usize) -> Self { 
        WindowsProcess { 
            pid: pid,
            handle: None,
            name: None,
        }
    }

    pub fn get_handle(&mut self) -> Result<(), NTSTATUS> { 
        let handle = nt_get_handle(self.pid)?;
        self.handle = Some(handle);
        Ok(())
    }

    fn check_handle(&mut self) -> Result<(), NTSTATUS> { 
        if self.handle.is_none() { 
            eprintln!("An open handle is required!");
            self.get_handle()?;
            eprintln!("Acquired a handle.")
        }
        Ok(())
    }

    pub fn write_process_memory(&mut self, address: usize, data: Vec<u8>) -> Result<usize, NTSTATUS> {
        self.check_handle()?;
        let handle = self.handle.as_ref().unwrap(); 
        Ok(nt_write_process_memory(
            **handle, 
            address as usize, 
            data
        )?)
    }

    pub fn read_process_memory(&mut self, address: usize, amount_to_read: usize) -> Result<(Vec<u8>, usize), NTSTATUS> {
        self.check_handle()?;
        let handle = self.handle.as_ref().unwrap(); 
        Ok(nt_read_process_memory(
            **handle, 
            address, 
            amount_to_read
        )?)
    }

    pub fn virtual_alloc(&mut self, address: Option<usize>, protection_flags: Option<usize>, size: Option<usize>, allocation_type: Option<usize>) -> Result<PVoid, NTSTATUS> {
        self.check_handle()?;
        let handle = self.handle.as_ref().unwrap(); 
        Ok(nt_virtual_alloc(
            **handle, 
            address, 
            protection_flags, 
            size, 
            allocation_type
        )?)

    }
    pub fn create_remote_thread_ex(&mut self, address: CCvoid) -> Result<(), NTSTATUS> {
        self.check_handle()?;
        let handle = self.handle.as_ref().unwrap(); 
        Ok(nt_create_remote_thread_ex(
            **handle, 
            address
        )?)
    }

    pub fn virtual_protect(&mut self, address: CCvoid, protection_size: usize, flags: usize) -> Result<CCvoid, NTSTATUS> {
        self.check_handle()?;
        let handle = self.handle.as_ref().unwrap(); 
        Ok(nt_virtual_protect_ex(
            **handle, 
            address, 
            protection_size, 
            flags
        )?)
    }


}

// --- Wrapper for handles to implement QOL features. ---
pub struct SafeHandle(pub HANDLE);

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
                Ok(_) => (),
                Err(e) => panic!("[!] Error closing handle\n-> {}", e),
            }
        }
    }
}
impl std::fmt::Display for SafeHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        let handle_id: isize = self.0.0;
        write!(formatter, "<Handle {}>", handle_id)
    }
}

// --- Types ---
pub type PVoid     = *mut c_void;       // C void*
pub type CCvoid    = *const c_void;     // C const void*
pub type PUsize    = *mut usize;        // C's PSIZE 

// --- Assembly syscalls ---
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

// --- FFI Bindings for the syscalls ---
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

// --- Rusty wrapper functions ---
pub fn enumerate_processes() -> Result<Vec<usize>, windows::core::Error> {
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

pub fn nt_get_handle(pid: usize) -> Result<SafeHandle, NTSTATUS> {
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
        match status.is_ok() { 
            true  => return Ok(SafeHandle(handle)),
            false => return Err(status)
        }
    }
}

pub fn nt_write_process_memory(handle: HANDLE, address: usize, mut data: Vec<u8>) -> Result<usize, NTSTATUS> { 
    let base_address:       CCvoid = address as CCvoid;
    let buffer_ptr:         CCvoid = data.as_mut_ptr() as *mut c_void;
    let mut bytes_written:  usize = 0; 
    let mut written_ptr:    PUsize = &mut bytes_written as PUsize;
    unsafe { 
        let status = nt_write_virtual_memory(
            handle, 
            base_address, 
            buffer_ptr, 
            data.len(), 
            written_ptr
        ); 
        match status.is_ok() { 
            true  => return Ok(bytes_written),
            false => return Err(status)
        }
    }
}

pub fn nt_read_process_memory(handle: HANDLE, address: usize, amount_to_read: usize) -> Result<(Vec<u8>, usize), NTSTATUS> { 
    let base_address:   CCvoid = address as CCvoid;
    let mut buffer:     Vec<u8>= vec![0u8; amount_to_read]; 
    let buffer_ptr:     CCvoid = buffer.as_mut_ptr() as PVoid;
    let mut bytes_read: usize  = 0;
    let mut read_ptr:   PUsize = &mut bytes_read as PUsize;
    unsafe { 
        let status = zw_read_virtual_memory(
            handle, 
            base_address, 
            buffer_ptr, 
            amount_to_read, 
            read_ptr
        );
        match status.is_ok() { 
            true  => return Ok((buffer, bytes_read)),
            false => return Err(status)
        }
    }
}

pub fn nt_virtual_alloc(handle: HANDLE, address: Option<usize>, protection_flags: Option<usize>, size: Option<usize>, allocation_type: Option<usize>) -> Result<PVoid, NTSTATUS> {
    let mut base_address:   PVoid = match address { 
        Some(number)    => number as PVoid,
        None                   => null_mut(),
    };
    let zero_bits:          usize = 0;
    let mut region_size:    usize = match size { 
        Some(size)      =>  size,
        None                   =>  4096
    };
    let allocation_type:    usize = match allocation_type { 
        Some(value)     => value,
        None                   => 0x00001000,
    }; 
    let protection_flags:   usize = match protection_flags{ 
        Some(flags)     => flags,    
        None                   => 0x00000004, // PAGE_READWRITE
    };
    unsafe { 
        let status = zw_allocate_virtual_memory(
            handle,
            &mut base_address,
            zero_bits,
            &mut region_size,
            allocation_type,
            protection_flags,
        );
        match status.is_ok() { 
            true  => return Ok(base_address),
            false => return Err(status)
        }
    }
}

pub fn nt_create_remote_thread_ex(handle: HANDLE, address: CCvoid) -> Result<(), NTSTATUS> {
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
        match status.is_ok() { 
            true  => return Ok(()),
            false => return Err(status)
        }

    }
}

pub fn nt_virtual_protect_ex(handle: HANDLE, address: CCvoid, size: usize, flags: usize) -> Result<CCvoid, NTSTATUS>{
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
        match status.is_ok() { 
            true  => return Ok(address),
            false => return Err(status)
        }
    }
}
