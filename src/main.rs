use core::ffi::c_void;
use core::arch::global_asm;
use windows::Win32::{
    Foundation::{HANDLE, NTSTATUS, CloseHandle},
    System::{
        ProcessStatus::EnumProcesses,
        Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS},
        Memory::{VirtualAllocEx, PAGE_PROTECTION_FLAGS, 
            VIRTUAL_ALLOCATION_TYPE, MEM_EXTENDED_PARAMETER, 
            MEM_EXTENDED_PARAMETER0, MEM_EXTENDED_PARAMETER1},
    },
};

#[allow(unused_imports)]
#[allow(unused_attributes)]

trait WinUtils {
    fn as_mut_cvoid(&mut self) -> *mut c_void;
    fn as_const_cvoid(&self) -> *const c_void;
}

impl<T> WinUtils for Vec<T> {
    fn as_mut_cvoid(&mut self) -> *mut c_void {
        self.as_mut_ptr() as *mut c_void
    }
    fn as_const_cvoid(&self) -> *const c_void { 
        self.as_ptr() as *const c_void
    }
}



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
    virtual_alloc:
        mov r10, rcx
        mov eax, 0x76
        syscall
        ret
");

extern "C" {   
    fn read_process_memory(
        hProcess: HANDLE,                   // Handle   
        lpBaseAddress: *const c_void,       // Where to start reading
        lpBuffer: *const c_void,            // ptr to buffer to read to
        nSize:  usize,                      // buffer size
        lpNumberOfBytesRead: *mut usize);   // returns read size.

    fn write_process_memory(    
        hProcess: HANDLE,                   // Handle   
        lpBaseAddress: *const c_void,       // Where to start writing
        lpBuffer: *const c_void,            // ptr to buffer to write from
        nSize:  usize,                      // buffer size (write size)
        lpNumberOfBytesRead: *mut usize);   // returns size of write
    
    fn virtual_alloc(

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
fn get_handle(pid: u32) -> Result<HANDLE, windows::core::Error> {
    let desired_access = PROCESS_ACCESS_RIGHTS(0xFFFF); //0x0010 | 0x0020 | 0x0008 | 0x0400 <- Correct flags, at the moment, we are using debug flags.
    let mut handle = HANDLE::default();
    unsafe {
        handle = OpenProcess(
            desired_access,
            false,
            pid
        )?;
    }
    Ok(handle)
}
fn nt_write_process_memory(handle: HANDLE, address: usize, amount_to_read: usize, mut data: Vec<u8>) { 
    let base_address = address as *const c_void;
    let buffer_ptr = data.as_mut_ptr() as *mut c_void;
    let mut bytes_read: usize = 0;
    println!("Running wpm syscall");
    unsafe { 
        write_process_memory(handle, base_address, buffer_ptr, 1, &mut bytes_read as *mut usize); 
    }
}
fn nt_read_process_memory(handle: HANDLE, address: usize, amount_to_read: usize) -> Vec<u8> { 
    let base_address = address as *const c_void;
    let mut buffer = vec![0u8; 1]; 
    let buffer_ptr = buffer.as_mut_ptr() as *mut c_void;
    let mut bytes_read: usize = 0;
    println!("Running rpm syscall");
    unsafe { 
        read_process_memory(handle, base_address, buffer_ptr, 1, &mut bytes_read as *mut usize); 
    }
    buffer
}

// -1073741819 -> 0xC0000005 STATUS_ACCESS_VIOLATION
fn nt_virtual_alloc(handle: HANDLE, address: Option<usize>) {
    let lpaddr: *mut usize = match address {
        Some(t) => &mut t as *mut usize,
        None => 0usize as &mut t as *mut usize,
    };
    let size = 2048usize as *mut usize;
    let alloc_type = 0x00001000usize;
    let page_flags = 0x04usize;

    unsafe { 
        virtual_alloc(
            handle,        // _In_ HANDLE ProcessHandle,
            lpaddr         // _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
            size,        // _Inout_ PSIZE_T RegionSize,
            alloc_type,       // _In_ ULONG AllocationType,
            page_flags,        // _In_ ULONG PageProtection,
                    // _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
                    // _In_ ULONG ExtendedParameterCount


        );
    }
}

fn virtual_alloc_ex(handle: HANDLE, address: Option<usize>) { 
    let size: usize = 2048;
    let lpaddr: Option<*const c_void> = match address {
            Some(t) => Some(t  as *const c_void),
            None => None
    };
    let alloc_type = VIRTUAL_ALLOCATION_TYPE(0x00001000);
    let page_flags = PAGE_PROTECTION_FLAGS(0x04);
    unsafe {
        VirtualAllocEx(
            handle,
            lpaddr,
            size,
            alloc_type,
            page_flags,
        );

    }
}

fn main() {
    let current_process_pid = enumerate_processes().unwrap();
    let current_process_handle = get_handle(*current_process_pid.last().unwrap()).unwrap();
    let variable_to_read = 100u8;
    let variable_location = &variable_to_read as *const _ as *const c_void;
    println!("Testing:\nAddress: {:?} contains {}", variable_location, variable_to_read);
    let buff = nt_read_process_memory(current_process_handle, variable_location as usize, 1);
    println!("Read: {}", buff[0]);
    println!("Overwriting with value 64");
    nt_write_process_memory(current_process_handle, variable_location as usize, 1, vec![64u8]);
    let buff = nt_read_process_memory(current_process_handle, variable_location as usize, 1);
    println!("Read: {}", buff[0]);
    virtual_alloc_ex(current_process_handle, None);
}
