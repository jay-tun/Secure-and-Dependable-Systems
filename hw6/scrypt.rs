// a) complete the file scrypt.rs

pub fn enc(m: u8, k: u32) -> u8 {
    let mut x = m;
    
    // Round 0
    x = x ^ ((k >> 24) as u8);
    
    // Round 1 
    x = sub(x) >> 2 | sub(x) << 6; // Substitution
    x = x.rotate_left(2); // Permutation 
    x = x ^ ((k >> 16) as u8); // Key step
    
    // Round 2
    x = sub(x) >> 2 | sub(x) << 6;
    x = x.rotate_left(2);
    x = x ^ ((k >> 8) as u8);
    
    // Round 3
    x = sub(x) >> 2 | sub(x) << 6;
    x = x ^ (k as u8);
    
    x
}



pub fn dec(c: u8, k: u32) -> u8 {
    let mut x = c;
    
    // Reverse Round 3
    x = x ^ (k as u8);
    x = sub_inv(x) >> 2 | sub_inv(x) << 6;
    
    // Reverse Round 2
    x = x ^ ((k >> 8) as u8);
    x = x.rotate_right(2);
    x = sub_inv(x) >> 2 | sub_inv(x) << 6;
    
    // Reverse Round 1
    x = x ^ ((k >> 16) as u8);
    x = x.rotate_right(2);
    x = sub_inv(x) >> 2 | sub_inv(x) << 6;
    
    // Reverse Round 0
    x = x ^ ((k >> 24) as u8);
    
    x
}


pub fn enc_ecb(m: &mut [u8], k: u32) {
    for x in m.iter_mut() {
        *x = enc(*x, k);
    }
}


pub fn dec_ecb(c: &mut [u8], k: u32) {
    for x in c.iter_mut() {
        *x = dec(*x, k);
    }
}

pub fn enc_cbc(m: &mut [u8], k: u32, iv: u8) {
    let mut prev = iv;
    for x in m.iter_mut() {
        let tmp = *x;
        *x = enc(tmp ^ prev, k);
        prev = *x;
    }
}

pub fn dec_cbc(c: &mut [u8], k: u32, iv: u8) {
    let mut prev = iv;
    for x in c.iter_mut() {
        let tmp = *x;
        *x = dec(*x, k) ^ prev;
        prev = tmp;
    }
}


//b) encrypt "hello world" using enc_ecb

let plaintext = [0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64];
let mut ciphertext_ecb = plaintext.clone();
let key = 0x98267351;

enc_ecb(&mut ciphertext_ecb, key);

println!("ECB ciphertext: {:?}", ciphertext_ecb);




//encrypt "hello world" using enc_cbc
let mut ciphertext_cbc = plaintext.clone();
let iv = 0x42;

enc_cbc(&mut ciphertext_cbc, key, iv);

println!("CBC ciphertext: {:?}", ciphertext_cbc);
