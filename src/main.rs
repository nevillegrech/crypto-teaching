use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Block};
use image::RgbImage;

// Repeating-key XOR: the same operation encrypts and decrypts arbitrary bytes.
fn xor(text: &[u8], key: &[u8]) -> Vec<u8> {
    text.iter().zip(key.iter().cycle())
        .map(|(&a, &b)| a ^ b)
        .collect()
}

// The Index of Coincidence measures the probability that two randomly selected characters from a given text are identical.
// When analyzing English text (ignoring case and filtering for A–Z), the IC values serve as distinct indicators:
// ~0.0667: Typical for natural English plaintext.
// ~0.0385: Typical for completely random text

fn ic(text: &[u8]) -> f64 {
    let mut counts = [0.0; 256];
    for &c in text { counts[c as usize] += 1.0; }
    let n = text.len() as f64;
    counts.iter().map(|&f| f * (f - 1.0)).sum::<f64>() / (n * (n - 1.0))
}

fn score(text: &[u8], period: usize) -> f64 {
    (0..period).map(|i| {
        let column: Vec<u8> = text[i..].iter().step_by(period).copied().collect();
        ic(&column)
    }).sum::<f64>() / period as f64
}

fn xor_cipher() {
    let text = b"live mine laugh hello";
    let encrypted = xor(text, b"abcde");
    let decrypted = xor(&encrypted, b"abcde");
    assert_eq!(decrypted.as_slice(), text);
    println!("Encrypted: {encrypted:02x?}");
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
    println!("IC: plaintext {:.4}, ciphertext {:.4}", ic(text), ic(&encrypted));

    // The same challenge message, encrypted with repeating-key XOR.
    let c = b"\x13\x0c\x1b\x13\x43\x11\x1b\x1b\x0f\x00\x18\x00\x09\x41\x0a\x57\
        \x01\x1b\x17\x06\x57\x04\x13\x12\x10\x12\x0d\x5a\x0e\x16\x05\x49\
        \x19\x09\x02\x03\x1a\x5a\x0d\x02\x03\x0c\x16\x18\x43\x1e\x49\x0d\
        \x0e\x16\x1b\x0d\x5a\x0d\x0a\x1c\x0c\x5a\x15\x0c\x57\x1c\x14\x05\
        \x06\x05\x1a\x0e\x00\x0d\x13\x49\x0d\x09\x02\x03\x49\x17\x18\x43\
        \x19\x0c\x02\x15\x43\x03\x08\x09\x0a\x43\x1e\x1a\x5a\x16\x0b\x12\
        \x1d\x12\x04\x11\x57\x1d\x15\x41\x13\x12\x1b\x1c\x0e\x11\x1a\x49\
        \x1f\x19\x17\x12\x07\x09\x08\x15\x12\x49\x0e\x13\x02\x1e\x07\x13\
        \x0f\x04\x57\x00\x14\x41\x0d\x1e\x0a\x1f\x41\x0d\x12\x11\x0e\x41\
        \x05\x12\x0b\x08\x14\x02\x05\x10\x5a\x00\x0d\x13\x49\x0d\x09\x06\
        \x03\x01\x1f\x13\x43\x1e\x49\x1b\x0c\x43\x19\x0c\x1f\x05\x06\x13\
        \x49\x09\x0e\x0e\x12\x1e\x12\x04\x11\x12\x49\x17\x0e\x11\x12\x49\
        \x0f\x13\x04\x12\x07\x0e\x0d\x1a\x57\x06\x0c\x04\x11\x57\x1d\x12\
        \x04\x43\x14\x06\x17\x08\x0d\x10\x49\x17\x0e\x0d\x03\x01\x09";


    let mut n = 0;
    let mut max_s: f64 = 0.0;
    for i in 1..8 {
        let s = score(c, i);
        println!("Key length {i}: IC = {s:.4}");
        if s > max_s {
            max_s = s;
            n = i;
        }
    }


    let mut key = xor(&c[..4], b"dear");      // Recover "wiza".
    key.resize(n, b'c');                      // Guess the remaining letter.
    let plaintext = xor(c, &key);
    println!("Key: {}", String::from_utf8_lossy(&key));
    println!("Plaintext: {}", String::from_utf8_lossy(&plaintext));


    println!();
}



fn main() {
    xor_cipher();
}

fn aes_ecb_example() {
    let img = image::open("penguin.png").expect("file not found").to_rgb8();
    let (w, h) = img.dimensions();
    let mut pixels = img.into_raw();
    // DELETE FROM HERE
    println!("Hello, world {}!", pixels.len() % 16);
    let key = b"YELLOW SUBSUBSUB";
    let cipher = Aes128::new_from_slice(key).unwrap();

    for chunk in pixels.chunks_mut(16) {
        let mut b = *Block::from_slice(chunk);
        cipher.encrypt_block(&mut b);
        chunk.copy_from_slice(&b);
    }
    // DELETE UP TO HERE
    RgbImage::from_raw(w, h, pixels)
        .expect("unchanged pixel count")
        .save("ecb-rust.png")
        .expect("failed saving image");
}
