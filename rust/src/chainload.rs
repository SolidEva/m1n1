// SPDX-License-Identifier: GPL-2.0-or-later
#![deny(unsafe_op_in_unsafe_fn)]

use crate::c_size_t;
use crate::gpt;
use crate::nvme;
use crate::println;
use alloc::vec::Vec;
use core::ffi::{c_char, c_int, c_void, CStr};
use fatfs::{FileSystem, FsOptions, Read, Seek, SeekFrom};
use uuid::Uuid;
#[cfg(feature = "secureboot")]
use rsa::{pkcs8::DecodePublicKey, sha2::{Digest, Sha512}, signature::SignatureEncoding, Pkcs1v15Sign};

#[cfg(feature = "secureboot")]
#[derive(Debug)]
pub enum KeyType {
    RsaSha512
}

#[cfg(feature = "secureboot")]
impl KeyType {
    fn from(keytype: &str) -> Result<KeyType, Error> {
        match str::to_lowercase(keytype).as_ref() {
            "rsa-sha512" => Ok(KeyType::RsaSha512),
            _ => Err(Error::UnsupportedKeyType),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    FATError(fatfs::Error<nvme::Error>),
    GPTError(gpt::Error<nvme::Error>),
    BadArgs,
    PartitionNotFound,
    RsaPublicKeyError(rsa::pkcs8::spki::Error),
    RsaSignatureFileError(rsa::signature::Error),
    BadSignature(rsa::Error),
    UnsupportedKeyType,
    Unknown,
}

impl From<fatfs::Error<nvme::Error>> for Error {
    fn from(err: fatfs::Error<nvme::Error>) -> Error {
        Error::FATError(err)
    }
}

impl From<gpt::Error<nvme::Error>> for Error {
    fn from(err: gpt::Error<nvme::Error>) -> Error {
        Error::GPTError(err)
    }
}

impl From<rsa::pkcs8::spki::Error> for Error {
    fn from(err: rsa::pkcs8::spki::Error) -> Error {
        Error::RsaPublicKeyError(err)
    }
}

impl From<rsa::Error> for Error {
    fn from(err: rsa::Error) -> Error {
        Error::BadSignature(err)
    }
}

impl From<rsa::signature::Error> for Error {
    fn from(err: rsa::signature::Error) -> Error {
        Error::RsaSignatureFileError(err)
    }
}

#[cfg(feature = "secureboot")]
fn verify_signature(image_buf: &Vec<u8>, sig_buf: &[u8], pubkey_type: &KeyType, pubkey: &str) -> Result<(), Error> {
    match pubkey_type {
        KeyType::RsaSha512 => verify_rsa_signature(image_buf, sig_buf, pubkey)?,
    };
    println!("Image signature validated");
    Ok(())
}

#[cfg(feature = "secureboot")]
fn verify_rsa_signature(image_buf: &Vec<u8>, sig_buf: &[u8], pubkey: &str) -> Result<(), Error> {
    let signature = rsa::pkcs1v15::Signature::try_from(sig_buf)?;
    let scheme = Pkcs1v15Sign::new::<Sha512>();
    let hash = Sha512::digest(image_buf);
    let key = rsa::RsaPublicKey::from_public_key_pem(pubkey)?;
    key.verify(scheme, &hash, signature.to_bytes().as_ref())?;
    Ok(())
}

fn read_file(fs: &FileSystem<nvme::NVMEStorage>, path: &str) -> Result<Vec<u8>, Error> {
    println!("Reading: {}", path);
    let mut file = fs.root_dir().open_file(path)?;

    let size = file.seek(SeekFrom::End(0))? as usize;
    file.seek(SeekFrom::Start(0))?;

    println!("File size: {}", size);

    let mut buf: Vec<u8> = vec![0; size];
    let mut slice = &mut buf[..];
    while !slice.is_empty() {
        let read = file.read(slice)?;
        slice = &mut slice[read..];
    }
    println!("File read successfully");
    Ok(buf)
}

fn load_image(spec: &str) -> Result<Vec<u8>, Error> {
    println!("Chainloading {}", spec);

    let mut args = spec.split(';');

    let uuid = Uuid::parse_str(args.next().ok_or(Error::BadArgs)?).or(Err(Error::BadArgs))?;
    let path = args.next().ok_or(Error::BadArgs)?;

    let part = {
        let storage = nvme::NVMEStorage::new(1, 0);
        let mut pt = gpt::GPT::new(storage)?;

        //println!("Partitions:");
        //pt.dump();

        println!("Searching for partition UUID: {}", uuid);
        pt.find_by_partuuid(uuid)?.ok_or(Error::PartitionNotFound)?
    };

    let offset = part.get_starting_lba();

    println!("Partition offset: {}", offset);

    let storage = nvme::NVMEStorage::new(1, offset);
    let opts = FsOptions::new().update_accessed_date(false);

    let fs = FileSystem::new(storage, opts)?;

    let image_buf = read_file(&fs, &path)?;

    #[cfg(feature = "secureboot")]
    {
        let pubkey_type = KeyType::from(args.next().ok_or(Error::BadArgs)?)?;
        let pubkey = args.next().ok_or(Error::BadArgs)?;
        let sig_buf = read_file(&fs, format!("{path}.sig").as_ref())?;
        verify_signature(&image_buf, &sig_buf, &pubkey_type, &pubkey)?;
    }

    Ok(image_buf)
}

#[no_mangle]
pub unsafe extern "C" fn rust_load_image(
    raw_spec: *const c_char,
    image: *mut *mut c_void,
    size: *mut c_size_t,
) -> c_int {
    let spec = unsafe { CStr::from_ptr(raw_spec).to_str().unwrap() };

    match load_image(spec) {
        Ok(buf) => {
            unsafe {
                *size = buf.len();
                *image = buf.leak().as_mut_ptr() as *mut c_void;
            }
            0
        }
        Err(err) => {
            println!("Chainload failed: {:?}", err);
            -1
        }
    }
}
