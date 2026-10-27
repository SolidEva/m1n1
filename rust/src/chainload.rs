// SPDX-License-Identifier: GPL-2.0-or-later
#![deny(unsafe_op_in_unsafe_fn)]

use crate::c_size_t;
use crate::gpt;
use crate::nvme;
use crate::println;
use alloc::vec::Vec;
use core::ffi::{c_char, c_int, c_void, CStr};
use fatfs::{FileSystem, FsOptions, Read, Seek, SeekFrom};
use rsa::{pkcs8::DecodePublicKey, sha2::{Digest, Sha512}, signature::SignatureEncoding, Pkcs1v15Sign};
use uuid::Uuid;

const PUBKEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0CGvmv+fltzgJfW4g32Q
bbxQzI76Ou+s8DKyNNUPlBRnahCMDaMtF7NwdRiU98nSHaClTk0WXRw3iTBGSdg3
1Xvej5Kh26i8g0FHfBNXTP8BuIqAGgcnw7kYhAY+wOA/JMmNf3ncCn7Hqea6CJ9+
kUFXnpF1C7N5XrFxJWKR5UstrOh3jBleoUdYxNO1J/6FegtGYzJXUgM0CiuPrzqW
w4+YkX59mhkv8+wHuiGt1BD/nUdWqLIXKeH/Az4sjJFJftbDefPvBNZs/yLg86PA
+TIIccbADK7iGFuF0MupitQKzYBx5KKvNBSj4fdFDyyNtpIxh3XzSixCODkCVa5c
6wIDAQAB
-----END PUBLIC KEY-----";

#[derive(Debug)]
pub enum Error {
    FATError(fatfs::Error<nvme::Error>),
    GPTError(gpt::Error<nvme::Error>),
    BadArgs,
    PartitionNotFound,
    RsaPublicKeyError(rsa::pkcs8::spki::Error),
    RsaSignatureFileError(rsa::signature::Error),
    BadSignature(rsa::Error),
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

fn verify_signature(image_buf: &Vec<u8>, sig_buf: &[u8], pubkey: &str) -> Result<(), Error> {
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
    let sig_buf = read_file(&fs, format!("{path}.sig").as_ref())?;

    verify_signature(&image_buf, &sig_buf, PUBKEY)?;

    println!("Image signature validated");

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
