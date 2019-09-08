use core::{convert::TryFrom, fmt, str::FromStr};
use digest::Input;
use exitfailure::ExitFailure;
use failure::{format_err, Error};
use multihash::{self, Code, Multihash, MultihashDigest};
use std::io::{self, Read, Write};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
struct Opts {
    /// The mode
    #[structopt(subcommand)]
    mode: Mode,
}

#[derive(StructOpt, Debug)]
enum Mode {
    #[structopt(name = "hash")]
    Hash {
        /// The hash to use.
        #[structopt(short = "h", long = "hash", default_value = "sha2-256")]
        hasher: Hasher,
    },
    #[structopt(name = "verify")]
    Verify {
        /// The multibase encoded multihash.
        #[structopt(name = "HASH")]
        hash: String,
    },
}

fn main() -> Result<(), ExitFailure> {
    env_logger::init();
    let opts = Opts::from_args();
    match opts.mode {
        Mode::Hash { hasher } => hash(hasher),
        Mode::Verify { hash } => verify(hash),
    }
}

#[derive(Debug)]
enum Hasher {
    Sha1(multihash::Sha1),
    Sha2_256(multihash::Sha2_256),
    Sha2_512(multihash::Sha2_512),
    Sha3_224(multihash::Sha3_224),
    Sha3_256(multihash::Sha3_256),
    Sha3_384(multihash::Sha3_384),
    Sha3_512(multihash::Sha3_512),
    Keccak224(multihash::Keccak224),
    Keccak256(multihash::Keccak256),
    Keccak384(multihash::Keccak384),
    Keccak512(multihash::Keccak512),
    Blake2b(multihash::Blake2b),
    Blake2s(multihash::Blake2s),
    Murmur3_32(multihash::Murmur3_32),
    Murmur3_128X64(multihash::Murmur3_128X64),
}

impl fmt::Display for Hasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hash_str = match self {
            Hasher::Sha1(_) => "sha1",
            Hasher::Sha2_256(_) => "sha2-256",
            Hasher::Sha2_512(_) => "sha2-512",
            Hasher::Sha3_224(_) => "sha3-224",
            Hasher::Sha3_256(_) => "sha3-256",
            Hasher::Sha3_384(_) => "sha3-384",
            Hasher::Sha3_512(_) => "sha3-512",
            Hasher::Keccak224(_) => "keccak-224",
            Hasher::Keccak256(_) => "keccak-256",
            Hasher::Keccak384(_) => "keccak-384",
            Hasher::Keccak512(_) => "keccak-512",
            Hasher::Blake2b(_) => "blake2b",
            Hasher::Blake2s(_) => "blake2s",
            Hasher::Murmur3_32(_) => "murmur3-32",
            Hasher::Murmur3_128X64(_) => "murmur3-128-x64",
        };
        write!(f, "{}", hash_str)
    }
}

impl FromStr for Hasher {
    type Err = Error;

    fn from_str(hash_str: &str) -> Result<Self, Self::Err> {
        match hash_str {
            "sha1" => Self::try_from(Code::Sha1),
            "sha2-256" => Self::try_from(Code::Sha2_256),
            "sha2-512" => Self::try_from(Code::Sha2_512),
            "sha3-224" => Self::try_from(Code::Sha3_224),
            "sha3-256" => Self::try_from(Code::Sha3_256),
            "sha3-384" => Self::try_from(Code::Sha3_384),
            "sha3-512" => Self::try_from(Code::Sha3_512),
            "keccak-224" => Self::try_from(Code::Keccak224),
            "keccak-256" => Self::try_from(Code::Keccak256),
            "keccak-384" => Self::try_from(Code::Keccak384),
            "keccak-512" => Self::try_from(Code::Keccak512),
            "blake2b" => Self::try_from(Code::Blake2b),
            "blake2s" => Self::try_from(Code::Blake2s),
            "murmur3-32" => Self::try_from(Code::Murmur3_32),
            "murmur3-128-x64" => Self::try_from(Code::Murmur3_128X64),
            _ => Err(format_err!("Unknown hasher {:?}", hash_str)),
        }
    }
}

impl TryFrom<Code> for Hasher {
    type Error = Error;

    fn try_from(code: Code) -> Result<Self, Self::Error> {
        match code {
            Code::Sha1 => Ok(Hasher::Sha1(multihash::Sha1::new())),
            Code::Sha2_256 => Ok(Hasher::Sha2_256(multihash::Sha2_256::new())),
            Code::Sha2_512 => Ok(Hasher::Sha2_512(multihash::Sha2_512::new())),
            Code::Sha3_224 => Ok(Hasher::Sha3_224(multihash::Sha3_224::new())),
            Code::Sha3_256 => Ok(Hasher::Sha3_256(multihash::Sha3_256::new())),
            Code::Sha3_384 => Ok(Hasher::Sha3_384(multihash::Sha3_384::new())),
            Code::Sha3_512 => Ok(Hasher::Sha3_512(multihash::Sha3_512::new())),
            Code::Keccak224 => Ok(Hasher::Keccak224(multihash::Keccak224::new())),
            Code::Keccak256 => Ok(Hasher::Keccak256(multihash::Keccak256::new())),
            Code::Keccak384 => Ok(Hasher::Keccak384(multihash::Keccak384::new())),
            Code::Keccak512 => Ok(Hasher::Keccak512(multihash::Keccak512::new())),
            Code::Blake2b => Ok(Hasher::Blake2b(multihash::Blake2b::new())),
            Code::Blake2s => Ok(Hasher::Blake2s(multihash::Blake2s::new())),
            Code::Murmur3_32 => Ok(Hasher::Murmur3_32(multihash::Murmur3_32::new())),
            Code::Murmur3_128X64 => Ok(Hasher::Murmur3_128X64(multihash::Murmur3_128X64::new())),
        }
    }
}

impl Hasher {
    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        match self {
            Self::Sha1(hasher) => hasher.input(data),
            Self::Sha2_256(hasher) => hasher.input(data),
            Self::Sha2_512(hasher) => hasher.input(data),
            Self::Sha3_224(hasher) => hasher.input(data),
            Self::Sha3_256(hasher) => hasher.input(data),
            Self::Sha3_384(hasher) => hasher.input(data),
            Self::Sha3_512(hasher) => hasher.input(data),
            Self::Keccak224(hasher) => hasher.input(data),
            Self::Keccak256(hasher) => hasher.input(data),
            Self::Keccak384(hasher) => hasher.input(data),
            Self::Keccak512(hasher) => hasher.input(data),
            Self::Blake2b(hasher) => hasher.input(data),
            Self::Blake2s(hasher) => hasher.input(data),
            Self::Murmur3_32(hasher) => hasher.input(data),
            Self::Murmur3_128X64(hasher) => hasher.input(data),
        }
    }

    fn result(self) -> Multihash {
        match self {
            Self::Sha1(hasher) => hasher.result(),
            Self::Sha2_256(hasher) => hasher.result(),
            Self::Sha2_512(hasher) => hasher.result(),
            Self::Sha3_224(hasher) => hasher.result(),
            Self::Sha3_256(hasher) => hasher.result(),
            Self::Sha3_384(hasher) => hasher.result(),
            Self::Sha3_512(hasher) => hasher.result(),
            Self::Keccak224(hasher) => hasher.result(),
            Self::Keccak256(hasher) => hasher.result(),
            Self::Keccak384(hasher) => hasher.result(),
            Self::Keccak512(hasher) => hasher.result(),
            Self::Blake2b(hasher) => hasher.result(),
            Self::Blake2s(hasher) => hasher.result(),
            Self::Murmur3_32(hasher) => hasher.result(),
            Self::Murmur3_128X64(hasher) => hasher.result(),
        }
    }
}

fn hash_stdin(mut hasher: Hasher) -> Result<Multihash, Error> {
    log::debug!("hashing with {}", hasher);
    let mut stdin = io::stdin();
    let mut buffer = Vec::new();
    stdin.read_to_end(&mut buffer)?;
    hasher.input(buffer.as_slice());
    Ok(hasher.result())
}

fn hash(hasher: Hasher) -> Result<(), ExitFailure> {
    let mut stdout = io::stdout();
    let hash = hash_stdin(hasher)?;
    let bytes = &hash;
    stdout.write_all(&bytes)?;
    Ok(())
}

fn verify(hash: String) -> Result<(), ExitFailure> {
    let (_, result) = multibase::decode(hash.as_str())?;
    let expected = multihash::decode(result.as_slice())?;
    let hasher = Hasher::try_from(expected.code())?;
    log::debug!("detected {}", hasher);
    let input = hash_stdin(hasher)?;
    if input != expected {
        Err(format_err!("Hash mismatch"))?
    }
    Ok(())
}
