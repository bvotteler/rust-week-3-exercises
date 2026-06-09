use serde::{Deserialize, Serialize, de::Error};
use std::fmt;
use std::io::Read;
use std::ops::Deref;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct CompactSize {
    pub value: u64,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BitcoinError {
    InsufficientBytes,
    InvalidFormat,
}

impl CompactSize {
    pub fn new(value: u64) -> Self {
        // Construct a CompactSize from a u64 value
        CompactSize { value }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // Encode according to Bitcoin's CompactSize format:
        // [0x00–0xFC] => 1 byte
        // [0xFDxxxx] => 0xFD + u16 (2 bytes)
        // [0xFExxxxxxxx] => 0xFE + u32 (4 bytes)
        // [0xFFxxxxxxxxxxxxxxxx] => 0xFF + u64 (8 bytes)
        match self.value {
            // less than 256
            v if v < 253 => {
                vec![self.value as u8]
            }
            // between 253 (incl) and 256^2 (incl)
            v if v <= u16::MAX as u64 => {
                // casting locks in required byte width
                let size: u16 = self.value as u16;
                let mut v = size.to_le_bytes().to_vec();
                v.insert(0, 0xFD);
                v
            }
            // between 256^2 (incl) and 256^4 (incl)
            v if v <= u32::MAX as u64 => {
                // casting locks in required byte width
                let size: u32 = self.value as u32;
                let mut v = size.to_le_bytes().to_vec();
                v.insert(0, 0xFE);
                v
            }
            // catchall: between 256^4 (incl) and 256^8 (incl)
            // v if v <= u64::MAX => {
            _ => {
                // no need to cast it's u64 already
                let mut v = self.value.to_le_bytes().to_vec();
                v.insert(0, 0xFF);
                v
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        // Decode CompactSize, returning value and number of bytes consumed.
        // First check if bytes is empty.
        if bytes.is_empty() {
            return Err(BitcoinError::InsufficientBytes);
        }

        // need mutable slice to be able to consume with read()
        let mut reader = bytes;

        let mut prefix_byte = [0u8; 1];
        // read from bytes
        reader
            .read(&mut prefix_byte)
            .map_err(|_| BitcoinError::InvalidFormat)?;

        // Check that enough bytes are available based on prefix.
        let prefix = prefix_byte[0];
        match prefix {
            0..0xFD => {
                // prefix is the size, so return that
                let compact = CompactSize::new(prefix as u64);
                Ok((compact, 1))
            }
            0xFD => {
                // expect 2 more bytes
                let mut buffer = [0u8; 2];
                reader
                    // throws if not enough bytes left
                    .read(&mut buffer)
                    .map_err(|_| BitcoinError::InvalidFormat)?;

                // 2*u8 fits into u16
                let size = u16::from_le_bytes(buffer);
                let compact = CompactSize::new(size as u64);
                Ok((compact, 1 + 2))
            }
            0xFE => {
                // expect 4 more bytes
                let mut buffer = [0u8; 4];
                reader
                    // throws if not enough bytes left
                    .read(&mut buffer)
                    .map_err(|_| BitcoinError::InvalidFormat)?;

                // 4*u8 fits into u32
                let size = u32::from_le_bytes(buffer);
                let compact = CompactSize::new(size as u64);
                Ok((compact, 1 + 4))
            }
            0xFF => {
                // expect 8 more bytes
                let mut buffer = [0u8; 8];
                reader
                    // throws if not enough bytes left
                    .read(&mut buffer)
                    .map_err(|_| BitcoinError::InvalidFormat)?;

                // 8*u8 fits into u64
                let size = u64::from_le_bytes(buffer);
                let compact = CompactSize::new(size);
                Ok((compact, 1 + 8))
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Txid(pub [u8; 32]);

impl Serialize for Txid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize as a hex-encoded string (32 bytes => 64 hex characters)
        let hex_str = hex::encode(self.0);
        serializer.serialize_str(&hex_str)
    }
}

impl<'de> Deserialize<'de> for Txid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Parse hex string into 32-byte array
        let hex_str = String::deserialize(deserializer)?;

        // Use `hex::decode`, validate length = 32
        // precondition: need 64 character hex to get 32 length byte array
        if hex_str.len() != 64 {
            return Err(D::Error::custom(format!(
                "invalid txid length: expected 64 hex characters, found {}",
                hex_str.len()
            )));
        }

        let mut bytes = [0u8; 32];
        hex::decode_to_slice(&hex_str, &mut bytes)
            // map error
            .map_err(|e| D::Error::custom(format!("error while decoding hex: {}", e)))?;

        Ok(Txid(bytes))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: Txid,
    pub vout: u32,
}

impl OutPoint {
    pub fn new(txid: [u8; 32], vout: u32) -> Self {
        // Create an OutPoint from raw txid bytes and output index
        Self {
            txid: Txid(txid),
            vout,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // Serialize as: txid (32 bytes) + vout (4 bytes, little-endian)
        let Txid(txid_bytes) = self.txid;
        let vout_bytes = self.vout.to_le_bytes();

        // initialize big enough vector
        let mut bytes: Vec<u8> = Vec::with_capacity(36);
        bytes.extend_from_slice(&txid_bytes);
        bytes.extend_from_slice(&vout_bytes);

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        // Deserialize 36 bytes: txid[0..32], vout[32..36]
        // Return error if insufficient bytes
        if bytes.len() < 36 {
            return Err(BitcoinError::InsufficientBytes);
        }

        let txid_bytes: [u8; 32] = bytes[0..32]
            .try_into()
            .map_err(|_| BitcoinError::InvalidFormat)?;

        let vout_bytes = bytes[32..36]
            .try_into()
            .map_err(|_| BitcoinError::InvalidFormat)?;
        let vout = u32::from_le_bytes(vout_bytes);

        Ok((Self::new(txid_bytes, vout), 36))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Script {
    pub bytes: Vec<u8>,
}

impl Script {
    pub fn new(bytes: Vec<u8>) -> Self {
        // Simple constructor
        Self { bytes }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // Prefix with CompactSize (length), then raw bytes
        let compact_size = CompactSize::new(self.bytes.len() as u64);

        let prefix = compact_size.to_bytes();

        // initialize vector capacity, then append
        let mut bytes = Vec::with_capacity(prefix.len() + self.bytes.len());
        bytes.extend_from_slice(&prefix);
        bytes.extend_from_slice(&self.bytes);

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        // Parse CompactSize prefix, then read that many bytes
        let (size, bytes_read) = CompactSize::from_bytes(bytes)?;
        let end_of_block = size.value as usize + bytes_read;

        let script_bytes: &[u8] = &bytes[bytes_read..end_of_block];

        Ok((Self::new(script_bytes.to_vec()), end_of_block))
    }
}

impl Deref for Script {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        // Allow &Script to be used as &[u8]
        &self.bytes
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct TransactionInput {
    pub previous_output: OutPoint,
    pub script_sig: Script,
    pub sequence: u32,
}

impl TransactionInput {
    pub fn new(previous_output: OutPoint, script_sig: Script, sequence: u32) -> Self {
        // Basic constructor
        Self {
            previous_output,
            script_sig,
            sequence,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // Serialize: OutPoint + Script (with CompactSize) + sequence (4 bytes LE)
        let out_bytes = self.previous_output.to_bytes();
        let script_bytes = self.script_sig.to_bytes();
        let seq_bytes = self.sequence.to_le_bytes();

        let mut bytes = Vec::with_capacity(out_bytes.len() + script_bytes.len() + seq_bytes.len());
        bytes.extend_from_slice(&out_bytes);
        bytes.extend_from_slice(&script_bytes);
        bytes.extend_from_slice(&seq_bytes);

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        // Deserialize in order:
        // - OutPoint (36 bytes)
        let (outpoint, out_len) = OutPoint::from_bytes(bytes)?;
        // - Script (with CompactSize)
        let (script, script_len) = Script::from_bytes(&bytes[out_len..])?;
        // - Sequence (4 bytes)
        let bytes_read = out_len + script_len;
        let bytes_remaining = bytes.len() - bytes_read;
        if bytes_remaining < 4 {
            return Err(BitcoinError::InsufficientBytes);
        }

        let mut reader = &bytes[bytes_read..];
        let mut seq_bytes = [0u8; 4];
        // read 4 bytes, map error
        reader
            .read(&mut seq_bytes)
            .map_err(|_| BitcoinError::InvalidFormat)?;

        let sequence = u32::from_le_bytes(seq_bytes);
        let total_bytes_read = bytes_read + seq_bytes.len();

        Ok((Self::new(outpoint, script, sequence), total_bytes_read))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct BitcoinTransaction {
    pub version: u32,
    pub inputs: Vec<TransactionInput>,
    pub lock_time: u32,
}

impl BitcoinTransaction {
    pub fn new(version: u32, inputs: Vec<TransactionInput>, lock_time: u32) -> Self {
        // Construct a transaction from parts
        BitcoinTransaction {
            version,
            inputs,
            lock_time,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // Format:
        // - version (4 bytes LE)
        let version_bytes = self.version.to_le_bytes();

        // - CompactSize (number of inputs)
        let compact_size = CompactSize::new(self.inputs.len() as u64);
        let size_bytes = compact_size.to_bytes();

        // - each input serialized
        let input_txs_vec: Vec<u8> = self.inputs.iter().flat_map(|tx| tx.to_bytes()).collect();

        // - lock_time (4 bytes LE)
        let lock_time_bytes = self.lock_time.to_le_bytes();

        // construct vector with bytes
        let mut bytes: Vec<u8> = Vec::with_capacity(
            version_bytes.len() + size_bytes.len() + input_txs_vec.len() + lock_time_bytes.len(),
        );

        bytes.extend_from_slice(&version_bytes);
        bytes.extend_from_slice(&size_bytes);
        bytes.extend_from_slice(&input_txs_vec);
        bytes.extend_from_slice(&lock_time_bytes);

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        let mut reader = bytes;

        // Read version, CompactSize for input count
        let mut version_bytes = [0u8; 4];
        reader
            .read(&mut version_bytes)
            .map_err(|_| BitcoinError::InvalidFormat)?;
        let mut bytes_read = version_bytes.len();

        let version = u32::from_le_bytes(version_bytes);

        let (compact_size, size_len) = CompactSize::from_bytes(&bytes[bytes_read..])?;
        bytes_read += size_len;

        // Parse inputs one by one
        let mut inputs: Vec<TransactionInput> = Vec::with_capacity(compact_size.value as usize);

        for _ in 0..compact_size.value {
            let (tx, tx_len) = TransactionInput::from_bytes(&bytes[bytes_read..])?;
            bytes_read += tx_len;
            inputs.push(tx);
        }

        // Read final 4 bytes for lock_time
        let mut reader = &bytes[bytes_read..];
        let mut lock_time_bytes = [0u8; 4];
        reader
            .read(&mut lock_time_bytes)
            .map_err(|_| BitcoinError::InvalidFormat)?;
        bytes_read += lock_time_bytes.len();

        let lock_time = u32::from_le_bytes(lock_time_bytes);

        Ok((Self::new(version, inputs, lock_time), bytes_read))
    }
}

impl fmt::Display for BitcoinTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format a user-friendly string showing version, inputs, lock_time
        // Display scriptSig length and bytes, and previous output info
        // // lean on serde for all of this
        // match serde_json::to_string_pretty(self) {
        //     Ok(pretty_json_string) => write!(f, "{}", pretty_json_string),
        //     Err(_) => Err(fmt::Error),
        // }

        // or not... some strings are explicitly expected, so do (some of) it manually
        writeln!(f, "BitcoinTransaction:")?;
        writeln!(f, "Version: {}", self.version)?;
        writeln!(f, "Lock Time: {}", self.lock_time)?;
        writeln!(f, "Inputs: [")?;
        for input in self.inputs.iter() {
            writeln!(f, "\tSequence: {}", input.sequence)?;
            writeln!(f, "\tScriptSig: {:?}", input.script_sig)?;
            writeln!(f, "\tPrevious Output: {{")?;
            let outpoint = &input.previous_output;
            writeln!(f, "\t\tTxid: {:?}", outpoint.txid)?;
            writeln!(f, "\t\tPrevious Output Vout: {}", outpoint.vout)?;
            writeln!(f, "\t}}")?;
        }
        writeln!(f, "]")
    }
}
