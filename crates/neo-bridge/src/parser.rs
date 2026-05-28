//! Self-contained Circom `.r1cs` + `.wtns` binary parsers, Goldilocks-targeted.
//!
//! Verbatim port (with light cleanup) from
//! `slh-dsa-circuit/tools/nightstream-spike/src/parser.rs`. Duplicated rather
//! than shared as a path-dep because that crate lives in a different repo.
//!
//! Format specs:
//! - R1CS binary:  <https://github.com/iden3/r1csfile/blob/master/doc/r1cs_bin_format.md>
//! - Witness:      <https://github.com/iden3/snarkjs/blob/master/src/wtns_format.md>

use anyhow::{Context, Result, anyhow, bail};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const R1CS_MAGIC: [u8; 4] = *b"r1cs";
const WTNS_MAGIC: [u8; 4] = *b"wtns";
const R1CS_SECTION_HEADER: u32 = 1;
const R1CS_SECTION_CONSTRAINTS: u32 = 2;
const WTNS_SECTION_HEADER: u32 = 1;
const WTNS_SECTION_DATA: u32 = 2;

#[derive(Debug, Clone)]
pub struct CircomR1cs {
    pub field_size_bytes: u32,
    pub n_wires: u32,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    pub n_constraints: u32,
    pub a: Vec<Vec<(u32, Vec<u8>)>>,
    pub b: Vec<Vec<(u32, Vec<u8>)>>,
    pub c: Vec<Vec<(u32, Vec<u8>)>>,
}

#[derive(Debug, Clone)]
pub struct CircomWitness {
    pub field_size_bytes: u32,
    pub n_wires: u32,
    pub wires_le_bytes: Vec<Vec<u8>>,
}

pub fn parse_circom_r1cs(path: &Path) -> Result<CircomR1cs> {
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).context("reading r1cs magic")?;
    if magic != R1CS_MAGIC {
        bail!("not a Circom r1cs file");
    }
    let version = read_u32_le(&mut f)?;
    if version != 1 {
        bail!("unsupported r1cs version {}", version);
    }
    let n_sections = read_u32_le(&mut f)?;

    let mut header: Option<(u32, u32, u32, u32, u32)> = None;
    let mut constraints_offset: Option<u64> = None;

    for _ in 0..n_sections {
        let section_type = read_u32_le(&mut f)?;
        let section_size = read_u64_le(&mut f)?;
        let section_start = f.stream_position()?;
        match section_type {
            R1CS_SECTION_HEADER => {
                let fsb = read_u32_le(&mut f)?;
                let mut _prime = vec![0u8; fsb as usize];
                f.read_exact(&mut _prime)?;
                let nw = read_u32_le(&mut f)?;
                let npo = read_u32_le(&mut f)?;
                let npi = read_u32_le(&mut f)?;
                let _npri = read_u32_le(&mut f)?;
                let _nlabels = read_u64_le(&mut f)?;
                let nc = read_u32_le(&mut f)?;
                header = Some((fsb, nw, npo, npi, nc));
                f.seek(SeekFrom::Start(section_start + section_size))?;
            }
            R1CS_SECTION_CONSTRAINTS => {
                constraints_offset = Some(section_start);
                f.seek(SeekFrom::Start(section_start + section_size))?;
            }
            _ => {
                f.seek(SeekFrom::Start(section_start + section_size))?;
            }
        }
    }

    let (fsb, nw, npo, npi, nc) = header.ok_or_else(|| anyhow!("missing header"))?;
    let constraints_offset = constraints_offset.ok_or_else(|| anyhow!("missing constraints"))?;

    f.seek(SeekFrom::Start(constraints_offset))?;
    let mut a = Vec::with_capacity(nc as usize);
    let mut b = Vec::with_capacity(nc as usize);
    let mut c = Vec::with_capacity(nc as usize);
    for _ in 0..nc {
        a.push(read_linear_combo(&mut f, fsb)?);
        b.push(read_linear_combo(&mut f, fsb)?);
        c.push(read_linear_combo(&mut f, fsb)?);
    }

    Ok(CircomR1cs {
        field_size_bytes: fsb,
        n_wires: nw,
        n_pub_out: npo,
        n_pub_in: npi,
        n_constraints: nc,
        a,
        b,
        c,
    })
}

pub fn parse_circom_wtns(path: &Path) -> Result<CircomWitness> {
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic)?;
    if magic != WTNS_MAGIC {
        bail!("not a Circom wtns file");
    }
    let version = read_u32_le(&mut f)?;
    if version != 2 {
        bail!("unsupported wtns version {}", version);
    }
    let n_sections = read_u32_le(&mut f)?;

    let mut fsb: Option<u32> = None;
    let mut nw: Option<u32> = None;
    let mut data_offset: Option<u64> = None;

    for _ in 0..n_sections {
        let section_type = read_u32_le(&mut f)?;
        let section_size = read_u64_le(&mut f)?;
        let section_start = f.stream_position()?;
        match section_type {
            WTNS_SECTION_HEADER => {
                let f_ = read_u32_le(&mut f)?;
                let mut _prime = vec![0u8; f_ as usize];
                f.read_exact(&mut _prime)?;
                let n = read_u32_le(&mut f)?;
                fsb = Some(f_);
                nw = Some(n);
                f.seek(SeekFrom::Start(section_start + section_size))?;
            }
            WTNS_SECTION_DATA => {
                data_offset = Some(section_start);
                f.seek(SeekFrom::Start(section_start + section_size))?;
            }
            _ => {
                f.seek(SeekFrom::Start(section_start + section_size))?;
            }
        }
    }

    let fsb = fsb.ok_or_else(|| anyhow!("missing header"))?;
    let nw = nw.ok_or_else(|| anyhow!("missing n_wires"))?;
    let data_offset = data_offset.ok_or_else(|| anyhow!("missing data"))?;
    f.seek(SeekFrom::Start(data_offset))?;
    let mut wires = Vec::with_capacity(nw as usize);
    for _ in 0..nw {
        let mut w = vec![0u8; fsb as usize];
        f.read_exact(&mut w)?;
        wires.push(w);
    }
    Ok(CircomWitness {
        field_size_bytes: fsb,
        n_wires: nw,
        wires_le_bytes: wires,
    })
}

fn read_linear_combo(f: &mut File, fsb: u32) -> Result<Vec<(u32, Vec<u8>)>> {
    let n = read_u32_le(f)?;
    let mut out = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let wire = read_u32_le(f)?;
        let mut coeff = vec![0u8; fsb as usize];
        f.read_exact(&mut coeff)?;
        out.push((wire, coeff));
    }
    Ok(out)
}

fn read_u32_le(f: &mut File) -> Result<u32> {
    let mut buf = [0u8; 4];
    f.read_exact(&mut buf).context("read u32 LE")?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64_le(f: &mut File) -> Result<u64> {
    let mut buf = [0u8; 8];
    f.read_exact(&mut buf).context("read u64 LE")?;
    Ok(u64::from_le_bytes(buf))
}
