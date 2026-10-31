//! Layout-0 encode and decode. A record that does not parse exactly is
//! malformed: wrong prefix or layout, a length out of range, an unknown
//! flag value, or trailing bytes.

use crate::{
    Coverage, CoverageMode, JOINREF_PREFIX, LAYOUT, OBSERVED_MAX, Observed, SELF_PROV_MAX,
    SIGHTING_PREFIX, SIGNATURE_LEN, SchemeTag, SelfProv, Seq, SequenceSource, SightingParts,
    SightingView, SubjectRef,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The output buffer cannot hold the record.
    BufferTooSmall,
    /// Observed data longer than 1024 bytes.
    ObservedTooLong,
    /// Self-provenance reference empty or longer than 256 bytes.
    SelfProvLength,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    Prefix,
    Layout,
    SubjectLength,
    ObservedLength,
    CoverageMode,
    SelfProvFlag,
    SelfProvLength,
    SourceFlag,
    Trailing,
}

struct Writer<'b> {
    buf: &'b mut [u8],
    at: usize,
}

impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        let end = self.at.checked_add(bytes.len()).ok_or(EncodeError::BufferTooSmall)?;
        if end > self.buf.len() {
            return Err(EncodeError::BufferTooSmall);
        }
        self.buf[self.at..end].copy_from_slice(bytes);
        self.at = end;
        Ok(())
    }

    fn u8(&mut self, v: u8) -> Result<(), EncodeError> {
        self.put(&[v])
    }

    fn u16(&mut self, v: u16) -> Result<(), EncodeError> {
        self.put(&v.to_be_bytes())
    }

    fn u64(&mut self, v: u64) -> Result<(), EncodeError> {
        self.put(&v.to_be_bytes())
    }

    fn subject(&mut self, s: &SubjectRef) -> Result<(), EncodeError> {
        self.u16(s.scheme().0)?;
        // SubjectRef guarantees 1..=32.
        self.u8(s.bytes().len() as u8)?;
        self.put(s.bytes())
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.at.checked_add(n).ok_or(DecodeError::Truncated)?;
        if end > self.buf.len() {
            return Err(DecodeError::Truncated);
        }
        let out = &self.buf[self.at..end];
        self.at = end;
        Ok(out)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn subject(&mut self) -> Result<SubjectRef, DecodeError> {
        let scheme = SchemeTag(self.u16()?);
        let len = self.u8()? as usize;
        let bytes = self.take(len)?;
        SubjectRef::new(scheme, bytes).ok_or(DecodeError::SubjectLength)
    }

    fn header(&mut self, prefix: &[u8]) -> Result<(), DecodeError> {
        if self.take(prefix.len())? != prefix {
            return Err(DecodeError::Prefix);
        }
        if self.u8()? != LAYOUT {
            return Err(DecodeError::Layout);
        }
        Ok(())
    }

    fn finish(&self) -> Result<(), DecodeError> {
        if self.at == self.buf.len() { Ok(()) } else { Err(DecodeError::Trailing) }
    }
}

/// Encode a sighting into `out`; returns the number of bytes written.
pub fn encode_sighting(p: &SightingParts, out: &mut [u8]) -> Result<usize, EncodeError> {
    if p.observed.data.len() > OBSERVED_MAX {
        return Err(EncodeError::ObservedTooLong);
    }
    if let Some(sp) = &p.self_prov {
        if sp.reference.is_empty() || sp.reference.len() > SELF_PROV_MAX {
            return Err(EncodeError::SelfProvLength);
        }
    }
    let mut w = Writer { buf: out, at: 0 };
    w.put(SIGHTING_PREFIX)?;
    w.u8(LAYOUT)?;
    w.subject(&p.subject)?;
    w.u16(p.observed.class)?;
    w.u16(p.observed.data.len() as u16)?;
    w.put(p.observed.data)?;
    w.u8(p.coverage.mode.to_wire())?;
    w.u64(p.coverage.from)?;
    w.u16(p.coverage.over)?;
    match &p.self_prov {
        None => w.u8(0)?,
        Some(sp) => {
            w.u8(1)?;
            w.u16(sp.kind)?;
            w.u16(sp.reference.len() as u16)?;
            w.put(sp.reference)?;
        }
    }
    w.put(&p.seq.instance)?;
    w.u64(p.seq.index)?;
    w.put(&p.seq.prev)?;
    match p.source {
        SequenceSource::None => w.u8(0)?,
        SequenceSource::Declared(tag) => {
            w.u8(1)?;
            w.u16(tag)?;
        }
    }
    w.put(&p.key_id)?;
    w.put(&p.signature)?;
    Ok(w.at)
}

/// Decode one complete sighting.
pub fn decode_sighting(buf: &[u8]) -> Result<SightingView<'_>, DecodeError> {
    let mut r = Reader { buf, at: 0 };
    r.header(SIGHTING_PREFIX)?;
    let subject = r.subject()?;
    let class = r.u16()?;
    let len = r.u16()? as usize;
    if len > OBSERVED_MAX {
        return Err(DecodeError::ObservedLength);
    }
    let data = r.take(len)?;
    let mode = CoverageMode::from_wire(r.u8()?).ok_or(DecodeError::CoverageMode)?;
    let from = r.u64()?;
    let over = r.u16()?;
    let self_prov = match r.u8()? {
        0 => None,
        1 => {
            let kind = r.u16()?;
            let len = r.u16()? as usize;
            if len == 0 || len > SELF_PROV_MAX {
                return Err(DecodeError::SelfProvLength);
            }
            Some(SelfProv { kind, reference: r.take(len)? })
        }
        _ => return Err(DecodeError::SelfProvFlag),
    };
    let instance = r.array()?;
    let index = r.u64()?;
    let prev = r.array()?;
    let source = match r.u8()? {
        0 => SequenceSource::None,
        1 => SequenceSource::Declared(r.u16()?),
        _ => return Err(DecodeError::SourceFlag),
    };
    let key_id = r.array()?;
    let signature: [u8; SIGNATURE_LEN] = r.array()?;
    r.finish()?;
    Ok(SightingView {
        parts: SightingParts {
            subject,
            observed: Observed { class, data },
            coverage: Coverage { mode, from, over },
            self_prov,
            seq: Seq { instance, index, prev },
            source,
            key_id,
            signature,
        },
        raw: buf,
    })
}

/// Encode a join reference into `out`; returns the number of bytes written.
pub fn encode_joinref(s: &SubjectRef, out: &mut [u8]) -> Result<usize, EncodeError> {
    let mut w = Writer { buf: out, at: 0 };
    w.put(JOINREF_PREFIX)?;
    w.u8(LAYOUT)?;
    w.subject(s)?;
    Ok(w.at)
}

/// Decode one complete join reference.
pub fn decode_joinref(buf: &[u8]) -> Result<SubjectRef, DecodeError> {
    let mut r = Reader { buf, at: 0 };
    r.header(JOINREF_PREFIX)?;
    let s = r.subject()?;
    r.finish()?;
    Ok(s)
}
