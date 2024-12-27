use std::io;

use crate::{byte_packet_buffer::BytePacketBuffer, query_types::QueryType};

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion { name, qtype }
    }
    /// Read Dns question.
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), io::Error> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?); // qtype
        let _ = buffer.read_u16()?; // class
        Ok(())
    }

    /// Write Dns question as bytes to buffer.
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), io::Error> {
        buffer.write_qname(&self.name)?;

        let typenum = self.qtype.to_num();
        buffer.write_u16(typenum)?;
        buffer.write_u16(1)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_question_from_buffer() {
        let mut buf = BytePacketBuffer::new();

        buf.buf[0] = 6;
        buf.buf[1..7].copy_from_slice(b"google");
        buf.buf[7] = 3;
        buf.buf[8..11].copy_from_slice(b"com");
        buf.buf[11] = 0;
        buf.buf[12] = 0x00;
        buf.buf[13] = 0x01; // qtype A

        let mut question = DnsQuestion::new("".to_string(), QueryType::A);
        assert!(question.read(&mut buf).is_ok());

        assert_eq!(question.name, "google.com");
        assert_eq!(question.qtype, QueryType::A);
    }

    #[test]
    fn test_write_question_to_buffer() {
        let question = DnsQuestion::new("google.com".to_string(), QueryType::A);

        let mut buf = BytePacketBuffer::new();
        assert!(question.write(&mut buf).is_ok());

        assert_eq!(buf.buf[0], 6);
        assert_eq!(&buf.buf[1..7], b"google");
        assert_eq!(buf.buf[7], 3);
        assert_eq!(&buf.buf[8..11], b"com");
        assert_eq!(buf.buf[11], 0);
        assert_eq!(buf.buf[12], 0x00);
        assert_eq!(buf.buf[13], 0x01); // qtype A
    }

    #[test]
    fn test_read_write() {
        let question = DnsQuestion::new("google.com".to_string(), QueryType::A);

        let mut buf = BytePacketBuffer::new();
        assert!(question.write(&mut buf).is_ok());

        let mut read_question = DnsQuestion::new("".to_string(), QueryType::A);
        assert!(buf.seek(0).is_ok());
        assert!(read_question.read(&mut buf).is_ok());

        assert_eq!(question.name, read_question.name);
        assert_eq!(question.qtype, read_question.qtype);
    }
}
