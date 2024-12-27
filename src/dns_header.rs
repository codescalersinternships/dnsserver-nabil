use std::io;

use crate::byte_packet_buffer::BytePacketBuffer;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16, // 16 bits

    pub recursion_desired: bool,    // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: u8,                 // 4 bits
    pub response: bool,             // 1 bit

    pub rescode: ResultCode,       // 4 bits
    pub checking_disabled: bool,   // 1 bit
    pub authed_data: bool,         // 1 bit
    pub z: bool,                   // 1 bit
    pub recursion_available: bool, // 1 bit

    pub questions: u16,             // 16 bits
    pub answers: u16,               // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16,      // 16 bits
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }
    /// Read Dns packet header.
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), io::Error> {
        self.id = buffer.read_u16()?;

        let mut flags = buffer.read()?;
        self.recursion_desired = (flags & (1 << 0)) > 0;
        self.truncated_message = (flags & (1 << 1)) > 0;
        self.authoritative_answer = (flags & (1 << 2)) > 0;
        self.opcode = (flags >> 3) & 0x0F;
        self.response = (flags & (1 << 7)) > 0;

        flags = buffer.read()?;
        self.rescode = ResultCode::from_num(flags & 0x0F);
        self.checking_disabled = (flags & (1 << 4)) > 0;
        self.authed_data = (flags & (1 << 5)) > 0;
        self.z = (flags & (1 << 6)) > 0;
        self.recursion_available = (flags & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }
    /// Write Dns packet header as bytes to buffer.
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), io::Error> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.opcode << 3)
                | ((self.response as u8) << 7) as u8,
        )?;

        buffer.write_u8(
            (self.rescode as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_header_from_buffer() {
        let mut buf = BytePacketBuffer::new();

        buf.buf[0] = 0x12;
        buf.buf[1] = 0x34;

        buf.buf[2] = 0b10010101; // flags: recursion_desired=1, truncated_message=0, authoritative_answer=1, opcode=2, response=1
        buf.buf[3] = 0b11100101; // flags: rescode=5, checking_disabled=0, authed_data=1, z=1, recursion_available=1

        buf.buf[4] = 0x00;
        buf.buf[5] = 0x01; // questions = 1
        buf.buf[6] = 0x00;
        buf.buf[7] = 0x02; // answers = 2
        buf.buf[8] = 0x00;
        buf.buf[9] = 0x03; // authoritative_entries = 3
        buf.buf[10] = 0x00;
        buf.buf[11] = 0x04; // resource_entries = 4

        let mut header = DnsHeader::new();
        assert!(header.read(&mut buf).is_ok());

        assert_eq!(header.id, 0x1234);
        assert_eq!(header.recursion_desired, true);
        assert_eq!(header.truncated_message, false);
        assert_eq!(header.authoritative_answer, true);
        assert_eq!(header.opcode, 2);
        assert_eq!(header.response, true);
        assert_eq!(header.rescode, ResultCode::REFUSED);
        assert_eq!(header.checking_disabled, false);
        assert_eq!(header.authed_data, true);
        assert_eq!(header.z, true);
        assert_eq!(header.recursion_available, true);
        assert_eq!(header.questions, 1);
        assert_eq!(header.answers, 2);
        assert_eq!(header.authoritative_entries, 3);
        assert_eq!(header.resource_entries, 4);
    }

    #[test]
    fn test_write_header_to_buffer() {
        let mut header = DnsHeader::new();
        header.id = 0x1234;
        header.recursion_desired = true;
        header.truncated_message = false;
        header.authoritative_answer = true;
        header.opcode = 2;
        header.response = true;
        header.rescode = ResultCode::REFUSED;
        header.checking_disabled = false;
        header.authed_data = true;
        header.z = true;
        header.recursion_available = true;
        header.questions = 1;
        header.answers = 2;
        header.authoritative_entries = 3;
        header.resource_entries = 4;

        let mut buf = BytePacketBuffer::new();
        assert!(header.write(&mut buf).is_ok());

        assert_eq!(buf.buf[0], 0x12);
        assert_eq!(buf.buf[1], 0x34); // id = 0x1234

        assert_eq!(buf.buf[2], 0b10010101);
        assert_eq!(buf.buf[3], 0b11100101);

        assert_eq!(buf.buf[4], 0x00);
        assert_eq!(buf.buf[5], 0x01); // questions = 1
        assert_eq!(buf.buf[6], 0x00);
        assert_eq!(buf.buf[7], 0x02); // answers = 2
        assert_eq!(buf.buf[8], 0x00);
        assert_eq!(buf.buf[9], 0x03); // authoritative_entries = 3
        assert_eq!(buf.buf[10], 0x00);
        assert_eq!(buf.buf[11], 0x04); // resource_entries = 4
    }

    #[test]
    fn test_read_write() {
        let mut header = DnsHeader::new();
        header.id = 0x4321;
        header.recursion_desired = true;
        header.truncated_message = true;
        header.authoritative_answer = true;
        header.opcode = 3;
        header.response = false;
        header.rescode = ResultCode::REFUSED;
        header.checking_disabled = true;
        header.authed_data = true;
        header.z = false;
        header.recursion_available = true;
        header.questions = 10;
        header.answers = 20;
        header.authoritative_entries = 30;
        header.resource_entries = 40;

        let mut buf = BytePacketBuffer::new();
        assert!(header.write(&mut buf).is_ok());

        let mut read_header = DnsHeader::new();
        assert!(buf.seek(0).is_ok());
        assert!(read_header.read(&mut buf).is_ok());
        println!("{read_header:?}");

        assert_eq!(header.id, read_header.id);
        assert_eq!(header.recursion_desired, read_header.recursion_desired);
        assert_eq!(header.truncated_message, read_header.truncated_message);
        assert_eq!(
            header.authoritative_answer,
            read_header.authoritative_answer
        );
        assert_eq!(header.opcode, read_header.opcode);
        assert_eq!(header.response, read_header.response);
        assert_eq!(header.rescode, read_header.rescode);
        assert_eq!(header.checking_disabled, read_header.checking_disabled);
        assert_eq!(header.authed_data, read_header.authed_data);
        assert_eq!(header.z, read_header.z);
        assert_eq!(header.recursion_available, read_header.recursion_available);
        assert_eq!(header.questions, read_header.questions);
        assert_eq!(header.answers, read_header.answers);
        assert_eq!(
            header.authoritative_entries,
            read_header.authoritative_entries
        );
        assert_eq!(header.resource_entries, read_header.resource_entries);
    }
}
