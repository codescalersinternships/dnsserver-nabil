use std::io::{self, Error};

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer {
    /// This gives us a fresh buffer for holding the packet contents, and a
    /// field for keeping track of where we are.
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    /// Current position within buffer
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Step the buffer position forward a specific number of steps
    pub fn step(&mut self, steps: usize) -> Result<(), io::Error> {
        if self.pos + steps >= 512 {
            return Err(Error::new(io::ErrorKind::UnexpectedEof, "End of buffer"));
        }
        self.pos += steps;
        Ok(())
    }

    /// Change the buffer position
    pub fn seek(&mut self, pos: usize) -> Result<(), io::Error> {
        if pos >= 512 {
            return Err(Error::new(io::ErrorKind::UnexpectedEof, "End of buffer"));
        }
        self.pos = pos;
        Ok(())
    }

    /// Read a single byte and move the position one step forward
    pub fn read(&mut self) -> Result<u8, io::Error> {
        if self.pos >= 512 {
            return Err(Error::new(io::ErrorKind::UnexpectedEof, "End of buffer"));
        }
        let res = self.buf[self.pos];
        self.pos += 1;
        Ok(res)
    }

    /// Get a single byte, without changing the buffer position
    pub fn get(&self, pos: usize) -> Result<u8, io::Error> {
        if pos >= 512 {
            return Err(Error::new(io::ErrorKind::UnexpectedEof, "End of buffer"));
        }
        Ok(self.buf[pos])
    }

    /// Get a range of bytes
    pub fn get_range(&self, start: usize, len: usize) -> Result<&[u8], io::Error> {
        if start + len > 512 {
            return Err(Error::new(io::ErrorKind::UnexpectedEof, "End of buffer"));
        }
        Ok(&self.buf[start..(start + len)])
    }

    /// Read two bytes, stepping two steps forward
    pub fn read_u16(&mut self) -> Result<u16, io::Error> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);
        Ok(res)
    }

    /// Read four bytes, stepping four steps forward
    pub fn read_u32(&mut self) -> Result<u32, io::Error> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);

        Ok(res)
    }

    /// Read a qname
    ///
    /// Will take something like [3]www[6]google[3]com[0] and append
    /// www.google.com to outstr.
    ///
    /// also it handle jemps .
    pub fn read_qname(&mut self, outstr: &mut String) -> Result<(), io::Error> {
        let mut pos = self.pos();
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;
        let mut delim = "";
        loop {
            if jumps_performed > max_jumps {
                return Err(Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("Limit of {} jumps exceeded", max_jumps),
                ));
            }

            let len = self.get(pos)?;

            if (len & 0xC0) == 0xC0 {
                if !jumped {
                    self.seek(pos + 2)?
                }

                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                jumped = true;
                jumps_performed += 1;
            } else {
                pos += 1;

                if len == 0 {
                    break;
                }
                outstr.push_str(delim);
                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";
                pos += len as usize;
            }
        }
        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }

    /// Write a single byte and move the position one step forward
    pub fn write(&mut self, val: u8) -> Result<(), io::Error> {
        if self.pos >= 512 {
            return Err(Error::new(io::ErrorKind::UnexpectedEof, "End of buffer"));
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    /// Read a single byte and move the position one step forward
    pub fn write_u8(&mut self, val: u8) -> Result<(), io::Error> {
        self.write(val)?;

        Ok(())
    }

    /// Read a two bytes and move the position two steps forward
    pub fn write_u16(&mut self, val: u16) -> Result<(), io::Error> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    /// Write four bytes, stepping four steps forward
    pub fn write_u32(&mut self, val: u32) -> Result<(), io::Error> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write(((val >> 0) & 0xFF) as u8)?;

        Ok(())
    }

    /// Write a qname
    ///
    /// Will take something like www.google.com
    ///
    /// dots are the separator used
    pub fn write_qname(&mut self, qname: &str) -> Result<(), io::Error> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 0x3f {
                return Err(Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Single label exceeds 63 characters of length",
                ));
            }

            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        self.write_u8(0)?;

        Ok(())
    }

    /// Write a single byte, without changing the buffer position
    pub fn set(&mut self, pos: usize, val: u8) -> Result<(), io::Error> {
        if pos >= 512 {
            return Err(Error::new(io::ErrorKind::UnexpectedEof, "End of buffer"));
        }
        self.buf[pos] = val;

        Ok(())
    }

    /// Get two bytes, without changing the buffer position
    pub fn set_u16(&mut self, pos: usize, val: u16) -> Result<(), io::Error> {
        self.set(pos, (val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_initial_position() {
        let buf = BytePacketBuffer::new();
        assert_eq!(buf.pos(), 0);
    }

    #[test]
    fn test_pos_step_seek_limit() {
        let mut buf = BytePacketBuffer::new();
        assert!(buf.step(511).is_ok());
        assert_eq!(buf.pos(), 511);
        assert!(buf.step(1).is_err());
        assert!(buf.seek(511).is_ok());
        assert!(buf.seek(512).is_err());
    }

    #[test]
    fn test_read_write_limits() {
        let mut buf = BytePacketBuffer::new();

        // Test reading at limit
        assert!(buf.seek(511).is_ok());
        assert!(buf.read().is_ok());
        assert!(buf.read().is_err());

        // Test writing at limit
        assert!(buf.seek(511).is_ok());
        assert!(buf.write(0xFF).is_ok());
        assert!(buf.write(0xFF).is_err());
        assert_eq!(buf.buf[511], 0xFF);
    }

    #[test]
    fn test_read_u16_u32() {
        let mut buf = BytePacketBuffer::new();
        buf.buf[0] = 0x12;
        buf.buf[1] = 0x34;
        buf.buf[2] = 0x56;
        buf.buf[3] = 0x78;

        assert_eq!(buf.read_u16().unwrap(), 0x1234);
        assert!(buf.seek(0).is_ok());
        assert_eq!(buf.read_u32().unwrap(), 0x12345678);
    }

    #[test]
    fn test_set_get() {
        let mut buf = BytePacketBuffer::new();
        assert!(buf.set(511, 0xAB).is_ok());
        assert_eq!(buf.get(511).unwrap(), 0xAB);
        assert!(buf.set(512, 0xAB).is_err());
    }

    #[test]
    fn test_read_qname_no_jump() {
        let mut buf = BytePacketBuffer::new();
        buf.buf[0] = 3;
        buf.buf[1] = b'w';
        buf.buf[2] = b'w';
        buf.buf[3] = b'w';
        buf.buf[4] = 6;
        buf.buf[5] = b'g';
        buf.buf[6] = b'o';
        buf.buf[7] = b'o';
        buf.buf[8] = b'g';
        buf.buf[9] = b'l';
        buf.buf[10] = b'e';
        buf.buf[11] = 3;
        buf.buf[12] = b'c';
        buf.buf[13] = b'o';
        buf.buf[14] = b'm';
        buf.buf[15] = 0;

        let mut outstr = String::new();
        assert!(buf.read_qname(&mut outstr).is_ok());
        assert_eq!(outstr, "www.google.com");
    }

    #[test]
    fn test_read_qname_with_single_jump() {
        let mut buf = BytePacketBuffer::new();
        buf.buf[20] = 3;
        buf.buf[21] = b'w';
        buf.buf[22] = b'w';
        buf.buf[23] = b'w';
        buf.buf[24] = 6;
        buf.buf[25] = b'g';
        buf.buf[26] = b'o';
        buf.buf[27] = b'o';
        buf.buf[28] = b'g';
        buf.buf[29] = b'l';
        buf.buf[30] = b'e';
        buf.buf[31] = 3;
        buf.buf[32] = b'c';
        buf.buf[33] = b'o';
        buf.buf[34] = b'm';
        buf.buf[35] = 0;

        buf.buf[0] = 0xC0;
        buf.buf[1] = 20;

        let mut outstr = String::new();
        assert!(buf.read_qname(&mut outstr).is_ok());
        assert_eq!(outstr, "www.google.com");
    }

    #[test]
    fn test_read_qname_with_multiple_jumps() {
        let mut buf = BytePacketBuffer::new();
        // "google.com" at position 20
        buf.buf[20] = 6;
        buf.buf[21] = b'g';
        buf.buf[22] = b'o';
        buf.buf[23] = b'o';
        buf.buf[24] = b'g';
        buf.buf[25] = b'l';
        buf.buf[26] = b'e';
        buf.buf[27] = 3;
        buf.buf[28] = b'c';
        buf.buf[29] = b'o';
        buf.buf[30] = b'm';
        buf.buf[31] = 0;

        // "www" at position 50
        buf.buf[50] = 3;
        buf.buf[51] = b'w';
        buf.buf[52] = b'w';
        buf.buf[53] = b'w';
        buf.buf[54] = 0xC0; // Pointer to "google.com"
        buf.buf[55] = 20;

        // Pointer to "www" at start
        buf.buf[0] = 0xC0;
        buf.buf[1] = 50;

        let mut outstr = String::new();
        assert!(buf.read_qname(&mut outstr).is_ok());
        assert_eq!(outstr, "www.google.com");
    }

    #[test]
    fn test_write_qname_success() {
        let mut buf = BytePacketBuffer::new();
        assert!(buf.write_qname("www.google.com").is_ok());

        let mut outstr = String::new();
        assert!(buf.seek(0).is_ok());
        assert!(buf.read_qname(&mut outstr).is_ok());
        assert_eq!(outstr, "www.google.com");
    }

    #[test]
    fn test_write_qname_overflow() {
        let mut buf = BytePacketBuffer::new();
        assert!(buf.seek(510).is_ok());
        assert!(buf.write_qname("a").is_err());
    }
}
