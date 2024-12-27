use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
};

use crate::{byte_packet_buffer::BytePacketBuffer, QueryType};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    }, // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    }, // 1
    NS {
        domain: String,
        host: String,
        ttl: u32,
    }, // 2
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    }, // 5
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    }, // 15
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    }, // 28
}

impl DnsRecord {
    /// Read Dns record (Answer Section - Authority Section - Additional Section)
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord, io::Error> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr >> 0) & 0xFF) as u8,
                );

                Ok(DnsRecord::A { domain, addr, ttl })
            }
            QueryType::AAAA => {
                let raw_addr1 = buffer.read_u32()?;
                let raw_addr2 = buffer.read_u32()?;
                let raw_addr3 = buffer.read_u32()?;
                let raw_addr4 = buffer.read_u32()?;
                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    ((raw_addr1 >> 0) & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    ((raw_addr2 >> 0) & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    ((raw_addr3 >> 0) & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    ((raw_addr4 >> 0) & 0xFFFF) as u16,
                );

                Ok(DnsRecord::AAAA { domain, addr, ttl })
            }
            QueryType::NS => {
                let mut ns = String::new();
                buffer.read_qname(&mut ns)?;

                Ok(DnsRecord::NS {
                    domain,
                    host: ns,
                    ttl,
                })
            }
            QueryType::CNAME => {
                let mut cname = String::new();
                buffer.read_qname(&mut cname)?;

                Ok(DnsRecord::CNAME {
                    domain,
                    host: cname,
                    ttl,
                })
            }
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let mut mx = String::new();
                buffer.read_qname(&mut mx)?;

                Ok(DnsRecord::MX {
                    domain,
                    priority: priority,
                    host: mx,
                    ttl,
                })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize)?;

                Ok(DnsRecord::UNKNOWN {
                    domain,
                    qtype: qtype_num,
                    data_len: data_len,
                    ttl,
                })
            }
        }
    }

    /// Write Dns record (Answer Section - Authority Section - Additional Section)
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize, io::Error> {
        let start_pos = buffer.pos();

        match *self {
            DnsRecord::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;

                let octets = addr.octets();
                buffer.write_u8(octets[0])?;
                buffer.write_u8(octets[1])?;
                buffer.write_u8(octets[2])?;
                buffer.write_u8(octets[3])?;
            }
            DnsRecord::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NS.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::CNAME.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::MX.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_u16(priority)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::AAAA {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::AAAA.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(16)?;

                for octet in &addr.segments() {
                    buffer.write_u16(*octet)?;
                }
            }
            DnsRecord::UNKNOWN { .. } => {
                println!("Skipping record: {:?}", self);
            }
        }

        Ok(buffer.pos() - start_pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_a_record() {
        let mut buf = BytePacketBuffer::new();

        buf.buf[0] = 6;
        buf.buf[1..7].copy_from_slice(b"google");
        buf.buf[7] = 3;
        buf.buf[8..11].copy_from_slice(b"com");
        buf.buf[11] = 0;
        buf.buf[12] = 0x00;
        buf.buf[13] = 0x01; // qtype A
        buf.buf[14] = 0x00;
        buf.buf[15] = 0x01; // class IN
        buf.buf[16] = 0x00;
        buf.buf[17] = 0x00;
        buf.buf[18] = 0x01;
        buf.buf[19] = 0x25; // ttl = 293
        buf.buf[20] = 0x00;
        buf.buf[21] = 0x04; // data_len = 4 (IPv4 length)
        buf.buf[22] = 0xd8; // 216.58.211.142
        buf.buf[23] = 0x3a;
        buf.buf[24] = 0xd3;
        buf.buf[25] = 0x8e;

        let record = DnsRecord::read(&mut buf).expect("Failed to read A record");

        match record {
            DnsRecord::A { domain, addr, ttl } => {
                assert_eq!(domain, "google.com");
                assert_eq!(addr, Ipv4Addr::new(216, 58, 211, 142));
                assert_eq!(ttl, 293);
            }
            _ => panic!("Record is not of type A"),
        }
    }

    #[test]
    fn test_write_a_record() {
        let record = DnsRecord::A {
            domain: "google.com".to_string(),
            addr: Ipv4Addr::new(216, 58, 211, 142),
            ttl: 293,
        };

        let mut buf = BytePacketBuffer::new();
        record.write(&mut buf).expect("Failed to write A record");

        assert_eq!(buf.buf[0], 6);
        assert_eq!(&buf.buf[1..7], b"google");
        assert_eq!(buf.buf[7], 3);
        assert_eq!(&buf.buf[8..11], b"com");
        assert_eq!(buf.buf[11], 0);
        assert_eq!(buf.buf[12], 0x00);
        assert_eq!(buf.buf[13], 0x01); // qtype A
        assert_eq!(buf.buf[14], 0x00);
        assert_eq!(buf.buf[15], 0x01); // class IN
        assert_eq!(buf.buf[16], 0x00);
        assert_eq!(buf.buf[17], 0x00);
        assert_eq!(buf.buf[18], 0x01);
        assert_eq!(buf.buf[19], 0x25); // ttl = 293
        assert_eq!(buf.buf[20], 0x00);
        assert_eq!(buf.buf[21], 0x04); // data_len = 4
        assert_eq!(&buf.buf[22..26], &[216, 58, 211, 142]);
    }

    #[test]
    fn test_a_record() {
        let record = DnsRecord::A {
            domain: "google.com".to_string(),
            addr: Ipv4Addr::new(216, 58, 211, 142),
            ttl: 293,
        };

        let mut buf = BytePacketBuffer::new();
        record.write(&mut buf).expect("Failed to write A record");
        assert!(buf.seek(0).is_ok());
        let read_record = DnsRecord::read(&mut buf).expect("Failed to read A record");

        assert_eq!(record, read_record);
    }

    #[test]
    fn test_read_aaaa_record() {
        let mut buf = BytePacketBuffer::new();

        buf.buf[0] = 6;
        buf.buf[1..7].copy_from_slice(b"google");
        buf.buf[7] = 3;
        buf.buf[8..11].copy_from_slice(b"com");
        buf.buf[11] = 0;
        buf.buf[12] = 0x00;
        buf.buf[13] = 0x1C; // qtype AAAA
        buf.buf[14] = 0x00;
        buf.buf[15] = 0x01; // class IN
        buf.buf[16] = 0x00;
        buf.buf[17] = 0x00;
        buf.buf[18] = 0x01;
        buf.buf[19] = 0x25; // ttl = 293
        buf.buf[20] = 0x00;
        buf.buf[21] = 0x10; // data_len = 16 (IPv6 length)
        buf.buf[22..38].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);

        let record = DnsRecord::read(&mut buf).expect("Failed to read AAAA record");

        match record {
            DnsRecord::AAAA { domain, addr, ttl } => {
                assert_eq!(domain, "google.com");
                assert_eq!(
                    addr,
                    Ipv6Addr::new(0x2001, 0xdb8, 0x0010, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001,)
                );
                assert_eq!(ttl, 293);
            }
            _ => panic!("Record is not of type AAAA"),
        }
    }

    #[test]
    fn test_write_aaaa_record() {
        let record = DnsRecord::AAAA {
            domain: "google.com".to_string(),
            addr: Ipv6Addr::new(
                0x2001, 0xdb8, 0x0010, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001,
            ),
            ttl: 293,
        };

        let mut buf = BytePacketBuffer::new();
        record.write(&mut buf).expect("Failed to write AAAA record");

        assert_eq!(buf.buf[0], 6);
        assert_eq!(&buf.buf[1..7], b"google");
        assert_eq!(buf.buf[7], 3);
        assert_eq!(&buf.buf[8..11], b"com");
        assert_eq!(buf.buf[11], 0);
        assert_eq!(buf.buf[12], 0x00);
        assert_eq!(buf.buf[13], 0x1C); // qtype AAAA
        assert_eq!(buf.buf[14], 0x00);
        assert_eq!(buf.buf[15], 0x01); // class IN
        assert_eq!(buf.buf[16], 0x00);
        assert_eq!(buf.buf[17], 0x00);
        assert_eq!(buf.buf[18], 0x01);
        assert_eq!(buf.buf[19], 0x25); // ttl = 293
        assert_eq!(buf.buf[20], 0x00);
        assert_eq!(buf.buf[21], 0x10); // data_len = 16
        assert_eq!(
            &buf.buf[22..38],
            &[
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ]
        );
    }

    #[test]
    fn test_aaaa_record() {
        let record = DnsRecord::AAAA {
            domain: "google.com".to_string(),
            addr: Ipv6Addr::new(
                0x2001, 0xdb8, 0x0010, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001,
            ),
            ttl: 293,
        };

        let mut buf = BytePacketBuffer::new();
        record.write(&mut buf).expect("Failed to write AAAA record");
        assert!(buf.seek(0).is_ok());
        let read_record = DnsRecord::read(&mut buf).expect("Failed to read AAAA record");

        assert_eq!(record, read_record);
    }

    #[test]
    fn test_read_cname_record() {
        let mut buf = BytePacketBuffer::new();

        buf.buf[0] = 6;
        buf.buf[1..7].copy_from_slice(b"google");
        buf.buf[7] = 3;
        buf.buf[8..11].copy_from_slice(b"com");
        buf.buf[11] = 0;
        buf.buf[12] = 0x00;
        buf.buf[13] = 0x05; // qtype CNAME
        buf.buf[14] = 0x00;
        buf.buf[15] = 0x01; // class IN
        buf.buf[16] = 0x00;
        buf.buf[17] = 0x00;
        buf.buf[18] = 0x01;
        buf.buf[19] = 0x25; // ttl = 293
        buf.buf[20] = 0x00;
        buf.buf[21] = 0x05; // data_len = 3
        buf.buf[22] = 0x03;
        buf.buf[23..26].copy_from_slice(b"www");

        let record = DnsRecord::read(&mut buf).expect("Failed to read CNAME record");

        match record {
            DnsRecord::CNAME { domain, host, ttl } => {
                assert_eq!(domain, "google.com");
                assert_eq!(host, "www");
                assert_eq!(ttl, 293);
            }
            _ => panic!("Record is not of type CNAME"),
        }
    }

    #[test]
    fn test_write_cname_record() {
        let record = DnsRecord::CNAME {
            domain: "google.com".to_string(),
            host: "www".to_string(),
            ttl: 293,
        };

        let mut buf = BytePacketBuffer::new();
        record
            .write(&mut buf)
            .expect("Failed to write CNAME record");

        assert_eq!(buf.buf[0], 6);
        assert_eq!(&buf.buf[1..7], b"google");
        assert_eq!(buf.buf[7], 3);
        assert_eq!(&buf.buf[8..11], b"com");
        assert_eq!(buf.buf[11], 0);
        assert_eq!(buf.buf[12], 0x00);
        assert_eq!(buf.buf[13], 0x05); // qtype CNAME
        assert_eq!(buf.buf[14], 0x00);
        assert_eq!(buf.buf[15], 0x01); // class IN
        assert_eq!(buf.buf[16], 0x00);
        assert_eq!(buf.buf[17], 0x00);
        assert_eq!(buf.buf[18], 0x01);
        assert_eq!(buf.buf[19], 0x25); // ttl = 293
        assert_eq!(buf.buf[20], 0x00);
        assert_eq!(buf.buf[21], 0x05); // data_len = 3
        assert_eq!(buf.buf[22], 3);
        assert_eq!(&buf.buf[23..26], b"www");
    }

    #[test]
    fn test_cname_record() {
        let record = DnsRecord::CNAME {
            domain: "google.com".to_string(),
            host: "www".to_string(),
            ttl: 293,
        };

        let mut buf = BytePacketBuffer::new();
        record
            .write(&mut buf)
            .expect("Failed to write CNAME record");
        assert!(buf.seek(0).is_ok());
        let read_record = DnsRecord::read(&mut buf).expect("Failed to read CNAME record");

        assert_eq!(record, read_record);
    }

    #[test]
    fn test_read_mx_record() {
        let mut buf = BytePacketBuffer::new();

        buf.buf[0] = 6;
        buf.buf[1..7].copy_from_slice(b"google");
        buf.buf[7] = 3;
        buf.buf[8..11].copy_from_slice(b"com");
        buf.buf[11] = 0;
        buf.buf[12] = 0x00;
        buf.buf[13] = 0x0F; // qtype MX
        buf.buf[14] = 0x00;
        buf.buf[15] = 0x01; // class IN
        buf.buf[16] = 0x00;
        buf.buf[17] = 0x00;
        buf.buf[18] = 0x01;
        buf.buf[19] = 0x25; // ttl = 293
        buf.buf[20] = 0x00;
        buf.buf[21] = 0x09; // data_len = 9
        buf.buf[22] = 0x00;
        buf.buf[23] = 0x0A; // priority = 10
        buf.buf[24] = 0x03;
        buf.buf[25..28].copy_from_slice(b"mx1");
        buf.buf[28] = 3;
        buf.buf[29..32].copy_from_slice(b"com");
        buf.buf[32] = 0;

        let record = DnsRecord::read(&mut buf).expect("Failed to read MX record");

        match record {
            DnsRecord::MX {
                domain,
                priority,
                host,
                ttl,
            } => {
                assert_eq!(domain, "google.com");
                assert_eq!(priority, 10);
                assert_eq!(host, "mx1.com");
                assert_eq!(ttl, 293);
            }
            _ => panic!("Record is not of type MX"),
        }
    }

    #[test]
    fn test_write_mx_record() {
        let record = DnsRecord::MX {
            domain: "google.com".to_string(),
            priority: 10,
            host: "mx1.com".to_string(),
            ttl: 293,
        };

        let mut buf = BytePacketBuffer::new();
        record.write(&mut buf).expect("Failed to write MX record");

        assert_eq!(buf.buf[0], 6);
        assert_eq!(&buf.buf[1..7], b"google");
        assert_eq!(buf.buf[7], 3);
        assert_eq!(&buf.buf[8..11], b"com");
        assert_eq!(buf.buf[11], 0);
        assert_eq!(buf.buf[12], 0x00);
        assert_eq!(buf.buf[13], 0x0F); // qtype MX
        assert_eq!(buf.buf[14], 0x00);
        assert_eq!(buf.buf[15], 0x01); // class IN
        assert_eq!(buf.buf[16], 0x00);
        assert_eq!(buf.buf[17], 0x00);
        assert_eq!(buf.buf[18], 0x01);
        assert_eq!(buf.buf[19], 0x25); // ttl = 293
        assert_eq!(buf.buf[20], 0x00);
        assert_eq!(buf.buf[21], 0x0b); // data_len = 9
        assert_eq!(buf.buf[22], 0x00);
        assert_eq!(buf.buf[23], 0x0A); // priority = 10
        assert_eq!(buf.buf[24], 0x03);
        assert_eq!(&buf.buf[25..28], b"mx1");
        assert_eq!(buf.buf[28], 3);
        assert_eq!(&buf.buf[29..32], b"com");
        assert_eq!(buf.buf[32], 0);
    }

    #[test]
    fn test_mx_record() {
        let record = DnsRecord::MX {
            domain: "google.com".to_string(),
            priority: 10,
            host: "mx1.com".to_string(),
            ttl: 293,
        };

        let mut buf = BytePacketBuffer::new();
        record.write(&mut buf).expect("Failed to write MX record");
        assert!(buf.seek(0).is_ok());
        let read_record = DnsRecord::read(&mut buf).expect("Failed to read MX record");

        assert_eq!(record, read_record);
    }

    #[test]
    fn test_read_ns_record() {
        let mut buf = BytePacketBuffer::new();

        buf.buf[0] = 6;
        buf.buf[1..7].copy_from_slice(b"google");
        buf.buf[7] = 3;
        buf.buf[8..11].copy_from_slice(b"com");
        buf.buf[11] = 0;
        buf.buf[12] = 0x00;
        buf.buf[13] = 0x02; // qtype NS
        buf.buf[14] = 0x00;
        buf.buf[15] = 0x01; // class IN
        buf.buf[16] = 0x00;
        buf.buf[17] = 0x00;
        buf.buf[18] = 0x01;
        buf.buf[19] = 0x25; // ttl = 293
        buf.buf[20] = 0x00;
        buf.buf[21] = 0x09; // data_len = 9
        buf.buf[22] = 0x03;
        buf.buf[23..26].copy_from_slice(b"ns1");
        buf.buf[26] = 3;
        buf.buf[27..30].copy_from_slice(b"com");
        buf.buf[30] = 0;

        let record = DnsRecord::read(&mut buf).expect("Failed to read NS record");

        match record {
            DnsRecord::NS { domain, host, ttl } => {
                assert_eq!(domain, "google.com");
                assert_eq!(host, "ns1.com");
                assert_eq!(ttl, 293);
            }
            _ => panic!("Record is not of type NS"),
        }
    }

    #[test]
    fn test_write_ns_record() {
        let record = DnsRecord::NS {
            domain: "google.com".to_string(),
            host: "ns1.com".to_string(),
            ttl: 293,
        };

        let mut buf = BytePacketBuffer::new();
        record.write(&mut buf).expect("Failed to write NS record");

        assert_eq!(buf.buf[0], 6);
        assert_eq!(&buf.buf[1..7], b"google");
        assert_eq!(buf.buf[7], 3);
        assert_eq!(&buf.buf[8..11], b"com");
        assert_eq!(buf.buf[11], 0);
        assert_eq!(buf.buf[12], 0x00);
        assert_eq!(buf.buf[13], 0x02); // qtype NS
        assert_eq!(buf.buf[14], 0x00);
        assert_eq!(buf.buf[15], 0x01); // class IN
        assert_eq!(buf.buf[16], 0x00);
        assert_eq!(buf.buf[17], 0x00);
        assert_eq!(buf.buf[18], 0x01);
        assert_eq!(buf.buf[19], 0x25); // ttl = 293
        assert_eq!(buf.buf[20], 0x00);
        assert_eq!(buf.buf[21], 0x09); // data_len = 9
        assert_eq!(buf.buf[22], 0x03);
        assert_eq!(&buf.buf[23..26], b"ns1");
        assert_eq!(buf.buf[26], 3);
        assert_eq!(&buf.buf[27..30], b"com");
        assert_eq!(buf.buf[30], 0);
    }

    #[test]
    fn test_ns_record() {
        let record = DnsRecord::NS {
            domain: "google.com".to_string(),
            host: "ns1.com".to_string(),
            ttl: 293,
        };

        let mut buf = BytePacketBuffer::new();
        record.write(&mut buf).expect("Failed to write NS record");
        assert!(buf.seek(0).is_ok());
        let read_record = DnsRecord::read(&mut buf).expect("Failed to read NS record");

        assert_eq!(record, read_record);
    }
}
