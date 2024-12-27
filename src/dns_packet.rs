use std::{io, net::Ipv4Addr};

use crate::{
    byte_packet_buffer::BytePacketBuffer, dns_header::DnsHeader, dns_question::DnsQuestion,
    dns_record::DnsRecord, query_types::QueryType,
};

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    /// Read complete Dns packet from BytePacketBuffer
    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket, io::Error> {
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = DnsRecord::read(buffer)?;
            result.answers.push(rec);
        }
        for _ in 0..result.header.authoritative_entries {
            let rec = DnsRecord::read(buffer)?;
            result.authorities.push(rec);
        }
        for _ in 0..result.header.resource_entries {
            let rec = DnsRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }

    /// Write complete Dns packet to BytePacketBuffer
    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), io::Error> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }
        for rec in &self.answers {
            rec.write(buffer)?;
        }
        for rec in &self.authorities {
            rec.write(buffer)?;
        }
        for rec in &self.resources {
            rec.write(buffer)?;
        }

        Ok(())
    }

    /// Get Random A to be able to pick a random A record from a packet. When we
    /// get multiple IP's for a single name, it doesn't matter which one we
    /// choose, so in those cases we can now pick one at random.
    pub fn get_random_a(&self) -> Option<Ipv4Addr> {
        self.answers
            .iter()
            .filter_map(|record| match record {
                DnsRecord::A { addr, .. } => Some(*addr),
                _ => None,
            })
            .next()
    }

    /// Get NS helper function which returns an iterator over all name servers in
    /// the authorities section, represented as (domain, host) tuples
    fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities
            .iter()
            .filter_map(|record| match record {
                DnsRecord::NS { domain, host, .. } => Some((domain.as_str(), host.as_str())),
                _ => None,
            })
            .filter(move |(domain, _)| qname.ends_with(*domain))
    }

    /// Get Resolved NS
    /// as We'll use the fact that name servers often bundle the corresponding
    /// A records when replying to an NS query to implement a function that
    /// returns the actual IP for an NS record if possible.
    pub fn get_resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
        self.get_ns(qname)
            .flat_map(|(_, host)| {
                self.resources
                    .iter()
                    .filter_map(move |record| match record {
                        DnsRecord::A { domain, addr, .. } if domain == host => Some(addr),
                        _ => None,
                    })
            })
            .map(|addr| *addr)
            .next()
    }

    /// Get Unresolved NS a method for returning the host
    /// name of an appropriate name server.
    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        self.get_ns(qname).map(|(_, host)| host).next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_and_read_dns_packet() {
        let mut buffer = BytePacketBuffer::new();
        let mut packet = DnsPacket::new();

        // Setup a DNS question
        let question = DnsQuestion::new("google.com".to_string(), QueryType::A);
        packet.questions.push(question);

        // Setup a DNS answer
        let answer = DnsRecord::A {
            domain: "google.com".to_string(),
            addr: Ipv4Addr::new(216, 58, 211, 142),
            ttl: 293,
        };
        packet.answers.push(answer);

        // Setup a DNS authority
        let authority = DnsRecord::NS {
            domain: "google.com".to_string(),
            host: "ns1.google.com".to_string(),
            ttl: 293,
        };
        packet.authorities.push(authority);

        // Setup a DNS resource
        let resource = DnsRecord::A {
            domain: "ns1.google.com".to_string(),
            addr: Ipv4Addr::new(8, 8, 8, 8),
            ttl: 293,
        };
        packet.resources.push(resource);

        packet
            .write(&mut buffer)
            .expect("Failed to write DNS packet");

        assert!(buffer.seek(0).is_ok());

        let read_packet = DnsPacket::from_buffer(&mut buffer).expect("Failed to read DNS packet");

        // Validate the read packet
        assert_eq!(read_packet.questions.len(), 1);
        assert_eq!(read_packet.answers.len(), 1);
        assert_eq!(read_packet.authorities.len(), 1);
        assert_eq!(read_packet.resources.len(), 1);

        // Validate the question
        match &read_packet.questions[0] {
            DnsQuestion { name, qtype, .. } => {
                assert_eq!(name, "google.com");
                assert_eq!(qtype, &QueryType::A);
            }
        }

        // Validate the answer
        match &read_packet.answers[0] {
            DnsRecord::A { domain, addr, ttl } => {
                assert_eq!(domain, "google.com");
                assert_eq!(addr, &Ipv4Addr::new(216, 58, 211, 142));
                assert_eq!(*ttl, 293);
            }
            _ => panic!("Expected A record"),
        }

        // Validate the authority
        match &read_packet.authorities[0] {
            DnsRecord::NS { domain, host, ttl } => {
                assert_eq!(domain, "google.com");
                assert_eq!(host, "ns1.google.com");
                assert_eq!(*ttl, 293);
            }
            _ => panic!("Expected NS record"),
        }

        // Validate the resource
        match &read_packet.resources[0] {
            DnsRecord::A { domain, addr, ttl } => {
                assert_eq!(domain, "ns1.google.com");
                assert_eq!(addr, &Ipv4Addr::new(8, 8, 8, 8));
                assert_eq!(*ttl, 293);
            }
            _ => panic!("Expected A record"),
        }
    }

    #[test]
    fn test_get_random_a() {
        let mut packet = DnsPacket::new();
        packet.answers.push(DnsRecord::A {
            domain: "google.com".to_string(),
            addr: Ipv4Addr::new(216, 58, 211, 142),
            ttl: 293,
        });
        packet.answers.push(DnsRecord::A {
            domain: "example.com".to_string(),
            addr: Ipv4Addr::new(93, 184, 216, 34),
            ttl: 293,
        });

        let random_a = packet.get_random_a();
        assert!(random_a.is_some());
        let random_a = random_a.unwrap();
        assert!(
            random_a == Ipv4Addr::new(216, 58, 211, 142)
                || random_a == Ipv4Addr::new(93, 184, 216, 34)
        );
    }

    #[test]
    fn test_get_resolved_ns() {
        let mut packet = DnsPacket::new();
        packet.authorities.push(DnsRecord::NS {
            domain: "google.com".to_string(),
            host: "ns1.google.com".to_string(),
            ttl: 293,
        });
        packet.resources.push(DnsRecord::A {
            domain: "ns1.google.com".to_string(),
            addr: Ipv4Addr::new(8, 8, 8, 8),
            ttl: 293,
        });

        let resolved_ns = packet.get_resolved_ns("google.com");
        assert_eq!(resolved_ns, Some(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn test_get_unresolved_ns() {
        let mut packet = DnsPacket::new();
        packet.authorities.push(DnsRecord::NS {
            domain: "google.com".to_string(),
            host: "ns1.google.com".to_string(),
            ttl: 293,
        });

        let unresolved_ns = packet.get_unresolved_ns("google.com");
        assert_eq!(unresolved_ns, Some("ns1.google.com"));
    }
}
