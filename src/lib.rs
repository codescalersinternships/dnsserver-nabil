use std::{
    io::{self},
    net::{Ipv4Addr, UdpSocket},
};
mod byte_packet_buffer;
mod dns_header;
mod dns_packet;
mod dns_question;
mod dns_record;
mod query_types;
use {
    byte_packet_buffer::BytePacketBuffer, dns_header::ResultCode, dns_packet::DnsPacket,
    dns_question::DnsQuestion, query_types::QueryType,
};

fn recursive_lookup(
    qname: &str,
    qtype: QueryType,
    root_ip: &Option<String>,
) -> Result<DnsPacket, io::Error> {
    // For now we're always starting with *a.root-servers.net* if no forwarding ip specified.
    let mut ns = match root_ip {
        Some(ip) => ip,
        None => "198.41.0.4",
    }
    .parse::<Ipv4Addr>()
    .unwrap();

    loop {
        println!("attempting lookup of {:?} {} with ns {}", qtype, qname, ns);

        let ns_copy = ns;

        let server = (ns_copy, 53);
        let response = lookup(qname, qtype, server)?;

        if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
            return Ok(response);
        }

        if response.header.rescode == ResultCode::NXDOMAIN {
            return Ok(response);
        }

        if let Some(new_ns) = response.get_resolved_ns(qname) {
            ns = new_ns;

            continue;
        }

        let new_ns_name = match response.get_unresolved_ns(qname) {
            Some(x) => x,
            None => return Ok(response),
        };

        let recursive_response = recursive_lookup(&new_ns_name, QueryType::A, root_ip)?;

        if let Some(new_ns) = recursive_response.get_random_a() {
            ns = new_ns;
        } else {
            return Ok(response);
        }
    }
}

fn lookup(qname: &str, qtype: QueryType, server: (Ipv4Addr, u16)) -> Result<DnsPacket, io::Error> {
    let socket = UdpSocket::bind(("0.0.0.0", 49152))?;

    let mut packet = DnsPacket::new();

    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;
    socket.send_to(&req_buffer.get_range(0, req_buffer.pos() + 1)?, server)?;

    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf)?;

    DnsPacket::from_buffer(&mut res_buffer)
}

/// Handle query
/// function handles an incoming DNS query from a UDP socket
/// and formulates an appropriate DNS response,
/// either answering directly or using recursive resolution to obtain the necessary data
pub fn handle_query(socket: &UdpSocket, root_ip: &Option<String>) -> Result<(), io::Error> {
    let mut req_buffer = BytePacketBuffer::new();

    let (_, src) = socket.recv_from(&mut req_buffer.buf)?;

    let mut request = DnsPacket::from_buffer(&mut req_buffer)?;

    let mut packet = DnsPacket::new();
    packet.header.id = request.header.id;
    packet.header.recursion_desired = true;
    packet.header.recursion_available = true;
    packet.header.response = true;

    if let Some(question) = request.questions.pop() {
        println!("Received query: {:?}", question);
        if let Ok(result) = recursive_lookup(&question.name, question.qtype, root_ip) {
            packet.questions.push(question.clone());
            packet.header.rescode = result.header.rescode;

            for rec in result.answers {
                println!("Answer: {:?}", rec);
                packet.answers.push(rec);
            }
            for rec in result.authorities {
                println!("Authority: {:?}", rec);
                packet.authorities.push(rec);
            }
            for rec in result.resources {
                println!("Resource: {:?}", rec);
                packet.resources.push(rec);
            }
        } else {
            packet.header.rescode = ResultCode::SERVFAIL;
        }
    } else {
        packet.header.rescode = ResultCode::FORMERR;
    }

    let mut res_buffer = BytePacketBuffer::new();
    packet.write(&mut res_buffer)?;

    let len = res_buffer.pos();
    let data = res_buffer.get_range(0, len)?;

    socket.send_to(data, src)?;

    Ok(())
}
