use clap::Parser;
use std::{io, net::UdpSocket};

#[derive(Parser)]
#[command(name = "DnsServerApp")]
#[command(version = "1.0")]
#[command(about = "A simple DNS server application", long_about = None)]
struct Args {
    /// Port to bind the UDP socket
    #[arg(short, long, default_value_t = 2053)]
    port: u16,
    /// forward replies to specified dns server
    #[arg(short, long, default_value = None)]
    forward_ip: Option<String>,
}

fn main() -> Result<(), io::Error> {
    let args = Args::parse();
    // Bind an UDP socket on port
    let socket = UdpSocket::bind(("0.0.0.0", args.port))?;
    println!("Server listening on port {}", args.port);

    // For now, queries are handled sequentially, so an infinite loop for servicing
    // requests is initiated.
    loop {
        match dnsserver_nabil::handle_query(&socket, &args.forward_ip) {
            Ok(_) => {}
            Err(e) => eprintln!("An error occurred: {}", e),
        }
    }
}
