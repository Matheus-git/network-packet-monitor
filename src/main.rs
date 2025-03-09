use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::datalink::{self, Channel};
use pnet::packet::Packet;
use std::net::{IpAddr, Ipv4Addr};
use trust_dns_resolver::Resolver;
use chrono::{DateTime, Local};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    datalink_receive();
    Ok(())
}

fn datalink_receive() {
    let interface_name = "enp61s0".to_string();
    let interfaces = datalink::interfaces();

    let interface = interfaces.into_iter().find(|iface| iface.name == interface_name).unwrap();
    println!("Interface: {:?}", interface);

    let mac_address = interface.mac.unwrap_or_default();
    println!("MAC address: {}", mac_address);

    let local_ip = interface.ips.iter().filter_map(|ip| {
        if let IpAddr::V4(ipv4) = ip.ip() {
            Some(ipv4)
        } else {
            None
        }
    }).next().unwrap_or_else(|| Ipv4Addr::new(0, 0, 0, 0));

    let resolver = Resolver::new(Default::default(), Default::default()).unwrap();

    let ( _, mut rxd) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(txd, rxd)) => (txd, rxd),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Error creating datalink channel: {}", e),
    };

    loop {
        match rxd.next() {
            Ok(packet) => {
                let ethernet_packet = EthernetPacket::new(packet).unwrap();
                if ethernet_packet.get_ethertype() == EtherTypes::Ipv4 {
                    if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
                        let source_ip = ipv4_packet.get_source();
                        let dest_ip = ipv4_packet.get_destination();

                        if source_ip != local_ip {
                            let timestamp = get_formatted_timestamp();
                            let domain = resolve_ip_to_domain(source_ip, &resolver);
                            println!(
                                "Timestamp: {}, IP {} is sending to host. Domain of source IP: {}",
                                timestamp, source_ip, domain
                            );
                        }
                        if dest_ip != local_ip {
                            let timestamp = get_formatted_timestamp();
                            let domain = resolve_ip_to_domain(dest_ip, &resolver);
                            println!(
                                "Timestamp: {}, IP {} is receiving from host. Domain of destination IP: {}",
                                timestamp, dest_ip, domain
                            );
                        }
                    }
                }
            }
            Err(e) => panic!("Error while reading: {}", e),
        }
    }
}

fn resolve_ip_to_domain(ip: Ipv4Addr, resolver: &Resolver) -> String {
    let ip_addr = IpAddr::V4(ip);
    match resolver.reverse_lookup(ip_addr) {
        Ok(names) => {
            if let Some(name) = names.iter().next() {
                name.to_string()
            } else {
                "Unknown".to_string()
            }
        }
        Err(_) => "Resolution error".to_string(),
    }
}

fn get_formatted_timestamp() -> String {
    let now: DateTime<Local> = Local::now();
    now.format("%d/%m/%Y %H:%M:%S").to_string()
}
