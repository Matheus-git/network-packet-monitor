use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{TcpPacket, MutableTcpPacket, Tcp, TcpFlags, ipv4_checksum};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::Packet;
use pnet::transport::{TransportReceiver, TransportSender};
use pnet::transport::{transport_channel, TransportChannelType::Layer4, TransportProtocol::Ipv4};
use pnet::util;
use std::net::{IpAddr, Ipv4Addr};
use std::ops::Deref;
use std::os::linux::raw;

use pnet::datalink::{self, NetworkInterface, Config, ChannelType, FanoutOption, FanoutType};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{MutablePacket};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use std::time::Duration;
use std::net::{TcpListener, TcpStream};

use std::env;
use std::thread;

fn TcpRaw() -> Tcp {
    Tcp {
        source: 8002,
        destination: 8080,
        sequence: 1,
        acknowledgement: 0,
        data_offset: 5,
        reserved: 0,
        flags: TcpFlags::SYN,
        window: 4096,
        checksum: 0,
        urgent_ptr: 0,
        options: vec![],
        payload: vec![],
    }
}

struct TcpEndpointPair {
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
}

struct TransportChannel {
    sender: TransportSender,
    receiver: TransportReceiver
}

impl TransportChannel {
    fn new() -> TransportChannel {
        let (tx, rx ) = match transport_channel(1024, Layer4(Ipv4(IpNextHeaderProtocols::Tcp))) {
            Ok((tx, rx)) => (tx, rx),
            Err(e) => panic!("An error occurred when creating the transport channel: {}", e)
        };

        TransportChannel {
            sender: tx,
            receiver: rx
        }
    }

    fn send_to<T>(&mut self, packet: T, destination: IpAddr) -> usize
    where 
        T: Packet
    {
        match self.sender.send_to(packet, destination) {
            Ok(result) => result,
            Err(e) => panic!("Error: {}", e)
        }
    }
}

// struct TcpPacketModule<T> {
//     raw: Tcp,
//     packet: T  
// }

// impl<T>  TcpPacketModule<T>{
//     fn generate_packet<'a>(self, tcp_endpoint_pair: TcpEndpointPair, buffer: &'a mut [u8] ) -> T 
//     where
//         T: From<MutableTcpPacket<'a>>
//     {
        // let mut packet = MutableTcpPacket::new(buffer).unwrap();
        // packet.populate(&self.raw);
        // packet.set_checksum(ipv4_checksum(&packet.to_immutable(), &tcp_endpoint_pair.src_ip, &tcp_endpoint_pair.dst_ip));
        // self.packet = packet.consume_to_immutable();
        // T::from(packet)
//     }
// }

fn generate_packet<'a>(tcp_endpoint_pair: &TcpEndpointPair, buffer: &'a mut [u8], tcp_raw: Tcp) -> TcpPacket<'a>
{
    let mut packet = MutableTcpPacket::new(buffer).unwrap();
    packet.populate(&tcp_raw);
    packet.set_checksum(ipv4_checksum(&packet.to_immutable(), &tcp_endpoint_pair.src_ip, &tcp_endpoint_pair.dst_ip));
    packet.consume_to_immutable()
}

fn main() {
    let tcp_endpoint_pair: TcpEndpointPair = TcpEndpointPair {
        src_ip: Ipv4Addr::new(192, 168, 3, 15),
        src_port: 8002,
        dst_ip: Ipv4Addr::new(192, 168, 3, 100),
        dst_port: 8080
    };

    let mut transport_channel: TransportChannel = TransportChannel::new();

    let mut buffer = [0u8; 20];
    let tcp_raw = TcpRaw();
    let packet = generate_packet(&tcp_endpoint_pair, &mut buffer, tcp_raw);
    let result = transport_channel.send_to(packet.consume_to_immutable(), IpAddr::V4(tcp_endpoint_pair.dst_ip.clone()));

    println!("Enviado com sucesso: {}", result);

    // thread::spawn(move || {
    //     datalink_receive();
    // });
}


fn datalink_receive() {

    let interface_name = "enp61s0".to_string();

    let interface_names_match =
        |iface: &NetworkInterface| iface.name == interface_name;

        let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
                              .filter(interface_names_match)
                              .next()
                              .unwrap();

                              println!("interface: {:?}", interface);

    let (mut txd, mut rxd) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(txd, rxd)) => (txd, rxd),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
    };

    loop {
        match rxd.next() {
            Ok(packet) => {
                let ethernet_packet = EthernetPacket::new(packet).unwrap();

                // Obtém o MAC de origem e converte para string
                let source_mac = ethernet_packet.get_source().to_string();

                if source_mac == "e8:ff:1e:da:1a:69" {
                    println!("Pacote vindo do remetente correto: {}", source_mac);

                    if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
                        if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                            let tcp_offset = ipv4_packet.get_header_length() as usize;
                            println!("header length {}", tcp_offset);
                            if let Some(tcp_packet) = TcpPacket::new(&ipv4_packet.payload()) {
                                
                                // if tcp_packet.get_acknowledgement() == 1 {
                                    let (mut tx, mut rx ) = match transport_channel(1024, Layer4(Ipv4(IpNextHeaderProtocols::Tcp))) {
                                        Ok((tx, rx)) => (tx, rx),
                                        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
                                    };

                                    let tcp: Tcp =  Tcp {
                                        source: 8002,
                                        destination: 8080,
                                        sequence: tcp_packet.get_sequence() + 1,
                                        acknowledgement: 1,
                                        data_offset: 5,
                                        reserved: 0,
                                        flags: TcpFlags::ACK,
                                        window: 4096,
                                        checksum: 0,
                                        urgent_ptr: 0,
                                        options: vec![],
                                        payload: vec![],
                                    };

                                    let mut buffer = [0u8; 20];
                                    let mut packet = MutableTcpPacket::new(&mut buffer).unwrap();
                                    packet.populate(&tcp);
                                    packet.set_checksum(ipv4_checksum(&packet.to_immutable(), &Ipv4Addr::new(192, 168, 3, 15), &Ipv4Addr::new(192, 168, 3, 100)));
                                
                                    let result = match tx.send_to(packet.consume_to_immutable(),IpAddr::V4(Ipv4Addr::new(192, 168, 3, 100))) {
                                        Ok(result) => result,
                                        Err(e) => panic!("Error: {}", e)
                                    };
                                // }else{
                                //     println!("Conhecimento: {}", tcp_packet.get_acknowledgement());
                                // }
                            }
                        }
                    }
                } else {

                }
            },
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}