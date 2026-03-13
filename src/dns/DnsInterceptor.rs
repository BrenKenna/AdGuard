use std::net::Ipv4Addr;
use dns_parser::{Packet};
use log::{info, warn, error};
use simple_dns::rdata::RData;

pub(crate) struct DnsInterceptor {
    sinkhole: Ipv4Addr
}


impl DnsInterceptor {
    pub fn new() -> Self {
        Self {
            sinkhole: Ipv4Addr::new(0, 0, 0, 0)
        }
    }

    pub fn extract_domain(packet: &[u8]) -> Option<String> {
        let mut val:Option<String> = None;
        match Packet::parse(packet) {
            Ok(dns) =>
                if let Some(q) = dns.questions.first() {
                    val = Some(q.qname.to_string())
                }
            Err(ex) => {
                error!(
                    "Failed to parse DNS packet:\t'{}'",
                    ex
                );
            }

        }
        return val;
    }


    pub fn build_block_response(&self, canon: &[u8]) -> Vec<u8> {

        // Try fetch packet
        let req = match simple_dns::Packet::parse(canon) {
            Ok(p ) => p,
            Err(_) => return vec![],
        };

        // Initialize response
        let mut resp = simple_dns::Packet::new_reply(req.id());

        // Set response code of 3
        let mock = simple_dns::rdata::RData::A(
            simple_dns::rdata::A{
                address: self.sinkhole.clone().to_bits()
        });
        for i in req.questions {
            let clone = i.clone();
            resp.questions.push(i.clone());
            resp.answers.push(simple_dns::ResourceRecord::new(
                i.clone().qname,
                simple_dns::CLASS::IN,
                60,
                mock.clone()
            ));
        }

        return resp.build_bytes_vec().unwrap_or_default();
    }


    pub fn build_payload(&self, canon: &[u8], payload: &[u8]) -> Vec<u8> {

        let builder = etherparse::PacketBuilder::ipv4(
            [10, 0, 0, 1],
            [0, 0, 0, 0],
                64
        ).udp(
            53, 1234
        );

        let mut packet = Vec::with_capacity(builder.size(payload.len()));
        builder.write(
            &mut packet,
            payload
        ).unwrap();
        return packet;
    }
}