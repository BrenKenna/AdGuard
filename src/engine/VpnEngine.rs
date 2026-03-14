use std::sync::Arc;
use std::os::unix::io::FromRawFd;
use log::{info, warn};

use crate::filtering::DomainFilter::DomainFilter;
use crate::dns::DnsInterceptor::DnsInterceptor;
use crate::stats;
use crate::engine::NetInf::NetInf;


/**
Building to support building VPN Engines
**/
pub(crate) struct VpnEngineBuilder<F: DomainFilter + Send + Sync + 'static> {
    filter: Option<Arc<F>>,
    net_inf: Option<NetInf>
}

impl<F: DomainFilter + Send + Sync + 'static> VpnEngineBuilder<F> {
    pub fn new() -> Self {
        Self {
            filter: None,
            net_inf: None
        }
    }

    pub fn with_filter(mut self, filter: Arc<F>) -> Self {
        self.filter = Some(filter);
        return self;
    }

    pub fn with_interface(mut self, interface: NetInf) -> Self {
        self.net_inf = Some(interface);
        return self;
    }

    pub fn build(self) -> VpnEngine<F> {
        VpnEngine{
            filter: self.filter.expect("Filter is required"),
            net_inf: self.net_inf.expect("TUN interface is required")
        }
    }
}


/**
VPN Engine whose TUN interface
 intercepts DNS queries and filters
 against blocked list.
**/
pub(crate) struct VpnEngine<F: DomainFilter + Send + Sync + 'static> {
    filter: Arc<F>,
    net_inf: NetInf
}

impl<F: DomainFilter + Send + Sync + 'static> VpnEngine<F> {

    pub fn new(filter: Arc<F>, net_inf: NetInf) -> Self {
        Self { filter, net_inf }
    }

    fn should_block(&self, domain: &str) -> bool {
        self.filter.is_blocked(domain)
    }

    pub fn run(&self, fd:i32) {

        let mut dnsInterceptor = DnsInterceptor::new();

        let mut dev = unsafe {
            std::os::unix::io::from_raw_fd(fd)
        }
        let mut buf = [0u8; 2000];

        loop {
            match dev.read(&mut buf) {
                Ok(n) => {
                    let packet_data = &buf[..n];
                    if let Some(domain) =
                        dnsInterceptor.extract_domain(packet_data) {
                            info!("DNS packet from {}", domain);
                            if self.should_block(&domain) {
                                stats::increment_blocked();
                                warn!("Blocking domain:\t'{}'", domain);
                                let resp = dnsInterceptor.build_block_response(packet_data);
                                let resp_packet = dnsInterceptor.build_payload(packet_data, &resp);

                                let _ = dev.write_all(&resp_packet);
                            }

                            // Forward non blocked dns query
                    }

                    // Forward non dns query
                }
            }
        }
    }
}