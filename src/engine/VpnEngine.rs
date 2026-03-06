use crate::filtering::DomainFilter::DomainFilter;
use std::sync::Arc;

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

    pub fn should_block(&self, domain: &str) -> bool {
        self.filter.is_blocked(domain)
    }
}