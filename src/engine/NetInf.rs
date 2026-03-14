use tun::{Configuration, Device};
use std::io::{ Read };

use log::{info, error};

/**
Class for building TUN interfaces
 configured with IP & subnet mask
**/
pub (in crate::engine) struct NetInfBuilder {
    ip_addr: Option<String>,
    net_mask: Option<String>
}

impl NetInfBuilder {
    pub fn new() -> Self {
        Self {
            ip_addr: None,
            net_mask: None
        }
    }

    pub fn with_ip(mut self, ip: String) -> Self {
        self.ip_addr = Some(ip);
        return self;
    }
    
    pub fn with_net_mask(mut self, net_mask: &str) -> Self {
        self.net_mask = Some(net_mask.to_string());
        return self;
    }
    
    pub fn build(self) -> NetInf {
        let mut dev = NetInf{
            ip_addr: self.ip_addr.unwrap(),
            net_mask: self.net_mask.unwrap(),
            device: None,
            state: false
        };
        dev.create_tun();
        return dev;
    }
}

/**
Class to hold logic for handling TUN interface
**/
pub(in crate::engine) struct NetInf {
    ip_addr: String,
    net_mask: String,
    device: Option<Device>,
    state: bool
}


/**
Construction
**/
impl NetInf {

    pub fn new(
        ip_addr: String,
        net_mask: String
    ) -> Self {
        Self {
            ip_addr,
            net_mask,
            device: None,
            state: false
        }
    }

    pub fn with_device(mut self, dev: Device) -> Self {
        self.device = Some(dev);
        self.state = true;
        return self;
    }

    pub fn get_device_ref(&mut self) -> Option<&Device> {
        return self.device.as_ref();
    }

    pub fn get_device_val(&mut self) -> Option<&mut Device> {
        return self.device.as_mut();
    }

    pub fn get_ip_addr(&mut self) -> String {
        return self.ip_addr.clone();
    }

    pub fn get_net_mask(&mut self) -> String {
        return self.net_mask.clone();
    }

    pub fn get_state(&mut self) -> bool {
        return self.state;
    }

    pub fn set_device(&mut self, device: Device) {
        self.device = Some(device);
        self.set_state(true);
    }

    pub fn set_ip_addr(&mut self, ip_addr: String) {
        self.ip_addr = ip_addr;
    }

    pub fn set_net_mask(&mut self, net_mask: String) {
        self.net_mask = net_mask;
    }

    pub fn set_state(&mut self, state: bool) {
        self.state = state;
    }
}


/**
 Configure TUN Device
**/
impl NetInf {
    pub fn create_tun(&mut self) {
        let mut config = Configuration::default();
        let ip = self.get_ip_addr();
        let net_mask = self.get_net_mask();

        config
            .address(ip)
            .netmask(net_mask)
            .up();

        let dev = tun::create(&config).unwrap();
        self.set_device(dev);
    }
}


/**
Read packets to console
**/
impl NetInf {
    pub fn read_packets(&mut self) {
        let mut buf = [0u8; 1600];
        if let Some(dev) = self.device.as_mut() {
            loop {
                let n = dev.read(&mut buf).unwrap();
                info!("packet size {}", n);
            }
        } else {
            error!("Device not initialized");
        }
    }
}