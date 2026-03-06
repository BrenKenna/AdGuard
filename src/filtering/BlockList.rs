use std::collections::HashSet;
use crate::filtering::DomainFilter::DomainFilter;


/**
Model class to hold logic for operations
 over blocked list of domains
**/
pub struct Blocklist {
    domains: HashSet<String>,
}

impl Blocklist {
    pub fn new() -> Self {
        Self { domains: HashSet::new() }
    }

    pub fn get_blocked_list(self) -> HashSet<String> {
        return self.domains;
    }

    pub fn get_mutable_blocked_list(&mut self) -> HashSet<String> {
        return self.domains.clone();
    }
}

impl DomainFilter for Blocklist {
    fn is_blocked(&self, domain: &str) -> bool {
        self.domains.contains(domain)
    }

    fn drop_record(&mut self, domain: &str) {
        if self.domains.contains(domain) {
            self.domains.remove(domain);
        }
    }

    fn add_record(&mut self, domain: &str) {
        if !self.domains.contains(domain) {
            self.domains.insert(domain.to_string());
        }
    }
}