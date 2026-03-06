/**
Interface for operations over Domain Lists
**/
pub trait DomainFilter {
    fn is_blocked(&self, domain: &str) -> bool;

    fn drop_record(&mut self, domain: &str);
    
    fn add_record(&mut self, domain: &str);
}