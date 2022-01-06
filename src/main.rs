extern crate ssl_expiration;

use std::io::{stderr, Write};
use std::env;
use std::process::exit;

fn main() {
    let mut exit_code = 0;
    for domain in env::args().skip(1) {
        match ssl_expiration::SslExpiration::from_domain_name(&domain) {
            Ok(expiration) => {
                for name in expiration.get_alt_names() {
                    println!("Alt: {}", name);
                }
                let days = expiration.days();
                if expiration.is_expired() {
                    let _ = writeln!(stderr(),
                                     "{} SSL certificate expired {} days ago",
                                     domain,
                                     !days);
                    exit_code = 1;
                } else if expiration.days() <= 7 {
                    println!("{} SSL certificate will expire soon, in {} days", domain, days);
                    exit_code = 1;
                } else {
                    println!("{} SSL certificate will expire in {} days", domain, days);
                }
            }
            Err(e) => {
                let _ = writeln!(stderr(),
                                 "An error occured when checking {}: {}",
                                 domain,
                                 e.description());
            }
        }
    }
    exit(exit_code);
}
