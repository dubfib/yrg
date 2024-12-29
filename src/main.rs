use std::env;
use std::fs::File;
use std::io::{self, Write};
use pesign::PeSign;
use chrono::Local;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("usage: <pe_path>");
        std::process::exit(1);
    }

    let path = &args[1];

    if let Some(pe) = PeSign::from_pe_path(path)? {
        for (i, cert) in pe.signed_data.cert_list.iter().enumerate() {
            let subject = cert.subject.to_string();

            let subject_cn = subject
                .split(", ")
                .find(|&str| str.starts_with("CN="))
                .and_then(|str| str.split('=').nth(1))
                .unwrap_or("");

            let serial = cert.serial_number
                .iter()
                .map(|byte| format!("{:02x}", byte))
                .collect::<String>();

            println!("[{}] {} ({})", i + 1, subject_cn, serial);
        }

        print!("which certificate? (select a number): ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        let selected_index: usize = match input.trim().parse() {
            Ok(num) => num,
            Err(_) => {
                eprintln!("error: invalid section");
                std::process::exit(1);
            }
        };

        if selected_index == 0 || selected_index > pe.signed_data.cert_list.len() {
            eprintln!("error: invalid selection");
            std::process::exit(1);
        }

        let selected_cert = &pe.signed_data.cert_list[selected_index - 1];
        let subject = selected_cert.subject.to_string();

        let subject_cn = subject
            .split(", ")
            .find(|&str| str.starts_with("CN="))
            .and_then(|str| str.split('=').nth(1))
            .unwrap_or("");

        let serial = selected_cert.serial_number
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>();

        let serial_octet = selected_cert.serial_number
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join(":");

        let valid_to = selected_cert.validity.not_after.timestamp();
        let time = Local::now().format("%Y-%m-%d").to_string();

        let rule = format!(r#"/**
    Generated using yrg (yara-rule-generator)
    https://github.com/dubfib/yrg
*/

import "pe"

rule certificate_{serial} {{
    meta:
        author = "dubfib"
        date = "{time}"

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "{subject_cn}" and
            pe.signatures[i].serial == "{serial_octet}" and
            {valid_to} <= pe.signatures[i].not_after
        )
}}"#);

        File::create("certificate.yar")?.write_all(rule.as_bytes())?;
        println!("success: written to certificate.yar");
        Ok(())
    } else {
        println!("error: pe has no signature");
        Ok(())
    }
}