use std::env;
use std::fs::File;
use std::io::Write;
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
        let zeroth = &pe.signed_data.cert_list[1];

        let subject = zeroth.subject.to_string();

        let subject_cn = subject
            .split(", ")
            .find(|&str| str.starts_with("CN="))
            .and_then(|str| str.split('=').nth(1))
            .unwrap_or("");

        let serial = zeroth.serial_number
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>();

        let serial_octet = zeroth.serial_number
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join(":");

        let valid_to = zeroth.validity.not_after.timestamp();
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
        println!("created certificate.yar successfully");
        Ok(())
    } else {
        println!("error: pe has no signature");
        Ok(())
    }
}