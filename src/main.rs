use std::{env, fs, path::Path, process};

fn take_once(slot: &mut Option<String>, value: Option<String>, flag: &str) {
    if slot.is_some() {
        eprintln!("Flag {} used more than once", flag);
        process::exit(1);
    }

    *slot = Some(value.unwrap_or_else(|| {
        eprintln!("Missing value for {}", flag);
        process::exit(1);
    }));
}

fn take_value(value: Option<String>, flag: &str) -> String {
    value.unwrap_or_else(|| {
        eprintln!("Missing value for {}", flag);
        process::exit(1);
    })
}

#[derive(Debug, Default)]
struct RestoreOptions {
    password: Option<String>,
    input: Option<String>,
}

impl RestoreOptions {
    fn parse(args: &mut impl Iterator<Item = String>) -> Self {
        let mut flags = Self::default();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-p" | "--password" => take_once(&mut flags.password, args.next(), "-p/--password"),
                "-i" | "--input" => take_once(&mut flags.input, args.next(), "-i/--input"),
                _ => {
                    eprintln!("Unknown argument: {}", arg);
                    process::exit(1);
                }
            }
        }

        flags
    }
}

#[derive(Debug, Default)]
struct BackupOptions {
    password: Option<String>,
    files: Vec<String>,
    config: Option<String>,
    salt: Option<String>,
    output: Option<String>,
    write_to_config: bool,
}

impl BackupOptions {
    fn parse(args: &mut impl Iterator<Item = String>) -> Self {
        let mut flags = Self::default();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-p" | "--password" => take_once(&mut flags.password, args.next(), "-p/--password"),
                "-c" | "--config" => take_once(&mut flags.config, args.next(), "-c/--config"),
                "-s" | "--salt" => take_once(&mut flags.salt, args.next(), "-s/--salt"),
                "-o" | "--output" => take_once(&mut flags.output, args.next(), "-o/--output"),
                "-w" | "--write" => {
                    match take_value(args.next(), "-w/--write")
                        .to_lowercase()
                        .as_str()
                    {
                        "1" | "true" | "y" | "yes" => flags.write_to_config = true,
                        "0" | "false" | "n" | "no" => flags.write_to_config = false,
                        v => {
                            eprintln!("Invalid value for -w/--write: {}", v);
                            process::exit(1);
                        }
                    }
                }
                "-f" | "--file" => {
                    flags.files.push(take_value(args.next(), "-f/--file"));
                }

                _ => {
                    eprintln!("Unknown argument: {}", arg);
                    process::exit(1);
                }
            }
        }

        flags
    }
}

fn backup(mut opt: BackupOptions) -> Result<(), std::io::Error> {
    let config = opt.config.as_deref().unwrap_or("./.config.AMBK");
    let config_path = Path::new(config);
    if fs::exists(config_path)? {
        fs::read_to_string(config_path)?
            .lines()
            .for_each(|l| opt.files.push(l.to_owned()));
    } else {
        println!(
            "WARNING: '{}' does not exist.",
            config_path.to_string_lossy()
        );
    }

    println!("{:?}", opt.password);
    println!("{:?}", opt.files);
    println!("{:?}", opt.config);
    println!("{:?}", opt.salt);
    println!("{:?}", opt.output);

    Ok(())
}

fn restore(opt: RestoreOptions) {
    println!("{:?}", opt.password);
    println!("{:?}", opt.input);
}

fn main() {
    let mut args = env::args().skip(1);

    match args.next().as_deref() {
        Some("backup") => backup(BackupOptions::parse(&mut args)).expect("I expect this to work"),
        Some("restore") => restore(RestoreOptions::parse(&mut args)),
        _ => {
            eprintln!("Usage: program <backup|restore> [options]");
            process::exit(1);
        }
    }
}
