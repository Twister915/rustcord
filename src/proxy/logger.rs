use std::fmt;
use chrono::Local;
use std::process::exit;

#[derive(Copy, Clone, Debug)]
pub struct Logger {
    min_print_level: Level,
    default_level: Option<Level>
}

impl Logger {
    pub fn new(min_print_level: Level) -> Self {
        Self{
            min_print_level,
            default_level: None,
        }
    }

    pub fn with_default_level(mut self, level: Level) -> Self {
        self.default_level = Some(level);
        self
    }

    pub fn fatal(&self, args: fmt::Arguments<'_>) {
        self.write_level(Level::Fatal, args);
        exit(1)
    }

    pub fn error(&self, args: fmt::Arguments<'_>) {
        self.write_level(Level::Error, args)
    }

    pub fn warning(&self, args: fmt::Arguments<'_>) {
        self.write_level(Level::Warning, args)
    }

    pub fn info(&self, args: fmt::Arguments<'_>) {
        self.write_level(Level::Info, args)
    }

    pub fn debug(&self, args: fmt::Arguments<'_>) {
        self.write_level(Level::Debug, args)
    }

    pub fn trace(&self, args: fmt::Arguments<'_>) {
        self.write_level(Level::Trace, args)
    }

    pub fn write(&self, args: fmt::Arguments) {
        self.write_level(self.default_level.unwrap_or(Level::Info), args)
    }

    pub fn write_level(&self, level: Level, args: fmt::Arguments) {
        if level <= self.min_print_level {
            let line = format!(
                "[{} @ {}]: {}",
                level,
                Local::now().format("%D %r"),
                fmt::format(args));

            if level >= Level::Warning {
                eprintln!("{}", line);
            } else {
                println!("{}", line);
            }
        }
    }
}

#[derive(PartialOrd, PartialEq, Ord, Eq, Copy, Clone, Debug)]
pub enum Level {
    Fatal,
    Error,
    Warning,
    Info,
    Debug,
    Trace
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Level::Fatal => f.write_str("FATAL"),
            Level::Error => f.write_str("ERROR"),
            Level::Warning => f.write_str("WARNING"),
            Level::Info => f.write_str("INFO"),
            Level::Debug => f.write_str("DEBUG"),
            Level::Trace => f.write_str("TRACE"),
        }
    }
}