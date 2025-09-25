pub mod fileio;
pub mod injection_log;

// Auto generated bindings of all init functions from files in this dir
include!(concat!(env!("OUT_DIR"), "/hooks_gen.rs"));