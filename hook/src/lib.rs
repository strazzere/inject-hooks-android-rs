mod hooks;
mod patch;
mod hook;
mod log;
mod elf;

pub fn exposed_function() {
    crate::hooks::init();
}

#[ctor::ctor]
unsafe fn ctor_init() {
    logd!("Running init");
    exposed_function();
}
