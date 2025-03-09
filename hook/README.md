# Hook

Some slim automation around doing hooks via a shared library. Two methods
are currently supported;

 - Direct patching with a trampoline (this might be buggy depending on function prolog)
 - GOT patching - this is the preferred method and should be prioritized due to
   the safeness.

# Adding hooks

Drop a file into `src/hooks/` and ensure it implements an `init()` function, this will automatically be pulled in when the `mod.rs` file is generated. These hooks will now automatically be run upon initialization/execution of this library.

The provided `logd` function will automatically be removed on `release` builds.