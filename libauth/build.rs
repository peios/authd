fn main() {
    println!("cargo:rustc-link-arg-cdylib=-Wl,-soname,libauth.so.1");
}
