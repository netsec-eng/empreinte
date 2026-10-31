fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    let mut resource = winresource::WindowsResource::new();
    resource.set_icon("assets/icon.ico");
    resource.set("ProductName", "Empreinte");
    resource.set("FileDescription", "Empreinte");
    resource.compile().expect("impossible d'intégrer l'icône");
}
