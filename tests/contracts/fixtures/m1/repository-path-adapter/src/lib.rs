fn forbidden_adapter() {
    let _ = std::env::vars_os().find(|(name, _)| name == "PATH");
}
