use std::{
    env::{var_os as read_variable},
};

pub fn inspect() {
    let _ = read_variable("PATH");
}
