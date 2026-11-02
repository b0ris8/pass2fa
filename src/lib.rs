//! Общий код для двух бинарников: `pass2fa` (консольный: CLI, native host браузера, GUI)
//! и `pass2faw` (только GUI; на Windows без консольного окна).
pub mod bundle;
pub mod desktop;
pub mod export;
pub mod filepick;
pub mod gen;
pub mod gui;
pub mod icons;
pub mod import;
pub mod model;
pub mod native;
pub mod session;
pub mod state;
pub mod totp;
pub mod vault;
