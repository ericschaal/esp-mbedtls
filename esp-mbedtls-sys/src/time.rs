//! Time support for MbedTLS.
//!
//! This module provides platform-specific time implementations for MbedTLS
//! certificate validation and other time-sensitive operations.
//!
//! # ESP32 Series Support
//!
//! On ESP32 targets (when using `esp-hal`), time functionality is provided
//! via the RTC peripheral. Enable with one of the `time-esp32*` features:
//! - `time-esp32`
//! - `time-esp32c2`, `time-esp32c3`, `time-esp32c6`
//! - `time-esp32h2`
//! - `time-esp32s2`, `time-esp32s3`
//!
//! See [`esp::register()`] for usage details.
//!
//! # Disabling Time Hooks
//!
//! Use the `nohook-platform-time` feature to completely disable time hook
//! functionality.

#[cfg(any(
    feature = "time-esp32",
    feature = "time-esp32c2",
    feature = "time-esp32c3",
    feature = "time-esp32c6",
    feature = "time-esp32h2",
    feature = "time-esp32s2",
    feature = "time-esp32s3",
))]
pub mod esp;