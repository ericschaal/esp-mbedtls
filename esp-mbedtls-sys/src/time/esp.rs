//! ESP32XX time support based on the baremetal `esp-hal` crate.
//!
//! This module provides MbedTLS time integration using the ESP32's RTC peripheral.
//! It implements the standard time hooks required by MbedTLS for certificate
//! validation and other time-sensitive operations.

use core::cell::Cell;
use critical_section::Mutex;
use time::OffsetDateTime;

use crate::hook::time::{MbedtlsGmtimeR, MbedtlsMsTime, MbedtlsTime, MbedtlsTm};

/// Backend for ESP32 time operations using the RTC peripheral.
///
/// This struct stores a reference to the RTC and implements the time-related
/// traits required by MbedTLS. Access to the RTC is protected by a critical
/// section to ensure thread safety.
pub struct EspTimeBackend {
    rtc: Mutex<Cell<Option<&'static esp_hal::rtc_cntl::Rtc<'static>>>>,
}

pub static ESP_TIME: EspTimeBackend = EspTimeBackend {
    rtc: Mutex::new(Cell::new(None)),
};

impl EspTimeBackend {
    fn with_rtc<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&esp_hal::rtc_cntl::Rtc<'_>) -> R,
    {
        critical_section::with(|cs| self.rtc.borrow(cs).get().map(f))
    }
}

impl MbedtlsTime for EspTimeBackend {
    fn time(&self) -> i64 {
        self.with_rtc(|rtc| (rtc.current_time_us() / 1_000_000) as i64)
            .unwrap_or(0)
    }
}

impl MbedtlsMsTime for EspTimeBackend {
    fn ms_time(&self) -> i64 {
        self.with_rtc(|rtc| (rtc.current_time_us() / 1_000) as i64)
            .unwrap_or(0)
    }
}

impl MbedtlsGmtimeR for EspTimeBackend {
    fn gmtime_r(&self, time: i64, tm_buf: &mut MbedtlsTm) -> Result<(), ()> {
        let dt = OffsetDateTime::from_unix_timestamp(time).map_err(|_| ())?;

        let date = dt.date();
        let time_components = dt.time();

        tm_buf.tm_sec = time_components.second() as i32;
        tm_buf.tm_min = time_components.minute() as i32;
        tm_buf.tm_hour = time_components.hour() as i32;
        tm_buf.tm_mday = date.day() as i32;
        tm_buf.tm_mon = u8::from(date.month()) as i32 - 1; // Fixed
        tm_buf.tm_year = date.year() - 1900;
        tm_buf.tm_wday = date.weekday().number_days_from_sunday() as i32;
        tm_buf.tm_yday = date.ordinal() as i32 - 1;
        tm_buf.tm_isdst = -1;

        Ok(())
    }
}

/// Register a static RTC reference for MbedTLS time operations.
///
/// This function registers the provided RTC peripheral with the MbedTLS
/// time hooks and returns a guard. When the guard is dropped, the hooks
/// are automatically unregistered.
///
/// # Arguments
///
/// * `rtc` - A static reference to the RTC peripheral
///
/// # Returns
///
/// A guard that will automatically unregister the hooks when dropped
/// ```
#[must_use = "The guard must be kept alive for the hooks to remain registered"]
pub fn register(rtc: &'static esp_hal::rtc_cntl::Rtc<'static>) -> EspTimeGuard {
    critical_section::with(|cs| {
        ESP_TIME.rtc.borrow(cs).set(Some(rtc));
    });

    unsafe {
        crate::hook::time::hook_time(Some(&ESP_TIME));
        crate::hook::time::hook_ms_time(Some(&ESP_TIME));
        crate::hook::time::hook_gmtime_r(Some(&ESP_TIME));
    }

    EspTimeGuard
}

/// Guard that manages the lifecycle of time hooks
///
/// When created (via `register()`), it registers the time hooks with MbedTLS.
/// When dropped, it automatically deregisters the hooks and clears the RTC reference.
pub struct EspTimeGuard;

impl Drop for EspTimeGuard {
    fn drop(&mut self) {
        // Deregister hooks
        unsafe {
            crate::hook::time::hook_time(None);
            crate::hook::time::hook_ms_time(None);
            crate::hook::time::hook_gmtime_r(None);
        }

        // Clear RTC reference
        critical_section::with(|cs| {
            ESP_TIME.rtc.borrow(cs).set(None);
        });
    }
}
