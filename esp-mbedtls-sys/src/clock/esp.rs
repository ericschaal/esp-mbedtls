use core::cell::Cell;
use critical_section::Mutex;

use crate::bindings::tm;
use crate::hook::wall_clock::MbedtlsWallClock;

/// ESP RTC-based wall clock backend.
///
/// This implementation uses the ESP32's RTC (Real-Time Clock) to provide
/// wall clock time for MbedTLS operations like X.509 certificate validation.
///
/// # Limitations
///
/// **IMPORTANT**: This implementation has significant limitations:
///
/// - **Clock drift**: The RTC is not synchronized with an external time source
///   and will drift over time. The drift rate depends on temperature and other
///   environmental factors.
/// - **Power cycling**: The RTC time is lost when the device loses power,
///   requiring the time to be set again after boot.
/// - **Initial time**: The RTC starts at the Unix epoch (1970-01-01 00:00:00 UTC)
///   on first boot. You MUST set the correct time before using TLS features
///   that depend on wall clock time (e.g., certificate validation).
///
/// For production use, consider:
/// - Setting the RTC time from an NTP server after network connection
/// - Using a battery-backed RTC if accurate timekeeping across power cycles is needed
/// - Implementing certificate validation with custom time verification if needed
pub struct EspRtcWallClockBackend {
    rtc: Mutex<Cell<Option<&'static esp_hal::rtc_cntl::Rtc<'static>>>>,
}

impl EspRtcWallClockBackend {
    pub const fn new() -> Self {
        Self {
            rtc: Mutex::new(Cell::new(None)),
        }
    }

    fn with_rtc<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&esp_hal::rtc_cntl::Rtc<'_>) -> R,
    {
        critical_section::with(|cs| self.rtc.borrow(cs).get().map(f))
    }
}

pub static CLOCK: EspRtcWallClockBackend = EspRtcWallClockBackend::new();

impl MbedtlsWallClock for EspRtcWallClockBackend {
    fn instant(&self) -> tm {
        // Get current time from RTC instance (returns None if no RTC registered)
        let rtc_time_secs = self.with_rtc(|rtc| {
            (rtc.current_time_us() / 1_000_000) as i64
        });

        // If no RTC is registered, return Unix epoch as default
        let rtc_time_secs = rtc_time_secs.unwrap_or(0);

        // Convert to OffsetDateTime
        let datetime = time::OffsetDateTime::from_unix_timestamp(rtc_time_secs)
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);

        let date = datetime.date();
        let time = datetime.time();

        tm {
            tm_sec: time.second() as i32,
            tm_min: time.minute() as i32,
            tm_hour: time.hour() as i32,
            tm_mday: date.day() as i32,
            tm_mon: date.month() as i32 - 1, // tm_mon is 0-11, time::Month is 1-12
            tm_year: date.year() - 1900, // tm_year is years since 1900
            tm_wday: date.weekday().number_days_from_sunday() as i32,
            tm_yday: date.ordinal() as i32 - 1, // MbedTLS uses 0-365
            tm_isdst: 0,
        }
    }
}

/// RAII guard for ESP RTC wall clock hook.
///
/// This guard automatically hooks the ESP RTC wall clock when created
/// and unhooks it when dropped, following the same pattern as `EmbassyTimer`.
///
/// # Example
///
/// ```no_run
/// use esp_mbedtls_sys::clock::EspRtcWallClock;
/// use esp_hal::rtc_cntl::Rtc;
///
/// // Assume you have initialized an RTC and made it static
/// static RTC: Rtc<'static> = /* your RTC initialization */;
///
/// // Hook the wall clock with the RTC
/// let _clock = EspRtcWallClock::new(&RTC);
///
/// // Use MbedTLS functions that need wall clock time
/// // ...
///
/// // Wall clock is automatically unhooked when _clock is dropped
/// ```
pub struct EspRtcWallClock;

impl EspRtcWallClock {
    /// Create a new ESP RTC wall clock guard and hook it.
    ///
    /// # Arguments
    /// * `rtc` - Static reference to the ESP RTC peripheral
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - The RTC has been initialized with the correct time before using
    ///   MbedTLS functions that depend on wall clock time
    /// - Only one wall clock hook is active at a time
    /// - The RTC reference remains valid for the lifetime of this guard
    pub fn new(rtc: &'static esp_hal::rtc_cntl::Rtc<'static>) -> Self {
        // Register the RTC with the backend
        critical_section::with(|cs| {
            CLOCK.rtc.borrow(cs).set(Some(rtc));
        });

        // Hook the wall clock
        unsafe {
            crate::hook::wall_clock::hook_wall_clock(Some(&CLOCK));
        }

        Self
    }
}

impl Drop for EspRtcWallClock {
    fn drop(&mut self) {
        // Unhook the wall clock
        unsafe {
            crate::hook::wall_clock::hook_wall_clock(None);
        }

        // Unregister the RTC
        critical_section::with(|cs| {
            CLOCK.rtc.borrow(cs).set(None);
        });
    }
}
