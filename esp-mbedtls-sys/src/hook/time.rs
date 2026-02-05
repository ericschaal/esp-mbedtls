//! Platform time hooks for MbedTLS.
//!
//! This module provides the hook interface for integrating custom time sources
//! into MbedTLS. It defines three time-related traits:
//! - [`MbedtlsTime`]: Second-based time retrieval
//! - [`MbedtlsMsTime`]: Millisecond-based time retrieval
//! - [`MbedtlsGmtimeR`]: Converting Unix timestamps to broken-down time
//!
//! Implementations of these traits can be registered via the `hook_*` functions,
//! which install them as MbedTLS's time providers through C FFI.

/// Helper type representing struct tm for safe Rust interaction
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MbedtlsTm {
    pub tm_sec: i32,
    pub tm_min: i32,
    pub tm_hour: i32,
    pub tm_mday: i32,
    pub tm_mon: i32,
    pub tm_year: i32,
    pub tm_wday: i32,
    pub tm_yday: i32,
    pub tm_isdst: i32,
}

/// Trait representing a custom (hooked) MbedTLS gmtime_r function
pub trait MbedtlsGmtimeR: Send + Sync {
    /// Convert time_t to broken-down time representation
    ///
    /// # Arguments
    /// - `time` - The time value to convert (seconds since epoch)
    /// - `tm_buf` - The buffer to fill with the broken-down time
    ///
    /// # Returns
    /// - `Ok(())` on success, or `Err(())` on failure
    fn gmtime_r(&self, time: i64, tm_buf: &mut MbedtlsTm) -> Result<(), ()>;
}

use core::ops::Deref;

impl<T> MbedtlsGmtimeR for T
where
    T: Deref + Send + Sync,
    T::Target: MbedtlsGmtimeR,
{
    fn gmtime_r(&self, time: i64, tm_buf: &mut MbedtlsTm) -> Result<(), ()> {
        self.deref().gmtime_r(time, tm_buf)
    }
}

/// Trait representing a custom (hooked) MbedTLS ms_time function
pub trait MbedtlsMsTime: Send + Sync {
    /// Get current time in milliseconds
    ///
    /// # Returns
    /// - The current time in milliseconds since epoch
    fn ms_time(&self) -> i64;
}

impl<T> MbedtlsMsTime for T
where
    T: Deref + Send + Sync,
    T::Target: MbedtlsMsTime,
{
    fn ms_time(&self) -> i64 {
        self.deref().ms_time()
    }
}

/// Trait representing a custom (hooked) time function
pub trait MbedtlsTime: Send + Sync {
    /// Get current time in seconds
    ///
    /// # Returns
    /// - The current time in seconds since epoch
    fn time(&self) -> i64;
}

impl<T> MbedtlsTime for T
where
    T: Deref + Send + Sync,
    T::Target: MbedtlsTime,
{
    fn time(&self) -> i64 {
        self.deref().time()
    }
}

/// Hook the gmtime_r function
///
/// # Safety
/// - This function is unsafe because it modifies global state that affects
///   the behavior of MbedTLS. The caller MUST call this hook BEFORE
///   any MbedTLS functions that use time functions, and ensure that the
///   `gmtime_r` implementation is valid for the duration of its use.
#[cfg(not(feature = "nohook-time"))]
pub unsafe fn hook_gmtime_r(gmtime_r: Option<&'static (dyn MbedtlsGmtimeR + Send + Sync)>) {
    critical_section::with(|cs| {
        #[allow(clippy::if_same_then_else)]
        if gmtime_r.is_some() {
            debug!("GMTIME_R hook: added custom impl");
        } else {
            debug!("GMTIME_R hook: removed");
        }

        alt::GMTIME_R.borrow(cs).set(gmtime_r);
    });
}

/// Hook the ms_time function
///
/// # Safety
/// - This function is unsafe because it modifies global state that affects
///   the behavior of MbedTLS. The caller MUST call this hook BEFORE
///   any MbedTLS functions that use time functions, and ensure that the
///   `ms_time` implementation is valid for the duration of its use.
#[cfg(not(feature = "nohook-time"))]
pub unsafe fn hook_ms_time(ms_time: Option<&'static (dyn MbedtlsMsTime + Send + Sync)>) {
    critical_section::with(|cs| {
        #[allow(clippy::if_same_then_else)]
        if ms_time.is_some() {
            debug!("MS_TIME hook: added custom impl");
        } else {
            debug!("MS_TIME hook: removed");
        }

        alt::MS_TIME.borrow(cs).set(ms_time);
    });
}

/// Hook the time function
///
/// # Safety
/// - This function is unsafe because it modifies global state that affects
///   the behavior of MbedTLS. The caller MUST call this hook BEFORE
///   any MbedTLS functions that use time functions, and ensure that the
///   `time` implementation is valid for the duration of its use.
#[cfg(not(feature = "nohook-time"))]
pub unsafe fn hook_time(time: Option<&'static (dyn MbedtlsTime + Send + Sync)>) {
    critical_section::with(|cs| {
        #[allow(clippy::if_same_then_else)]
        if time.is_some() {
            debug!("TIME hook: added custom impl");
        } else {
            debug!("TIME hook: removed");
        }

        alt::TIME.borrow(cs).set(time);
    });
}

#[cfg(not(feature = "nohook-time"))]
mod alt {
    use core::cell::Cell;
    use core::ptr;

    use critical_section::Mutex;

    use super::{MbedtlsGmtimeR, MbedtlsMsTime, MbedtlsTime, MbedtlsTm};

    pub(crate) static GMTIME_R: Mutex<Cell<Option<&(dyn MbedtlsGmtimeR + Send + Sync)>>> =
        Mutex::new(Cell::new(None));

    pub(crate) static MS_TIME: Mutex<Cell<Option<&(dyn MbedtlsMsTime + Send + Sync)>>> =
        Mutex::new(Cell::new(None));

    pub(crate) static TIME: Mutex<Cell<Option<&(dyn MbedtlsTime + Send + Sync)>>> =
        Mutex::new(Cell::new(None));

    /// Convert time_t to broken-down time representation
    ///
    /// This is the C-compatible function that MbedTLS will call when
    /// MBEDTLS_PLATFORM_GMTIME_R_ALT is enabled.
    #[no_mangle]
    unsafe extern "C" fn mbedtls_platform_gmtime_r(
        tt: *const i64,
        tm_buf: *mut MbedtlsTm,
    ) -> *mut MbedtlsTm {
        // Validate pointers
        if tt.is_null() || tm_buf.is_null() {
            return ptr::null_mut();
        }

        let time = *tt;
        let tm_buf_ref = &mut *tm_buf;

        // Try to dispatch to hooked implementation
        let result = if let Some(gmtime_r) = critical_section::with(|cs| GMTIME_R.borrow(cs).get())
        {
            gmtime_r.gmtime_r(time, tm_buf_ref)
        } else {
            // No hook registered - return error
            Err(())
        };

        // Return tm_buf pointer on success, null on failure
        match result {
            Ok(()) => tm_buf,
            Err(()) => ptr::null_mut(),
        }
    }

    /// Get current time in milliseconds
    ///
    /// This is the C-compatible function that MbedTLS will call when
    /// MBEDTLS_PLATFORM_MS_TIME_ALT is enabled.
    #[no_mangle]
    unsafe extern "C" fn mbedtls_ms_time() -> i64 {
        // Try to dispatch to hooked implementation
        if let Some(ms_time) = critical_section::with(|cs| MS_TIME.borrow(cs).get()) {
            ms_time.ms_time()
        } else {
            // No hook registered - return 0
            0
        }
    }

    /// Default time() implementation that dispatches to our hook
    /// This is called by MbedTLS when mbedtls_time function pointer is used
    #[no_mangle]
    unsafe extern "C" fn time(timer: *mut i64) -> i64 {
        // Try to dispatch to hooked implementation
        let current_time = if let Some(time_fn) = critical_section::with(|cs| TIME.borrow(cs).get())
        {
            time_fn.time()
        } else {
            // No hook registered - return 0
            0
        };

        // If timer is not null, store the time value
        if !timer.is_null() {
            *timer = current_time;
        }

        current_time
    }
}
