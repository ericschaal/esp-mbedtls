use crate::bindings::tm;
pub trait MbedtlsWallClock {
    /// Get current wall clock time as broken-down time structure.
    ///
    /// Returns the current calendar time in UTC as a `tm` structure.
    ///
    /// # Returns
    /// - `tm` - Current time as a broken-down time structure
    fn instant(&self) -> tm;
}

/// Hook the wall clock function
///
/// # Safety
/// - This function is unsafe because it modifies global state that affects
///   the behavior of MbedTLS. The caller MUST call this hook BEFORE
///   any MbedTLS functions that need wall clock time (e.g., X.509 certificate
///   time validation), and ensure that the wall clock implementation is valid
///   for the duration of its use.
#[cfg(not(feature = "nohook-wall-clock"))]
pub unsafe fn hook_wall_clock(wc: Option<&'static (dyn MbedtlsWallClock + Send + Sync)>) {
    critical_section::with(|cs| {
        #[allow(clippy::if_same_then_else)]
        if wc.is_some() {
            debug!("Wall Clock hook: added custom impl");
        } else {
            debug!("Wall Clock hook: removed");
        }

        alt::WALL_CLOCK.borrow(cs).set(wc);
    });
}

#[cfg(not(feature = "nohook-wall-clock"))]
mod alt {
    use crate::bindings::tm;
    use core::cell::Cell;
    use core::ptr;
    use critical_section::Mutex;

    use super::MbedtlsWallClock;

    pub(crate) static WALL_CLOCK: Mutex<Cell<Option<&(dyn MbedtlsWallClock + Send + Sync)>>> =
        Mutex::new(Cell::new(None));

    /// Get current wall clock time as broken-down time in UTC.
    ///
    /// This function returns the current wall clock time as a broken-down time structure.
    /// The timestamp parameter is ignored for compatibility with the MbedTLS platform API.
    ///
    /// # Parameters
    /// - `_tt`: Ignored (exists for MbedTLS platform API compatibility)
    /// - `tm_buf`: Pointer to buffer where the result will be written
    ///
    /// # Returns
    /// a pointer to `tm_buf` on success, or null if:
    /// - `tm_buf` is null
    /// - No wall clock implementation is hooked
    #[no_mangle]
    pub unsafe extern "C" fn mbedtls_platform_gmtime_r(
        _tt: *const i64,
        tm_buf: *mut tm,
    ) -> *mut tm {
        if tm_buf.is_null() {
            return ptr::null_mut();
        }

        critical_section::with(|cs| {
            WALL_CLOCK
                .borrow(cs)
                .get()
                .map(|wc| {
                    *tm_buf = wc.instant();
                    tm_buf
                })
                .unwrap_or(ptr::null_mut())
        })
    }
}
