//! Hook for mbedtls_mpi_exp_mod

use core::ops::Deref;

use crate::{mbedtls_mpi, MbedtlsError};

/// Trait representing a custom (hooked) MbedTLS modular exponentiation function
/// Z = X ^ Y mod M
pub trait MbedtlsMpiExpMod {
    /// Perform modular exponentiation
    ///
    /// # Arguments
    /// - `z` - The result of the modular exponentiation
    /// - `x` - The base
    /// - `y` - The exponent
    /// - `m` - The modulus
    /// - `prec_rr` - Optional precomputed value for optimization
    ///
    /// # Returns
    /// - `Ok(())` on success, or `Err(MbedtlsError)` on failure
    fn exp_mod(
        &self,
        z: &mut mbedtls_mpi,
        x: &mbedtls_mpi,
        y: &mbedtls_mpi,
        m: &mbedtls_mpi,
        prec_rr: Option<&mut mbedtls_mpi>,
    ) -> Result<(), MbedtlsError>;
}

impl<T> MbedtlsMpiExpMod for T
where
    T: Deref,
    T::Target: MbedtlsMpiExpMod,
{
    fn exp_mod(
        &self,
        z: &mut mbedtls_mpi,
        x: &mbedtls_mpi,
        y: &mbedtls_mpi,
        m: &mbedtls_mpi,
        prec_rr: Option<&mut mbedtls_mpi>,
    ) -> Result<(), MbedtlsError> {
        self.deref().exp_mod(z, x, y, m, prec_rr)
    }
}

/// Hook the modular exponentiation function
///
/// # Safety
/// - This function is unsafe because it modifies global state that affects
///   the behavior of MbedTLS. The caller MUST call this hook BEFORE
///   any MbedTLS functions that use modular exponentiation, and ensure that the
///   `exp_mod` implementation is valid for the duration of its use.
#[cfg(not(feature = "nohook-exp-mod"))]
pub unsafe fn hook_exp_mod(exp_mod: Option<&'static (dyn MbedtlsMpiExpMod + Send + Sync)>) {
    critical_section::with(|cs| {
        #[allow(clippy::if_same_then_else)]
        if exp_mod.is_some() {
            debug!("RSA-EXP-MOD hook: added custom/HW accelerated impl");
        } else {
            debug!("RSA-EXP-MOD hook: removed");
        }

        alt::EXP_MOD.borrow(cs).set(exp_mod);
    });
}

#[cfg(not(feature = "nohook-exp-mod"))]
pub(crate) mod alt {
    use core::cell::Cell;
    use core::ffi::c_int;

    use critical_section::Mutex;

    use crate::{
        mbedtls_mpi, mbedtls_mpi_bitlen, mbedtls_mpi_copy, mbedtls_mpi_free, mbedtls_mpi_get_bit,
        mbedtls_mpi_init, mbedtls_mpi_lset, mbedtls_mpi_mod_mpi, mbedtls_mpi_mul_mpi, MbedtlsError,
    };

    use super::MbedtlsMpiExpMod;

    pub(crate) static EXP_MOD: Mutex<Cell<Option<&(dyn MbedtlsMpiExpMod + Send + Sync)>>> =
        Mutex::new(Cell::new(None));
    pub(crate) static EXP_MOD_FALLBACK: FallbackMpiExpMod = FallbackMpiExpMod::new();

    pub struct FallbackMpiExpMod(());

    impl FallbackMpiExpMod {
        pub const fn new() -> Self {
            Self(())
        }
    }

    impl Default for FallbackMpiExpMod {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MbedtlsMpiExpMod for FallbackMpiExpMod {
        fn exp_mod(
            &self,
            z: &mut mbedtls_mpi,
            x: &mbedtls_mpi,
            y: &mbedtls_mpi,
            m: &mbedtls_mpi,
            _prec_rr: Option<&mut mbedtls_mpi>,
        ) -> Result<(), MbedtlsError> {
            // Software fallback using square-and-multiply algorithm
            // This replaces the mbedtls_mpi_exp_mod_soft() call which no longer exists in mbedtls 3.6.5
            unsafe {
                // Initialize result to 1: z = 1
                let mut result = mbedtls_mpi_lset(z, 1);
                if result != 0 {
                    return Err(MbedtlsError::new(result));
                }

                // Create a copy of the base
                let mut base: mbedtls_mpi = core::mem::zeroed();
                mbedtls_mpi_init(&mut base);
                result = mbedtls_mpi_copy(&mut base, x);
                if result != 0 {
                    mbedtls_mpi_free(&mut base);
                    return Err(MbedtlsError::new(result));
                }

                // Get bit length of exponent
                let bits = mbedtls_mpi_bitlen(y);

                // Square-and-multiply algorithm
                // For each bit in the exponent (from MSB to LSB):
                //   - Square the current result
                //   - If the bit is set, multiply by the base
                for i in (0..bits).rev() {
                    // Square: z = z * z mod m
                    result = mbedtls_mpi_mul_mpi(z, z, z);
                    if result != 0 {
                        mbedtls_mpi_free(&mut base);
                        return Err(MbedtlsError::new(result));
                    }
                    result = mbedtls_mpi_mod_mpi(z, z, m);
                    if result != 0 {
                        mbedtls_mpi_free(&mut base);
                        return Err(MbedtlsError::new(result));
                    }

                    // If bit is set: z = z * base mod m
                    if mbedtls_mpi_get_bit(y, i) == 1 {
                        result = mbedtls_mpi_mul_mpi(z, z, &base);
                        if result != 0 {
                            mbedtls_mpi_free(&mut base);
                            return Err(MbedtlsError::new(result));
                        }
                        result = mbedtls_mpi_mod_mpi(z, z, m);
                        if result != 0 {
                            mbedtls_mpi_free(&mut base);
                            return Err(MbedtlsError::new(result));
                        }
                    }
                }

                mbedtls_mpi_free(&mut base);
                Ok(())
            }
        }
    }

    /// Z = X ^ Y mod M
    #[no_mangle]
    unsafe extern "C" fn mbedtls_mpi_exp_mod(
        z: *mut mbedtls_mpi,
        x: *const mbedtls_mpi,
        y: *const mbedtls_mpi,
        m: *const mbedtls_mpi,
        prec_rr: *mut mbedtls_mpi,
    ) -> c_int {
        let result = if let Some(exp_mod) = critical_section::with(|cs| EXP_MOD.borrow(cs).get()) {
            exp_mod.exp_mod(&mut *z, &*x, &*y, &*m, prec_rr.as_mut())
        } else {
            EXP_MOD_FALLBACK.exp_mod(&mut *z, &*x, &*y, &*m, prec_rr.as_mut())
        };

        result.map_or_else(|e| e.code(), |_| 0)
    }
}
