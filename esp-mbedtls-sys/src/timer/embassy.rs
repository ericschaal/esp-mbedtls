
use crate::hook::timer::MbedtlsTimer;
pub static TIMER: EmbassyTimerBackend = EmbassyTimerBackend;

pub struct EmbassyTimerBackend;
impl MbedtlsTimer for EmbassyTimerBackend {
    fn now(&self) -> u64 {
        embassy_time::Instant::now().as_millis()
    }
}

pub struct EmbassyTimer;

impl EmbassyTimer {
    pub fn new() -> Self {
        unsafe  {
            crate::hook::timer::hook_timer(Some(&TIMER));
        }
        Self
    }
}

impl Drop for EmbassyTimer {
    fn drop(&mut self) {
        unsafe {
            crate::hook::timer::hook_timer(None);
        }
    }
}
