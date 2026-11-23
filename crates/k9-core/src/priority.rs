//! Low process priority so scans never compete with games.

use windows::Win32::System::Threading::{
    GetCurrentProcess, ProcessPowerThrottling, SetPriorityClass, SetProcessInformation, BELOW_NORMAL_PRIORITY_CLASS,
    PROCESS_MODE_BACKGROUND_BEGIN, PROCESS_POWER_THROTTLING_CURRENT_VERSION, PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
    PROCESS_POWER_THROTTLING_STATE,
};

/// Sets BELOW_NORMAL priority, background mode (low I/O and memory priority)
/// and EcoQoS ("Effizienzmodus"). Failures are logged, not fatal.
pub fn enter_background_mode() {
    // SAFETY: pseudo handle of the current process, valid structure sizes.
    unsafe {
        let me = GetCurrentProcess();
        if let Err(e) = SetPriorityClass(me, BELOW_NORMAL_PRIORITY_CLASS) {
            tracing::warn!("BELOW_NORMAL_PRIORITY_CLASS nicht gesetzt: {e}");
        }
        if let Err(e) = SetPriorityClass(me, PROCESS_MODE_BACKGROUND_BEGIN) {
            tracing::warn!("PROCESS_MODE_BACKGROUND_BEGIN nicht gesetzt: {e}");
        }
        let state = PROCESS_POWER_THROTTLING_STATE {
            Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
            ControlMask: PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
            StateMask: PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
        };
        if let Err(e) = SetProcessInformation(
            me,
            ProcessPowerThrottling,
            &state as *const _ as *const _,
            std::mem::size_of::<PROCESS_POWER_THROTTLING_STATE>() as u32,
        ) {
            tracing::debug!("EcoQoS nicht verfügbar: {e}");
        }
    }
}

/// Only lowers the CPU priority (used for interactive `k9 scan`).
pub fn below_normal() {
    // SAFETY: pseudo handle of the current process.
    unsafe {
        let _ = SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
    }
}
