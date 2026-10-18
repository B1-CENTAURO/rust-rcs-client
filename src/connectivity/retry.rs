// Copyright 2023 宋昊文
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::time::Duration;

use uuid::Uuid;

/// When to register again once a registration has ended
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Reconnect {
    /// At once, as when the network deactivates a registration
    Now,
    /// After the backoff of RFC 5626 section 4.5
    Backoff,
    /// After the time the network gave, if longer than the backoff
    After(Duration),
    /// Only when asked to connect again, as when the network rejects the
    /// registration
    Never,
}

/// The time to wait before trying again after `failures` attempts in a row
/// have failed (RFC 5626 section 4.5): 30 s doubled for each failure up to
/// 30 minutes, of which a random 50 to 100 percent is taken
pub fn backoff(failures: u32) -> Duration {
    let base: u64 = 30;
    let max: u64 = 1800;
    let wait = max.min(base << failures.min(6));
    let random = (Uuid::new_v4().as_u128() % 1001) as u64; // 0 to 1000
    Duration::from_millis(wait * (500 + random / 2))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::backoff;

    #[test]
    fn the_backoff_doubles_up_to_half_an_hour_and_is_randomised() {
        for (failures, max) in [(0, 30), (1, 60), (2, 120), (5, 960), (6, 1800), (40, 1800)] {
            for _ in 0..50 {
                let wait = backoff(failures);
                assert!(
                    wait >= Duration::from_secs(max) / 2,
                    "{} {:?}",
                    failures,
                    wait
                );
                assert!(wait <= Duration::from_secs(max), "{} {:?}", failures, wait);
            }
        }
    }
}
