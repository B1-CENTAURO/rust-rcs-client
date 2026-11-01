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

//! End-to-end encryption of chats (GSMA RCC.16), on the MLS of rust-rcs-core

pub mod device;
pub mod era;
pub mod ffi;
pub mod file;
pub mod group;
pub mod heal;
pub mod kds;
pub mod lost;
pub mod message;
pub mod metadata;
pub mod notes;
pub mod provisioning;
pub mod replace;
pub mod sent;
pub mod store;
pub mod upgrade;

#[cfg(test)]
mod device_tests;
#[cfg(test)]
mod ffi_tests;
#[cfg(test)]
mod group_tests;
#[cfg(test)]
mod kds_tests;
#[cfg(test)]
mod provisioning_tests;
#[cfg(test)]
mod tests;
