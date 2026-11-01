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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use uuid::Uuid;

pub mod config;
pub mod content_server;
pub mod download;
pub mod resume_info_xml;
pub mod upload;

pub use content_server::{ContentServer, Credentials};
pub use download::download_file;

pub use upload::upload_file;
pub use upload::upload_sealed_file;
pub use upload::FileInfo;

pub struct FileTransferOverHTTPService {
    recorded_tids: Arc<Mutex<Vec<Uuid>>>,
    /// The files of the uploads sealed before they are uploaded, by tid, for
    /// an upload resumed to go on with what was sealed for it
    sealed: Arc<Mutex<HashMap<Uuid, upload::SealedUpload>>>,
}

impl FileTransferOverHTTPService {
    pub fn new() -> FileTransferOverHTTPService {
        FileTransferOverHTTPService {
            recorded_tids: Arc::new(Mutex::new(Vec::with_capacity(1024))),
            sealed: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[cfg(test)]
mod tests;
