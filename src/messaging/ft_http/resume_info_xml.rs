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

use quick_xml::{
    events::{BytesStart, Event},
    Reader,
};

pub struct ResumeInfo {
    pub range_start: usize,
    pub range_end: usize,
    pub data_url: String,
}

/// Reads to the end of the element whose start was just read
fn skip_element<R>(xml_reader: &mut Reader<R>, buf: &mut Vec<u8>)
where
    R: std::io::BufRead,
{
    let mut level = 1;

    loop {
        match xml_reader.read_event_into(buf) {
            Ok(Event::Start(ref _e)) => {
                level += 1;
            }

            Ok(Event::End(_)) => {
                level -= 1;
                if level == 0 {
                    break;
                }
            }

            Ok(Event::Eof) | Err(_) => {
                break;
            }

            _ => {}
        }
    }
}

fn parse_file_range_element<R>(
    xml_reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
    e: &BytesStart,
    level: i32,
) -> Option<(usize, usize)>
where
    R: std::io::BufRead,
{
    let mut start: Option<usize> = None;
    let mut end: Option<usize> = None;

    for attribute in e.attributes() {
        if let Ok(attribute) = attribute {
            if attribute.key.as_ref() == b"start" {
                if let Ok(attribute_value) = attribute.unescape_value() {
                    if let Ok(attribute_value) = attribute_value.parse::<usize>() {
                        start.replace(attribute_value);
                    }
                }
            } else if attribute.key.as_ref() == b"end" {
                if let Ok(attribute_value) = attribute.unescape_value() {
                    if let Ok(attribute_value) = attribute_value.parse::<usize>() {
                        end.replace(attribute_value);
                    }
                }
            }
        }
    }

    // the rest of the element, if it has any: an empty one ends where it
    // starts
    if level > 0 {
        skip_element(xml_reader, buf);
    }

    if let (Some(start), Some(end)) = (start, end) {
        return Some((start, end));
    }

    None
}

fn parse_data_element<R>(
    xml_reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
    e: &BytesStart,
    level: i32,
) -> Option<String>
where
    R: std::io::BufRead,
{
    let mut url: Option<String> = None;

    for attribute in e.attributes() {
        if let Ok(attribute) = attribute {
            if attribute.key.as_ref() == b"url" {
                if let Ok(attribute_value) = attribute.unescape_value() {
                    url.replace(attribute_value.into_owned());
                }
            }
        }
    }

    // the rest of the element, if it has any: an empty one ends where it
    // starts
    if level > 0 {
        skip_element(xml_reader, buf);
    }

    return url;
}

fn parse_file_resume_info<R>(
    xml_reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
    _e: &BytesStart,
    level: i32,
) -> Option<ResumeInfo>
where
    R: std::io::BufRead,
{
    let mut file_range = None;
    let mut data = None;

    let mut handle_element = |xml_reader: &mut Reader<R>, e: &BytesStart, level: i32| -> bool {
        if e.name().as_ref().eq_ignore_ascii_case(b"file-range") {
            let mut buf = Vec::new();
            file_range = parse_file_range_element(xml_reader, &mut buf, e, level);
            return true;
        } else if e.name().as_ref().eq_ignore_ascii_case(b"data") {
            let mut buf = Vec::new();
            data = parse_data_element(xml_reader, &mut buf, e, level);
            return true;
        }

        false
    };

    let mut level = level;

    if level > 0 {
        loop {
            match xml_reader.read_event_into(buf) {
                Ok(Event::Start(ref e)) => {
                    if !handle_element(xml_reader, e, 1) {
                        level += 1;
                    }
                }

                Ok(Event::Empty(ref e)) => {
                    handle_element(xml_reader, e, 0);
                }

                Ok(Event::End(_)) => {
                    level -= 1;
                    if level == 0 {
                        break;
                    }
                }

                Ok(Event::Eof) | Err(_) => {
                    break;
                }

                _ => {}
            }
        }
    }

    if let (Some((range_start, range_end)), Some(data_url)) = (file_range, data) {
        return Some(ResumeInfo {
            range_start,
            range_end,
            data_url,
        });
    }

    None
}

pub fn parse_xml(data: &[u8]) -> Option<ResumeInfo> {
    let mut xml_reader = Reader::from_reader(data);

    let mut buf = Vec::new();
    loop {
        match xml_reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                if e.name().as_ref().eq_ignore_ascii_case(b"file-resume-info") {
                    let mut buf = Vec::new();
                    return parse_file_resume_info(&mut xml_reader, &mut buf, e, 1);
                }
            }

            Ok(Event::Empty(ref e)) => {
                if e.name().as_ref().eq_ignore_ascii_case(b"file-resume-info") {
                    let mut buf = Vec::new();
                    return parse_file_resume_info(&mut xml_reader, &mut buf, e, 0);
                }
            }

            Ok(Event::Eof) | Err(_) => {
                break;
            }

            _ => {}
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::parse_xml;

    #[test]
    fn resume_info_is_read_with_empty_elements_and_with_content() {
        for xml in [
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<file-resume-info>\n\
  <file-range start=\"0\" end=\"4499\"/>\n\
  <data url=\"https://ftcs.example.com/upload/1?a=1&amp;b=2\"/>\n\
</file-resume-info>",
            "<file-resume-info><file-range start=\"0\" end=\"4499\"></file-range>\
<data url=\"https://ftcs.example.com/upload/1?a=1&amp;b=2\"><x/></data></file-resume-info>",
        ] {
            let info = parse_xml(xml.as_bytes()).expect(xml);
            assert_eq!((info.range_start, info.range_end), (0, 4499));
            assert_eq!(info.data_url, "https://ftcs.example.com/upload/1?a=1&b=2");
        }
    }

    #[test]
    fn resume_info_without_a_range_or_a_url_is_not_read() {
        assert!(parse_xml(
            b"<file-resume-info><data url=\"https://a.example.com/\"/></file-resume-info>"
        )
        .is_none());
        assert!(parse_xml(
            b"<file-resume-info><file-range start=\"0\" end=\"1\"/></file-resume-info>"
        )
        .is_none());
    }
}
