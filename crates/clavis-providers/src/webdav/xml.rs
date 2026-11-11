//! Bounded WebDAV multistatus parsing without external entities. The parser
//! reads `<D:response>` href text nodes only; oversized XML is rejected.

use clavis_core::error::CoreError;

const MAX_XML_BYTES: usize = 10 * 1024 * 1024;

/// Extract href texts from a 207 multistatus document.
pub fn parse_multistatus_hrefs(bytes: &[u8]) -> Result<Vec<String>, CoreError> {
    if bytes.len() > MAX_XML_BYTES {
        return Err(CoreError::ResourceLimit);
    }
    let mut reader = quick_xml::Reader::from_reader(bytes);
    let mut hrefs = Vec::new();
    let mut buf = Vec::new();
    let mut in_href = false;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_lowercase();
                if name.ends_with("href") || name == "d:href" || name == "href" {
                    in_href = true;
                }
            }
            Ok(quick_xml::events::Event::End(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_lowercase();
                if name.ends_with("href") || name == "d:href" || name == "href" {
                    in_href = false;
                }
            }
            Ok(quick_xml::events::Event::Text(ref t)) => {
                if in_href {
                    let raw = String::from_utf8_lossy(t.as_ref()).into_owned();
                    let text = quick_xml::escape::unescape(&raw)
                        .map_err(|_| CoreError::IntegrityFailure)?
                        .into_owned();
                    // Reject external entity tricks outright.
                    if text.contains('&') && !text.contains("&amp;") {
                        return Err(CoreError::InvalidInput("unexpected entity in XML"));
                    }
                    hrefs.push(text);
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Err(CoreError::IntegrityFailure),
        }
        buf.clear();
    }
    Ok(hrefs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_namespaced_multistatus() {
        let doc = br#"<?xml version="1.0"?>
        <d:multistatus xmlns:d="DAV:">
          <d:response><d:href>/clavis/v/revisions/</d:href></d:response>
          <d:response><d:href>/clavis/v/revisions/abc.clv</d:href></d:response>
        </d:multistatus>"#;
        let hrefs = parse_multistatus_hrefs(doc).unwrap();
        assert_eq!(hrefs.len(), 2);
        assert!(hrefs[1].ends_with("abc.clv"));
    }

    #[test]
    fn rejects_unknown_entities() {
        let doc = br#"<multistatus><response><href>&xxe;</href></response></multistatus>"#;
        assert!(parse_multistatus_hrefs(doc).is_err());
    }
}
