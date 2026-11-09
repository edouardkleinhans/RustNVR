//! ONVIF device and media services: the camera's maker and model, its video
//! profiles and their RTSP addresses (`GetStreamUri`), with WS-Security
//! `UsernameToken` authentication (password digest, dated with the camera's
//! own clock so that a camera on the wrong time still accepts it).

use crate::xml::{self, Element, escape};
use base64::Engine as _;
use rustnvr_core::Secret;
use sha1::{Digest as _, Sha1};
use std::time::Duration;

/// Usual ports of the ONVIF device service, tried when WS-Discovery gave no
/// address (Hikvision, Dahua: 80; Reolink: 8000; Tapo: 2020).
pub const DEVICE_PORTS: [u16; 5] = [80, 8000, 2020, 8080, 8899];

/// Why the camera could not be read.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum OnvifError {
    /// Nothing ONVIF answers there.
    #[error("pas de service ONVIF à cette adresse")]
    NotOnvif,
    /// Wrong user name or password (or ONVIF user not created on the camera).
    #[error(
        "la caméra refuse l'identifiant ou le mot de passe ONVIF (sur certaines caméras, il faut créer un utilisateur ONVIF dans leur interface)"
    )]
    Unauthorized,
    /// ONVIF answers, but announces no PTZ service (or no profile with a
    /// PTZ configuration).
    #[error("la caméra n'annonce pas de commande PTZ en ONVIF")]
    NoPtz,
    /// ONVIF answers, but does not implement this optional method (a camera
    /// with no presets, for instance).
    #[error("la caméra n'implémente pas cette méthode ONVIF optionnelle")]
    NotImplemented,
    /// Anything else.
    #[error("{0}")]
    Other(String),
}

/// Maker and model.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceInfo {
    /// `Manufacturer`.
    pub manufacturer: Option<String>,
    /// `Model`.
    pub model: Option<String>,
    /// `FirmwareVersion`.
    pub firmware: Option<String>,
}

/// A video stream of the camera (one ONVIF profile).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnvifStream {
    /// Profile name (`mainStream`, `Profile_1`…).
    pub profile: String,
    /// RTSP address, without credentials.
    pub url: String,
    /// `H264`, `H265`, `JPEG`…
    pub encoding: Option<String>,
    /// Picture size.
    pub width: Option<u32>,
    /// Picture size.
    pub height: Option<u32>,
}

/// An ONVIF client for one camera.
pub struct Client {
    http: reqwest::Client,
    credentials: Option<(String, Secret)>,
    /// Camera clock minus ours, in seconds.
    clock_offset: i64,
}

const NAMESPACES: &str = r#"xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl""#;

fn now_seconds() -> i64 {
    jiff::Timestamp::now().as_second()
}

/// `PasswordDigest = Base64(SHA-1(nonce + created + password))`.
fn password_digest(nonce: &[u8], created: &str, password: &str) -> String {
    let mut h = Sha1::new();
    h.update(nonce);
    h.update(created.as_bytes());
    h.update(password.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(h.finalize())
}

/// RTSP address without `user:password@`.
fn strip_credentials(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => {
            let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
            let host = authority.rsplit('@').next().unwrap_or(authority);
            format!("{scheme}://{host}{path}")
        }
        None => url.to_owned(),
    }
}

impl Client {
    /// Client with `timeout` per request.
    pub fn new(
        credentials: Option<(String, Secret)>,
        timeout: Duration,
    ) -> Result<Self, OnvifError> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout.min(Duration::from_secs(3)))
            .build()
            .map_err(|e| OnvifError::Other(e.without_url().to_string()))?;
        Ok(Self {
            http,
            credentials,
            clock_offset: 0,
        })
    }

    fn security_header(&self) -> String {
        let Some((user, password)) = &self.credentials else {
            return String::new();
        };
        let mut nonce = [0u8; 16];
        let _ = getrandom::fill(&mut nonce);
        let created = jiff::Timestamp::from_second(now_seconds() + self.clock_offset)
            .map(|t| t.to_string())
            .unwrap_or_default();
        let digest = password_digest(&nonce, &created, password.expose());
        let b64 = base64::engine::general_purpose::STANDARD.encode(nonce);
        format!(
            r#"<s:Header><wsse:Security s:mustUnderstand="1" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><wsse:UsernameToken><wsse:Username>{}</wsse:Username><wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{digest}</wsse:Password><wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{b64}</wsse:Nonce><wsu:Created>{created}</wsu:Created></wsse:UsernameToken></wsse:Security></s:Header>"#,
            escape(user)
        )
    }

    /// Posts `body` to `url`; the SOAP `Body`.
    pub(crate) async fn call(
        &self,
        url: &str,
        body: &str,
        authenticated: bool,
    ) -> Result<Element, OnvifError> {
        let header = if authenticated {
            self.security_header()
        } else {
            String::new()
        };
        let envelope = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><s:Envelope {NAMESPACES}>{header}<s:Body>{body}</s:Body></s:Envelope>"#
        );
        let response = self
            .http
            .post(url)
            .header("Content-Type", "application/soap+xml; charset=utf-8")
            .body(envelope)
            .send()
            .await
            .map_err(|e| {
                if e.is_connect() || e.is_timeout() {
                    OnvifError::NotOnvif
                } else {
                    OnvifError::Other(e.without_url().to_string())
                }
            })?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| OnvifError::Other(e.without_url().to_string()))?;
        if status.as_u16() == 401 {
            return Err(OnvifError::Unauthorized);
        }
        let root = xml::parse(&text).ok_or(OnvifError::NotOnvif)?;
        let body = root.find("Body").ok_or(OnvifError::NotOnvif)?;
        if let Some(fault) = body.find("Fault") {
            let reason = fault
                .find("Reason")
                .and_then(|r| r.find("Text"))
                .map(|t| t.text.trim().to_owned())
                .unwrap_or_default();
            let codes = {
                let mut v = Vec::new();
                fault.find_all("Value", &mut v);
                v.iter()
                    .map(|c| c.text.clone())
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            let refused = codes.contains("NotAuthorized")
                || codes.contains("FailedAuthentication")
                || reason.to_ascii_lowercase().contains("auth");
            let missing = codes.contains("NotImplemented")
                || codes.contains("NotSupported")
                || reason.to_ascii_lowercase().contains("not implemented");
            return Err(if refused {
                OnvifError::Unauthorized
            } else if missing {
                OnvifError::NotImplemented
            } else {
                OnvifError::Other(format!(
                    "la caméra répond une erreur ONVIF : {}",
                    if reason.is_empty() { codes } else { reason }
                ))
            });
        }
        if !status.is_success() {
            return Err(OnvifError::Other(format!("réponse HTTP {status}")));
        }
        Ok(body.clone())
    }

    /// Reads the camera clock (no authentication: also proves ONVIF answers
    /// at `device_url`).
    pub async fn sync_clock(&mut self, device_url: &str) -> Result<(), OnvifError> {
        let body = self
            .call(device_url, "<tds:GetSystemDateAndTime/>", false)
            .await?;
        let utc = body.find("UTCDateTime").ok_or(OnvifError::NotOnvif)?;
        let n = |path: &[&str]| utc.text_at(path).and_then(|v| v.parse::<i16>().ok());
        if let (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(s)) = (
            n(&["Date", "Year"]),
            n(&["Date", "Month"]),
            n(&["Date", "Day"]),
            n(&["Time", "Hour"]),
            n(&["Time", "Minute"]),
            n(&["Time", "Second"]),
        ) && let Ok(t) =
            jiff::civil::datetime(y, mo as i8, d as i8, h as i8, mi as i8, s as i8, 0)
                .to_zoned(jiff::tz::TimeZone::UTC)
        {
            self.clock_offset = t.timestamp().as_second() - now_seconds();
        }
        Ok(())
    }

    /// Maker, model, firmware.
    pub async fn device_information(&self, device_url: &str) -> Result<DeviceInfo, OnvifError> {
        let body = self
            .call(device_url, "<tds:GetDeviceInformation/>", true)
            .await?;
        let r = body
            .find("GetDeviceInformationResponse")
            .ok_or(OnvifError::NotOnvif)?;
        let get = |n: &str| r.text_at(&[n]).map(str::to_owned);
        Ok(DeviceInfo {
            manufacturer: get("Manufacturer"),
            model: get("Model"),
            firmware: get("FirmwareVersion"),
        })
    }

    /// Address of the media service (the device service when not told).
    pub async fn media_url(&self, device_url: &str) -> Result<String, OnvifError> {
        let body = self
            .call(
                device_url,
                "<tds:GetCapabilities><tds:Category>Media</tds:Category></tds:GetCapabilities>",
                true,
            )
            .await?;
        Ok(body
            .find("Media")
            .and_then(|m| m.text_at(&["XAddr"]))
            .map(str::to_owned)
            .unwrap_or_else(|| device_url.to_owned()))
    }

    /// Video profiles and their RTSP addresses, largest picture first.
    pub async fn streams(&self, media_url: &str) -> Result<Vec<OnvifStream>, OnvifError> {
        let body = self.call(media_url, "<trt:GetProfiles/>", true).await?;
        let mut profiles = Vec::new();
        body.find_all("Profiles", &mut profiles);
        let mut out = Vec::new();
        for p in profiles {
            let Some(token) = p.attr("token") else {
                continue;
            };
            let encoder = p.find("VideoEncoderConfiguration");
            let size = |n: &str| {
                encoder
                    .and_then(|e| e.find("Resolution"))
                    .and_then(|r| r.text_at(&[n]))
                    .and_then(|v| v.parse().ok())
            };
            let request = format!(
                "<trt:GetStreamUri><trt:StreamSetup><tt:Stream>RTP-Unicast</tt:Stream><tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trt:StreamSetup><trt:ProfileToken>{}</trt:ProfileToken></trt:GetStreamUri>",
                escape(token)
            );
            let uri = match self.call(media_url, &request, true).await {
                Ok(b) => b
                    .find("MediaUri")
                    .and_then(|m| m.text_at(&["Uri"]))
                    .map(strip_credentials),
                Err(OnvifError::Unauthorized) => return Err(OnvifError::Unauthorized),
                Err(e) => {
                    tracing::debug!(profile = token, error = %e, "ONVIF GetStreamUri failed");
                    None
                }
            };
            let Some(url) = uri.filter(|u| u.starts_with("rtsp://")) else {
                continue;
            };
            // Several profiles may share one stream.
            if out.iter().any(|s: &OnvifStream| s.url == url) {
                continue;
            }
            out.push(OnvifStream {
                profile: p.text_at(&["Name"]).unwrap_or(token).to_owned(),
                url,
                encoding: encoder
                    .and_then(|e| e.text_at(&["Encoding"]))
                    .map(str::to_owned),
                width: size("Width"),
                height: size("Height"),
            });
        }
        out.sort_by_key(|s| {
            std::cmp::Reverse(u64::from(s.width.unwrap_or(0)) * u64::from(s.height.unwrap_or(0)))
        });
        Ok(out)
    }
}

/// Everything about a camera: finds its device service (`device_url`, or
/// the usual ports of `host`), then its maker and streams.
pub async fn read_camera(
    host: &str,
    device_url: Option<&str>,
    credentials: Option<(String, Secret)>,
    timeout: Duration,
) -> Result<(String, DeviceInfo, Vec<OnvifStream>), OnvifError> {
    let mut client = Client::new(credentials, timeout)?;
    let candidates: Vec<String> = match device_url {
        Some(u) => vec![u.to_owned()],
        None => DEVICE_PORTS
            .iter()
            .map(|p| match p {
                80 => format!("http://{host}/onvif/device_service"),
                p => format!("http://{host}:{p}/onvif/device_service"),
            })
            .collect(),
    };
    let mut url = None;
    for c in candidates {
        match client.sync_clock(&c).await {
            Ok(()) => {
                url = Some(c);
                break;
            }
            Err(OnvifError::NotOnvif) => continue,
            // Answered, but differently (auth on everything): ONVIF is there.
            Err(_) => {
                url = Some(c);
                break;
            }
        }
    }
    let url = url.ok_or(OnvifError::NotOnvif)?;
    let info = client.device_information(&url).await?;
    let media = client.media_url(&url).await?;
    let streams = client.streams(&media).await?;
    Ok((url, info, streams))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    #[test]
    fn digest_and_credentials() {
        // Example of the WS-Security UsernameToken profile.
        let nonce = base64::engine::general_purpose::STANDARD
            .decode("LKqI6G/AikKCQrN0zqZFlg==")
            .expect("nonce");
        assert_eq!(
            password_digest(&nonce, "2010-09-16T07:50:45Z", "userpassword"),
            "tuOSpGlFlIXsozq4HFNeeGeFLEI="
        );
        assert_eq!(
            strip_credentials("rtsp://admin:pw@192.168.1.20:554/Streaming/Channels/101"),
            "rtsp://192.168.1.20:554/Streaming/Channels/101"
        );
        assert_eq!(strip_credentials("rtsp://h/a@b"), "rtsp://h/a@b");
    }

    fn soap(body: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="d" xmlns:trt="m" xmlns:tt="s"><SOAP-ENV:Body>{body}</SOAP-ENV:Body></SOAP-ENV:Envelope>"#
        )
    }

    /// A fake ONVIF camera: answers by request, refuses requests without
    /// credentials (except the clock).
    async fn camera() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut req = Vec::new();
                    let mut buf = [0u8; 8192];
                    // Headers then the announced body.
                    loop {
                        let Ok(n) = s.read(&mut buf).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        req.extend_from_slice(&buf[..n]);
                        let text = String::from_utf8_lossy(&req);
                        if let Some(end) = text.find("\r\n\r\n") {
                            let len = text[..end]
                                .lines()
                                .find_map(|l| {
                                    l.to_ascii_lowercase()
                                        .strip_prefix("content-length:")
                                        .and_then(|v| v.trim().parse::<usize>().ok())
                                })
                                .unwrap_or(0);
                            if req.len() >= end + 4 + len {
                                break;
                            }
                        }
                    }
                    let text = String::from_utf8_lossy(&req).into_owned();
                    let authed = text.contains("<wsse:Username>admin</wsse:Username>");
                    let body = if text.contains("GetSystemDateAndTime") {
                        soap(
                            "<tds:GetSystemDateAndTimeResponse><tds:SystemDateAndTime><tt:UTCDateTime><tt:Time><tt:Hour>8</tt:Hour><tt:Minute>0</tt:Minute><tt:Second>0</tt:Second></tt:Time><tt:Date><tt:Year>2030</tt:Year><tt:Month>1</tt:Month><tt:Day>2</tt:Day></tt:Date></tt:UTCDateTime></tds:SystemDateAndTime></tds:GetSystemDateAndTimeResponse>",
                        )
                    } else if !authed {
                        soap(
                            "<SOAP-ENV:Fault><SOAP-ENV:Code><SOAP-ENV:Value>SOAP-ENV:Sender</SOAP-ENV:Value><SOAP-ENV:Subcode><SOAP-ENV:Value>ter:NotAuthorized</SOAP-ENV:Value></SOAP-ENV:Subcode></SOAP-ENV:Code><SOAP-ENV:Reason><SOAP-ENV:Text>Sender not Authorized</SOAP-ENV:Text></SOAP-ENV:Reason></SOAP-ENV:Fault>",
                        )
                    } else if text.contains("GetDeviceInformation") {
                        soap(
                            "<tds:GetDeviceInformationResponse><tds:Manufacturer>Dahua</tds:Manufacturer><tds:Model>IPC-HDW2431T</tds:Model><tds:FirmwareVersion>2.8</tds:FirmwareVersion></tds:GetDeviceInformationResponse>",
                        )
                    } else if text.contains("GetCapabilities") {
                        soap(&format!(
                            "<tds:GetCapabilitiesResponse><tds:Capabilities><tt:Media><tt:XAddr>http://{addr}/onvif/media_service</tt:XAddr></tt:Media></tds:Capabilities></tds:GetCapabilitiesResponse>"
                        ))
                    } else if text.contains("GetProfiles") {
                        soap(
                            "<trt:GetProfilesResponse><trt:Profiles token=\"MediaProfile001\"><tt:Name>Sub</tt:Name><tt:VideoEncoderConfiguration><tt:Encoding>H264</tt:Encoding><tt:Resolution><tt:Width>704</tt:Width><tt:Height>576</tt:Height></tt:Resolution></tt:VideoEncoderConfiguration></trt:Profiles><trt:Profiles token=\"MediaProfile000\"><tt:Name>Main</tt:Name><tt:VideoEncoderConfiguration><tt:Encoding>H265</tt:Encoding><tt:Resolution><tt:Width>2688</tt:Width><tt:Height>1520</tt:Height></tt:Resolution></tt:VideoEncoderConfiguration></trt:Profiles></trt:GetProfilesResponse>",
                        )
                    } else if text.contains("MediaProfile000") {
                        soap(
                            "<trt:GetStreamUriResponse><trt:MediaUri><tt:Uri>rtsp://192.168.1.21:554/cam/realmonitor?channel=1&amp;subtype=0&amp;unicast=true</tt:Uri></trt:MediaUri></trt:GetStreamUriResponse>",
                        )
                    } else {
                        soap(
                            "<trt:GetStreamUriResponse><trt:MediaUri><tt:Uri>rtsp://192.168.1.21:554/cam/realmonitor?channel=1&amp;subtype=1&amp;unicast=true</tt:Uri></trt:MediaUri></trt:GetStreamUriResponse>",
                        )
                    };
                    let answer = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(answer.as_bytes()).await;
                });
            }
        });
        format!("http://{addr}/onvif/device_service")
    }

    #[tokio::test]
    async fn reads_a_camera_and_its_streams() {
        let url = camera().await;
        let creds = Some(("admin".to_owned(), Secret::new("pw".to_owned())));
        let (found, info, streams) =
            read_camera("127.0.0.1", Some(&url), creds, Duration::from_secs(5))
                .await
                .expect("camera");
        assert_eq!(found, url);
        assert_eq!(info.manufacturer.as_deref(), Some("Dahua"));
        assert_eq!(info.model.as_deref(), Some("IPC-HDW2431T"));
        assert_eq!(streams.len(), 2);
        assert_eq!(
            (
                streams[0].profile.as_str(),
                streams[0].encoding.as_deref(),
                streams[0].width
            ),
            ("Main", Some("H265"), Some(2688))
        );
        assert_eq!(
            streams[0].url,
            "rtsp://192.168.1.21:554/cam/realmonitor?channel=1&subtype=0&unicast=true"
        );
        assert_eq!(streams[1].profile, "Sub");

        // Wrong user: refused, said as such.
        let bad = Some(("other".to_owned(), Secret::new("x".to_owned())));
        assert_eq!(
            read_camera("127.0.0.1", Some(&url), bad, Duration::from_secs(5))
                .await
                .map(|_| ()),
            Err(OnvifError::Unauthorized)
        );
        // Nothing there.
        assert_eq!(
            read_camera(
                "127.0.0.1",
                Some("http://127.0.0.1:9/onvif/device_service"),
                None,
                Duration::from_secs(2)
            )
            .await
            .map(|_| ()),
            Err(OnvifError::NotOnvif)
        );
    }
}
