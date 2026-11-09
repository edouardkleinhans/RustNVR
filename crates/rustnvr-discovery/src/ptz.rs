//! ONVIF PTZ: moving a motorised camera (pan, tilt, zoom) and its presets,
//! through the PTZ service the camera announces in `GetCapabilities`, on the
//! first media profile that has a PTZ configuration.

use crate::onvif::{Client, OnvifError};
use crate::xml::{Element, escape};
use rustnvr_core::Secret;
use std::time::Duration;

/// A position stored on the camera.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preset {
    /// Its token, used to recall it.
    pub token: String,
    /// Its name (the token when the camera gives none).
    pub name: String,
}

/// Speeds of a continuous move, each from -1 to 1: pan (right > 0), tilt
/// (up > 0), zoom (in > 0).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Velocity {
    /// Left (< 0) or right (> 0).
    pub pan: f32,
    /// Down (< 0) or up (> 0).
    pub tilt: f32,
    /// Out (< 0) or in (> 0).
    pub zoom: f32,
}

/// A camera ready to be moved: its PTZ service and the profile to move.
pub struct PtzCamera {
    client: Client,
    ptz_url: String,
    profile: String,
}

/// `v` as an ONVIF speed, clamped to [-1, 1].
fn speed(v: f32) -> String {
    let v = if v.is_finite() {
        v.clamp(-1.0, 1.0)
    } else {
        0.0
    };
    format!("{v:.3}")
}

/// ISO 8601 duration of a whole number of seconds (`PT10S`).
fn duration(d: Duration) -> String {
    format!("PT{}S", d.as_secs().max(1))
}

/// The presets of a `GetPresetsResponse`.
fn presets_of(body: &Element) -> Vec<Preset> {
    let mut found = Vec::new();
    body.find_all("Preset", &mut found);
    found
        .into_iter()
        .filter_map(|p| {
            let token = p.attr("token")?.to_owned();
            let name = p.text_at(&["Name"]).unwrap_or(&token).to_owned();
            Some(Preset { token, name })
        })
        .collect()
}

impl PtzCamera {
    /// Finds the PTZ service of the camera whose device service is at
    /// `device_url`, and its first profile with a PTZ configuration.
    pub async fn connect(
        device_url: &str,
        credentials: Option<(String, Secret)>,
        timeout: Duration,
    ) -> Result<Self, OnvifError> {
        let mut client = Client::new(credentials, timeout)?;
        client.sync_clock(device_url).await?;
        let caps = client
            .call(
                device_url,
                "<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>",
                true,
            )
            .await?;
        let xaddr = |service: &str| {
            caps.find(service)
                .and_then(|s| s.text_at(&["XAddr"]))
                .map(str::to_owned)
        };
        let ptz_url = xaddr("PTZ").ok_or(OnvifError::NoPtz)?;
        let media_url = xaddr("Media").unwrap_or_else(|| device_url.to_owned());
        let profiles = client.call(&media_url, "<trt:GetProfiles/>", true).await?;
        let mut all = Vec::new();
        profiles.find_all("Profiles", &mut all);
        let profile = all
            .into_iter()
            .find(|p| p.find("PTZConfiguration").is_some())
            .and_then(|p| p.attr("token"))
            .ok_or(OnvifError::NoPtz)?
            .to_owned();
        Ok(Self {
            client,
            ptz_url,
            profile,
        })
    }

    async fn ptz(&self, body: &str) -> Result<Element, OnvifError> {
        self.client.call(&self.ptz_url, body, true).await
    }

    fn profile_token(&self) -> String {
        format!(
            "<tptz:ProfileToken>{}</tptz:ProfileToken>",
            escape(&self.profile)
        )
    }

    /// Moves at `velocity` until [`Self::stop`], or for `timeout` at most
    /// (in case the stop never comes).
    pub async fn continuous_move(
        &self,
        velocity: Velocity,
        timeout: Duration,
    ) -> Result<(), OnvifError> {
        let mut v = String::new();
        if velocity.pan != 0.0 || velocity.tilt != 0.0 {
            v.push_str(&format!(
                r#"<tt:PanTilt x="{}" y="{}"/>"#,
                speed(velocity.pan),
                speed(velocity.tilt)
            ));
        }
        if velocity.zoom != 0.0 {
            v.push_str(&format!(r#"<tt:Zoom x="{}"/>"#, speed(velocity.zoom)));
        }
        if v.is_empty() {
            return self.stop().await;
        }
        self.ptz(&format!(
            "<tptz:ContinuousMove>{}<tptz:Velocity>{v}</tptz:Velocity><tptz:Timeout>{}</tptz:Timeout></tptz:ContinuousMove>",
            self.profile_token(),
            duration(timeout)
        ))
        .await
        .map(|_| ())
    }

    /// Stops any move (pan, tilt and zoom).
    pub async fn stop(&self) -> Result<(), OnvifError> {
        self.ptz(&format!(
            "<tptz:Stop>{}<tptz:PanTilt>true</tptz:PanTilt><tptz:Zoom>true</tptz:Zoom></tptz:Stop>",
            self.profile_token()
        ))
        .await
        .map(|_| ())
    }

    /// The positions stored on the camera.
    pub async fn presets(&self) -> Result<Vec<Preset>, OnvifError> {
        let request = format!(
            "<tptz:GetPresets>{}</tptz:GetPresets>",
            self.profile_token()
        );
        match self.ptz(&request).await {
            // Presets are optional in ONVIF: a camera that has none answers
            // ter:NotImplemented (Imou Cruiser SE+ 2MP, e.g.): there are none.
            Err(OnvifError::NotImplemented) => Ok(Vec::new()),
            other => other.map(|body| presets_of(&body)),
        }
    }

    /// Goes to the preset `token`.
    pub async fn goto_preset(&self, token: &str) -> Result<(), OnvifError> {
        self.ptz(&format!(
            "<tptz:GotoPreset>{}<tptz:PresetToken>{}</tptz:PresetToken></tptz:GotoPreset>",
            self.profile_token(),
            escape(token)
        ))
        .await
        .map(|_| ())
    }

    /// Stores the current position as a new preset named `name`; its token.
    pub async fn set_preset(&self, name: &str) -> Result<String, OnvifError> {
        let body = self
            .ptz(&format!(
                "<tptz:SetPreset>{}<tptz:PresetName>{}</tptz:PresetName></tptz:SetPreset>",
                self.profile_token(),
                escape(name)
            ))
            .await?;
        body.find("PresetToken")
            .map(|t| t.text.trim().to_owned())
            .filter(|t| !t.is_empty())
            .ok_or_else(|| OnvifError::Other("la caméra n'a pas rendu le preset créé".into()))
    }

    /// Deletes the preset `token`.
    pub async fn remove_preset(&self, token: &str) -> Result<(), OnvifError> {
        self.ptz(&format!(
            "<tptz:RemovePreset>{}<tptz:PresetToken>{}</tptz:PresetToken></tptz:RemovePreset>",
            self.profile_token(),
            escape(token)
        ))
        .await
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    fn soap(body: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="d" xmlns:trt="m" xmlns:tt="s" xmlns:tptz="p"><env:Body>{body}</env:Body></env:Envelope>"#
        )
    }

    /// A fake PTZ camera (`ptz`: whether it announces the service, `presets`:
    /// whether it implements `GetPresets`); the bodies it received.
    async fn camera(ptz: bool, presets: bool) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let log = log.clone();
                tokio::spawn(async move {
                    let mut req = Vec::new();
                    let mut buf = [0u8; 8192];
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
                    let body_in = text.split("\r\n\r\n").nth(1).unwrap_or("").to_owned();
                    log.lock().expect("log").push(body_in);
                    let ptz_caps = if ptz {
                        format!(
                            "<tt:PTZ><tt:XAddr>http://{addr}/onvif/ptz_service</tt:XAddr></tt:PTZ>"
                        )
                    } else {
                        String::new()
                    };
                    let body = if text.contains("GetSystemDateAndTime") {
                        soap(
                            "<tds:GetSystemDateAndTimeResponse><tds:SystemDateAndTime><tt:UTCDateTime><tt:Time><tt:Hour>8</tt:Hour><tt:Minute>0</tt:Minute><tt:Second>0</tt:Second></tt:Time><tt:Date><tt:Year>2030</tt:Year><tt:Month>1</tt:Month><tt:Day>2</tt:Day></tt:Date></tt:UTCDateTime></tds:SystemDateAndTime></tds:GetSystemDateAndTimeResponse>",
                        )
                    } else if !text.contains("<wsse:Username>admin</wsse:Username>") {
                        soap(
                            "<env:Fault><env:Code><env:Value>env:Sender</env:Value><env:Subcode><env:Value>ter:NotAuthorized</env:Value></env:Subcode></env:Code><env:Reason><env:Text>Sender not Authorized</env:Text></env:Reason></env:Fault>",
                        )
                    } else if text.contains("GetCapabilities") {
                        soap(&format!(
                            "<tds:GetCapabilitiesResponse><tds:Capabilities><tt:Media><tt:XAddr>http://{addr}/onvif/media_service</tt:XAddr></tt:Media>{ptz_caps}</tds:Capabilities></tds:GetCapabilitiesResponse>"
                        ))
                    } else if text.contains("GetProfiles") {
                        soap(
                            "<trt:GetProfilesResponse><trt:Profiles token=\"Sub\"><tt:Name>Sub</tt:Name></trt:Profiles><trt:Profiles token=\"Main&amp;1\"><tt:Name>Main</tt:Name><tt:PTZConfiguration token=\"PtzConf\"><tt:Name>ptz</tt:Name></tt:PTZConfiguration></trt:Profiles></trt:GetProfilesResponse>",
                        )
                    } else if text.contains("GetPresets") {
                        if presets {
                            soap(
                                "<tptz:GetPresetsResponse><tptz:Preset token=\"1\"><tt:Name>Portail</tt:Name></tptz:Preset><tptz:Preset token=\"2\"></tptz:Preset></tptz:GetPresetsResponse>",
                            )
                        } else {
                            // Imou Cruiser SE+ 2MP: presets are not implemented.
                            soap(
                                "<env:Fault><env:Code><env:Value>env:Sender</env:Value><env:Subcode><env:Value>ter:NotImplemented</env:Value></env:Subcode></env:Code><env:Reason><env:Text>This optional method is not implemented</env:Text></env:Reason></env:Fault>",
                            )
                        }
                    } else if text.contains("SetPreset") {
                        soap(
                            "<tptz:SetPresetResponse><tptz:PresetToken>3</tptz:PresetToken></tptz:SetPresetResponse>",
                        )
                    } else {
                        // ContinuousMove, Stop, GotoPreset, RemovePreset.
                        soap("<tptz:Response/>")
                    };
                    let answer = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(answer.as_bytes()).await;
                });
            }
        });
        (format!("http://{addr}/onvif/device_service"), seen)
    }

    fn admin() -> Option<(String, Secret)> {
        Some(("admin".to_owned(), Secret::new("pw".to_owned())))
    }

    #[tokio::test]
    async fn moves_the_camera_and_uses_its_presets() {
        let (url, seen) = camera(true, true).await;
        let cam = PtzCamera::connect(&url, admin(), Duration::from_secs(5))
            .await
            .expect("ptz");
        let last = || {
            seen.lock()
                .expect("log")
                .last()
                .cloned()
                .unwrap_or_default()
        };
        // The profile with a PTZ configuration, its token escaped.
        cam.continuous_move(
            Velocity {
                pan: 0.5,
                tilt: -2.0,
                zoom: 0.0,
            },
            Duration::from_secs(10),
        )
        .await
        .expect("move");
        let body = last();
        assert!(body.contains("ptz_service") || body.contains("ContinuousMove"));
        assert!(
            body.contains("<tptz:ProfileToken>Main&amp;1</tptz:ProfileToken>"),
            "{body}"
        );
        assert!(
            body.contains(r#"<tt:PanTilt x="0.500" y="-1.000"/>"#),
            "{body}"
        );
        assert!(!body.contains("Zoom"), "{body}");
        assert!(
            body.contains("<tptz:Timeout>PT10S</tptz:Timeout>"),
            "{body}"
        );
        cam.continuous_move(
            Velocity {
                zoom: 0.25,
                ..Velocity::default()
            },
            Duration::from_secs(10),
        )
        .await
        .expect("zoom");
        let body = last();
        assert!(
            body.contains(r#"<tt:Zoom x="0.250"/>"#) && !body.contains("PanTilt x"),
            "{body}"
        );
        // No speed at all: a stop.
        cam.continuous_move(Velocity::default(), Duration::from_secs(10))
            .await
            .expect("stop");
        assert!(last().contains("<tptz:Stop>"));

        assert_eq!(
            cam.presets().await.expect("presets"),
            [
                Preset {
                    token: "1".into(),
                    name: "Portail".into()
                },
                Preset {
                    token: "2".into(),
                    name: "2".into()
                }
            ]
        );
        cam.goto_preset("1").await.expect("goto");
        assert!(last().contains("<tptz:GotoPreset><tptz:ProfileToken>Main&amp;1</tptz:ProfileToken><tptz:PresetToken>1</tptz:PresetToken>"));
        assert_eq!(cam.set_preset("Allée <nord>").await.expect("set"), "3");
        assert!(last().contains("<tptz:PresetName>Allée &lt;nord&gt;</tptz:PresetName>"));
        cam.remove_preset("3").await.expect("remove");
        assert!(last().contains("<tptz:RemovePreset>"));
    }

    #[tokio::test]
    async fn a_camera_without_ptz_or_with_other_credentials_is_refused() {
        let (url, _) = camera(false, true).await;
        assert!(matches!(
            PtzCamera::connect(&url, admin(), Duration::from_secs(5)).await,
            Err(OnvifError::NoPtz)
        ));
        let (url, _) = camera(true, true).await;
        let other = Some(("other".to_owned(), Secret::new("x".to_owned())));
        assert!(matches!(
            PtzCamera::connect(&url, other, Duration::from_secs(5)).await,
            Err(OnvifError::Unauthorized)
        ));
        assert_eq!(speed(f32::NAN), "0.000");
        assert_eq!(duration(Duration::from_millis(300)), "PT1S");
    }

    #[tokio::test]
    async fn a_camera_without_presets_has_none() {
        let (url, _) = camera(true, false).await;
        let cam = PtzCamera::connect(&url, admin(), Duration::from_secs(5))
            .await
            .expect("ptz");
        assert!(cam.presets().await.expect("no presets").is_empty());
    }
}
