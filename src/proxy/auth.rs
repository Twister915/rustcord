use anyhow::Result;
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use mcproto_rs::utils::hex;
use mcproto_rs::uuid::UUID4;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq)]
pub struct HasJoinedRequest {
    pub username: String,
    pub ip: String,
    pub hash: ServerHashComponents,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HasJoinedResponse {
    pub id: UUID4,
    pub name: String,
    pub properties: Vec<UserProperty>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UserProperty {
    pub name: String,
    pub value: String,
    pub signature: String,
}

impl HasJoinedRequest {
    pub async fn send(self, client: &reqwest::Client) -> Result<HasJoinedResponse> {
        Ok(client
            .get("https://sessionserver.mojang.com/session/minecraft/hasJoined")
            .query(&[
                ("username", self.username.as_str()),
                ("ip", self.ip.as_str()),
                ("serverId", self.hash.into_hash_string().as_str()),
            ])
            .send()
            .await?
            .json()
            .await?)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ServerHashComponents {
    pub server_id: String,
    pub shared_secret: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl ServerHashComponents {
    pub fn into_hash_string(self) -> String {
        let server_id_bytes = self.server_id.as_bytes();
        let mut data = Vec::with_capacity(
            server_id_bytes.len() + self.shared_secret.len() + self.public_key.len(),
        );
        data.extend_from_slice(server_id_bytes);
        data.extend(self.shared_secret.iter());
        data.extend(self.public_key.iter());
        mc_sha1(data.as_slice())
    }
}

#[inline]
fn mc_sha1(input: &[u8]) -> String {
    let mut sha1 = Sha1::new();
    sha1.input(input);
    let mut out = vec![0u8; sha1.output_bytes()];
    sha1.result(&mut out);

    let is_negative = out[0] & 0x80 != 0;
    if is_negative {
        for item in &mut out {
            *item = !*item;
        }

        let mut added_one = false;
        for i in (0..out.len()).rev() {
            let val = &mut out[i];
            if *val == 0xFF {
                *val = 0
            } else {
                *val += 1;
                added_one = true;
                break;
            }
        }

        if !added_one {
            panic!("overflow {:?}", out);
        }
    }

    let mut out = hex(&out);
    while !out.is_empty() && &out.as_str()[0..1] == "0" {
        out.remove(0);
    }

    if is_negative {
        out.insert(0, '-');
    }

    out
}

#[cfg(test)]
mod tests {
    use super::mc_sha1;

    #[test]
    pub fn calc_hashes() {
        assert_eq!(
            "-7c9d5b0044c130109a5d7b5fb5c317c02b4e28c1",
            mc_sha1("jeb_".as_bytes())
        );
        assert_eq!(
            "4ed1f46bbe04bc756bcb17c0c7ce3e4632f06a48",
            mc_sha1("Notch".as_bytes())
        );
        assert_eq!(
            "88e16a1019277b15d58faf0541e11910eb756f6",
            mc_sha1("simon".as_bytes())
        );
    }
}
