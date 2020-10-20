#[derive(Clone, Debug)]
pub struct Configuration {
    pub servers: Vec<TargetServerSpec>,
    pub motd: Option<String>,
    pub favicon_location: Option<String>,
    pub max_players: u32,
    pub ping_backends: bool,
    pub bind_addresses: Vec<String>,
    pub encryption: bool,
    pub compression_threshold: Option<usize>,
    pub log_level: super::logger::Level,
}

impl Configuration {
    pub async fn load_favicon(&self) -> anyhow::Result<Option<Vec<u8>>> {
        let location = if let Some(location) = &self.favicon_location {
            location
        } else {
            return Ok(None);
        };

        let (_, filename, ext) = file_path_name_ext(location.as_str());

        if let Some(ext) = ext {
            if ext != "png" {
                return Err(anyhow::anyhow!("favicon should be png file, but got {}.{}", filename, ext));
            }
        } else {
            return Err(anyhow::anyhow!("favicon should be png file, but got no extension for {}", filename));
        }

        let mut f = tokio::fs::File::open(location).await?;
        let mut data = Vec::new();
        use tokio::io::AsyncReadExt;
        f.read_to_end(&mut data).await?;
        Ok(Some(data))
    }
}

#[derive(Clone, Debug)]
pub struct TargetServerSpec {
    pub address: String,
    pub name: String,
    pub use_motd: bool,
    pub connect_to: bool,
}

fn file_path_name_ext(source: &str) -> (Option<&str>, &str, Option<&str>) {
    let mut idx_last_sep = None;
    let mut idx_last_dot = None;
    for (idx, c) in source.chars().enumerate() {
        if c == '.' {
            idx_last_dot = Some(idx);
        }
        if std::path::is_separator(c) {
            idx_last_sep = Some(idx);
        }
    }

    let (dir, rest) = if let Some(idx) = idx_last_sep {
        let (front, back) = source.split_at(idx);
        (Some(front), &back[1..])
    } else {
        (None, source)
    };

    let (file, ext) = if let Some(mut idx) = idx_last_dot {
        if let Some(sep_idx) = idx_last_sep {
            if sep_idx > idx {
                return (dir, rest, None);
            } else {
                idx -= sep_idx + 1;
            }
        }

        let (front, back) = rest.split_at(idx);
        (front, Some(&back[1..]))
    } else {
        (rest, None)
    };

    (dir, file, ext)
}

#[cfg(test)]
pub mod tests {
    use crate::proxy::config::file_path_name_ext;

    #[test]
    fn test_file_path_with_no_dir() {
        let (dir, name, ext) = file_path_name_ext("image.png");
        assert_eq!(dir, None);
        assert_eq!(name, "image");
        assert_eq!(ext, Some("png"));
    }

    #[test]
    fn test_file_path_with_no_ext_no_dir() {
        let (dir, name, ext) = file_path_name_ext("image");
        assert_eq!(dir, None);
        assert_eq!(name, "image");
        assert_eq!(ext, None);
    }

    #[test]
    fn test_file_with_multiple_dots() {
        let (dir, name, ext) = file_path_name_ext("image.png.mp4");
        assert_eq!(dir, None);
        assert_eq!(name, "image.png");
        assert_eq!(ext, Some("mp4"));
    }

    #[test]
    fn test_file_with_dir() {
        let (dir, name, ext) = file_path_name_ext("my/assets/123/bb/image.png");
        assert_eq!(dir, Some("my/assets/123/bb"));
        assert_eq!(name, "image");
        assert_eq!(ext, Some("png"));
    }
}