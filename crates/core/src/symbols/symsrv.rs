use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{codeview::CodeViewInfo, default_cache_dir, read_all, write_atomic};

pub const DEFAULT_SYMBOL_SERVER: &str = "https://msdl.microsoft.com/download/symbols";

pub struct SymSrvClient {
    cache_dir: PathBuf,
    servers: Vec<String>,
    timeout: Duration,
    user_agent: String,
}

impl SymSrvClient {
    pub fn new_default() -> io::Result<Self> {
        let cache_dir = default_cache_dir();
        fs::create_dir_all(&cache_dir)?;
        Ok(Self {
            cache_dir,
            servers: vec![DEFAULT_SYMBOL_SERVER.to_string()],
            timeout: Duration::from_secs(60),
            user_agent: "Microsoft-Symbol-Server/10.0.0.0 OnyxEngine/0.2".to_string(),
        })
    }

    pub fn with_cache_dir(mut self, dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        self.cache_dir = dir;
        Ok(self)
    }

    pub fn with_server(mut self, url: &str) -> Self {
        self.servers = vec![url.to_string()];
        self
    }

    pub fn add_server(&mut self, url: &str) {
        self.servers.push(url.to_string());
    }

    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    pub fn cached_path(&self, info: &CodeViewInfo) -> PathBuf {
        let name = info.pdb_basename();
        self.cache_dir
            .join(name)
            .join(info.guid_age_key())
            .join(name)
    }

    pub fn fetch(&self, info: &CodeViewInfo) -> io::Result<PathBuf> {
        let dest = self.cached_path(info);
        if dest.exists() {
            return Ok(dest);
        }

        let name = info.pdb_basename();
        let sub = format!("{}/{}/{}", name, info.guid_age_key(), name);

        let mut last_err: Option<io::Error> = None;

        for base in &self.servers {
            let url = format!("{}/{}", base.trim_end_matches('/'), sub);
            match self.download(&url) {
                Ok(bytes) => {
                    write_atomic(&dest, &bytes)?;
                    return Ok(dest);
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }

            let compressed_sub = {
                let mut s = sub.clone();
                let last = s.pop().unwrap_or('_');
                s.push(if last.is_ascii_alphanumeric() {
                    '_'
                } else {
                    last
                });
                s
            };
            let compressed_url = format!("{}/{}", base.trim_end_matches('/'), compressed_sub);
            if let Ok(bytes) = self.download(&compressed_url) {
                let _ = bytes;
            }
        }

        Err(last_err.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "no symbol server succeeded")
        }))
    }

    fn download(&self, url: &str) -> io::Result<Vec<u8>> {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(self.timeout)
            .timeout_read(self.timeout)
            .timeout_write(self.timeout)
            .user_agent(&self.user_agent)
            .build();

        let resp = agent
            .get(url)
            .call()
            .map_err(|e| io::Error::other(format!("http: {e}")))?;

        if resp.status() != 200 {
            return Err(io::Error::other(format!(
                "http status {} for {}",
                resp.status(),
                url
            )));
        }

        let mut reader = resp.into_reader();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Ok(buf)
    }
}

pub fn read_cached_pdb(path: &Path) -> io::Result<Vec<u8>> {
    read_all(path)
}
