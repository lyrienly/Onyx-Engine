use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::collections::HashMap;

use pdb::FallibleIterator;

pub mod codeview;
pub mod symsrv;

pub use codeview::{CodeViewInfo, read_codeview_from_file};
pub use symsrv::{SymSrvClient, DEFAULT_SYMBOL_SERVER};

type ResolvedEntry = (u32, u32, String);
type ResolvedMap = HashMap<String, Vec<ResolvedEntry>>;
type NamesMap = HashMap<String, HashMap<String, u32>>;

pub struct SymbolCache {
    client: SymSrvClient,
    resolved: Mutex<ResolvedMap>,
    names: Mutex<NamesMap>,
}

impl SymbolCache {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            client: SymSrvClient::new_default()?,
            resolved: Mutex::new(HashMap::new()),
            names: Mutex::new(HashMap::new()),
        })
    }

    pub fn with_client(client: SymSrvClient) -> Self {
        Self {
            client,
            resolved: Mutex::new(HashMap::new()),
            names: Mutex::new(HashMap::new()),
        }
    }

    pub fn cache_dir(&self) -> &Path {
        self.client.cache_dir()
    }

    pub fn ensure_pdb<P: AsRef<Path>>(&self, module_path: P) -> io::Result<PathBuf> {
        let info = read_codeview_from_file(module_path.as_ref())?;
        self.client.fetch(&info)
    }

    fn load_index<P: AsRef<Path>>(&self, module_path: P) -> io::Result<String> {
        let module_path = module_path.as_ref();
        let module_key = module_path.to_string_lossy().to_lowercase();

        {
            let names = self.names.lock().unwrap();
            if names.contains_key(&module_key) {
                return Ok(module_key);
            }
        }

        let pdb_path = self.ensure_pdb(module_path)?;
        let file = fs::File::open(&pdb_path)?;
        let mut pdb = pdb::PDB::open(file)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("pdb open: {e}")))?;

        let address_map = pdb
            .address_map()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("address_map: {e}")))?;

        let global_syms = pdb
            .global_symbols()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("global_symbols: {e}")))?;

        let mut rva_to_name: Vec<(u32, u32, String)> = Vec::new();
        let mut name_to_rva: HashMap<String, u32> = HashMap::new();

        let mut iter = global_syms.iter();
        while let Some(sym) = iter.next().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("sym iter: {e}")))? {
            if let Ok(data) = sym.parse() {
                match data {
                    pdb::SymbolData::Public(d) => {
                        if let Some(rva) = d.offset.to_rva(&address_map) {
                            let name = d.name.to_string().into_owned();
                            name_to_rva.entry(name.clone()).or_insert(rva.0);
                            rva_to_name.push((rva.0, 0, name));
                        }
                    }
                    pdb::SymbolData::Procedure(d) => {
                        if let Some(rva) = d.offset.to_rva(&address_map) {
                            let name = d.name.to_string().into_owned();
                            name_to_rva.entry(name.clone()).or_insert(rva.0);
                            rva_to_name.push((rva.0, d.len, name));
                        }
                    }
                    pdb::SymbolData::Data(d) => {
                        if let Some(rva) = d.offset.to_rva(&address_map) {
                            let name = d.name.to_string().into_owned();
                            name_to_rva.entry(name.clone()).or_insert(rva.0);
                            rva_to_name.push((rva.0, 0, name));
                        }
                    }
                    _ => {}
                }
            }
        }

        rva_to_name.sort_by_key(|t| t.0);

        self.resolved.lock().unwrap().insert(module_key.clone(), rva_to_name);
        self.names.lock().unwrap().insert(module_key.clone(), name_to_rva);

        Ok(module_key)
    }

    pub fn resolve_symbol<P: AsRef<Path>>(&self, module_path: P, rva: u32) -> Option<String> {
        let key = self.load_index(module_path).ok()?;
        let resolved = self.resolved.lock().unwrap();
        let list = resolved.get(&key)?;
        if list.is_empty() {
            return None;
        }
        let idx = match list.binary_search_by_key(&rva, |t| t.0) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        let (sym_rva, sym_len, name) = &list[idx];
        if *sym_len != 0 && rva >= *sym_rva + *sym_len {
            return None;
        }
        let delta = rva - *sym_rva;
        if delta == 0 {
            Some(name.clone())
        } else {
            Some(format!("{}+0x{:x}", name, delta))
        }
    }

    pub fn lookup_by_name<P: AsRef<Path>>(&self, module_path: P, name: &str) -> Option<u64> {
        let key = self.load_index(module_path).ok()?;
        let names = self.names.lock().unwrap();
        let map = names.get(&key)?;
        map.get(name).map(|&v| v as u64)
    }
}

pub fn default_cache_dir() -> PathBuf {
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        PathBuf::from(local).join("OnyxEngine").join("symbols")
    } else if let Ok(home) = std::env::var("USERPROFILE") {
        PathBuf::from(home).join("AppData").join("Local").join("OnyxEngine").join("symbols")
    } else {
        PathBuf::from(".onyx_symbols")
    }
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("part");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

pub(crate) fn read_all(path: &Path) -> io::Result<Vec<u8>> {
    let mut f = fs::File::open(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(buf)
}
