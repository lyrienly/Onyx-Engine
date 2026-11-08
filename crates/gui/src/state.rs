use onyx_core::scanner::ValType;

/// Classification used to colour disassembly rows without re-parsing the
/// mnemonic every frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisasmFlow {
    Normal,
    Branch,
    Ret,
}

/// Pre-formatted disassembly row.
///
/// Building this once when the view is refreshed avoids repeated string
/// allocation and symbol lookup for every row on every frame. The renderer
/// only paints the rows that are actually visible.
#[derive(Debug, Clone)]
pub struct DisasmRowView {
    pub address: usize,
    pub length: usize,
    pub mnemonic: String,
    pub addr_str: String,
    pub bytes_str: String,
    pub opcode_str: String,
    pub comment: String,
    pub flow: DisasmFlow,
}

#[derive(Debug, Clone)]
pub struct GuiTableEntry {
    pub active: bool,
    pub description: String,
    pub address: usize,
    pub module_name: Option<String>,
    pub base_offset: usize,
    pub offsets: Vec<usize>,
    pub val_type: ValType,
    pub current_val: String,
    pub target_val: String,
}

impl GuiTableEntry {
    pub fn new_simple(description: String, address: usize, val_type: ValType) -> Self {
        Self {
            active: false,
            description,
            address,
            module_name: None,
            base_offset: 0,
            offsets: Vec::new(),
            val_type,
            current_val: "???".to_string(),
            target_val: "0".to_string(),
        }
    }

    pub fn new_pointer(
        description: String,
        module_name: Option<String>,
        base_offset: usize,
        offsets: Vec<usize>,
        val_type: ValType,
    ) -> Self {
        Self {
            active: false,
            description,
            address: 0,
            module_name,
            base_offset,
            offsets,
            val_type,
            current_val: "???".to_string(),
            target_val: "0".to_string(),
        }
    }

    pub fn is_pointer(&self) -> bool {
        !self.offsets.is_empty()
    }
}
