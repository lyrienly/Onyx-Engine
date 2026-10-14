// OnyxEngine GUI State Definitions
// Clean, strongly-typed state structures for memory scanner and inspection interface

use onyx_core::scanner::ValType;

#[derive(Debug, Clone)]
pub struct GuiTableEntry {
    pub active: bool,
    pub description: String,
    pub address: usize, // live resolved address
    pub module_name: Option<String>,
    pub base_offset: usize,
    pub offsets: Vec<usize>, // If non-empty, this is a multi-level Pointer!
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
