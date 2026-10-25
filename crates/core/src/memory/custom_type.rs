
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustomTypeKind {
    Integer,
    Float,
    CustomBytes,
}

#[derive(Debug, Clone)]
pub struct CustomType {
    pub name: String,
    pub kind: CustomTypeKind,
    pub byte_size: usize,
    pub script_bytes_to_val: String,
    pub script_val_to_bytes: String,
    pub internal_only: bool,
}

impl CustomType {
    pub fn new_integer(name: &str, internal_only: bool) -> Self {

        CustomType {
            name: name.to_string(),
            kind: CustomTypeKind::Integer,
            byte_size: 8,
            script_bytes_to_val: String::new(),
            script_val_to_bytes: String::new(),
            internal_only,
        }
    }

    pub fn new_custom(name: &str, byte_size: usize, internal_only: bool) -> Self {
        CustomType {
            name: name.to_string(),
            kind: CustomTypeKind::CustomBytes,
            byte_size,
            script_bytes_to_val: String::new(),
            script_val_to_bytes: String::new(),
            internal_only,
        }
    }

    pub fn default_templates() -> Vec<CustomType> {
        vec![

            CustomType {
                name: "Big Endian 4 Bytes".to_string(),
                kind: CustomTypeKind::Integer,
                byte_size: 4,
                script_bytes_to_val: "return (b[1]<<24) | (b[2]<<16) | (b[3]<<8) | b[4]".to_string(),
                script_val_to_bytes: "return {(v>>24)&0xFF, (v>>16)&0xFF, (v>>8)&0xFF, v&0xFF}".to_string(),
                internal_only: false,
            },

            CustomType {
                name: "Big Endian 8 Bytes".to_string(),
                kind: CustomTypeKind::Integer,
                byte_size: 8,
                script_bytes_to_val: "local res = 0; for i=1,8 do res = (res<<8) | b[i] end return res".to_string(),
                script_val_to_bytes: "local t = {}; for i=8,1,-1 do t[i] = v&0xFF; v = v>>8 end return t".to_string(),
                internal_only: false,
            },

            CustomType {
                name: "24-bit Integer".to_string(),
                kind: CustomTypeKind::Integer,
                byte_size: 3,
                script_bytes_to_val: "return b[1] | (b[2]<<8) | (b[3]<<16)".to_string(),
                script_val_to_bytes: "return {v&0xFF, (v>>8)&0xFF, (v>>16)&0xFF}".to_string(),
                internal_only: false,
            },

            CustomType {
                name: "Internal XOR8 Masked".to_string(),
                kind: CustomTypeKind::Integer,
                byte_size: 8,
                script_bytes_to_val: "return v ~ 0x5A5A5A5A5A5A5A5A".to_string(),
                script_val_to_bytes: "return v ~ 0x5A5A5A5A5A5A5A5A".to_string(),
                internal_only: true,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_type_64bit_integer_and_internal_only() {
        let t = CustomType::new_integer("MyInt64", true);
        assert_eq!(t.byte_size, 8, "Integer variant must be 8 bytes in 64-bit CE");
        assert!(t.internal_only, "internal_only flag must be set");

        let templates = CustomType::default_templates();
        let user_visible: Vec<_> = templates.iter().filter(|t| !t.internal_only).collect();
        let internal: Vec<_> = templates.iter().filter(|t| t.internal_only).collect();

        assert_eq!(user_visible.len(), 3);
        assert_eq!(internal.len(), 1);
        assert_eq!(internal[0].name, "Internal XOR8 Masked");
    }
}

