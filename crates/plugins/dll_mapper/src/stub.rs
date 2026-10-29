#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CallRequest {
    pub function: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub result: u64,
}

impl CallRequest {
    pub fn new(function: u64, args: [u64; 4]) -> Self {
        Self {
            function,
            arg0: args[0],
            arg1: args[1],
            arg2: args[2],
            arg3: args[3],
            result: 0,
        }
    }
}

pub fn call_stub() -> Vec<u8> {
    vec![
        0x49, 0x89, 0xCA,
        0x49, 0x8B, 0x4A, 0x08,
        0x49, 0x8B, 0x52, 0x10,
        0x4D, 0x8B, 0x42, 0x18,
        0x4D, 0x8B, 0x4A, 0x20,
        0x49, 0x8B, 0x02,
        0x48, 0x83, 0xEC, 0x28,
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x28,
        0x49, 0x89, 0x42, 0x28,
        0xC3,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_request_layout_matches_stub_offsets() {
        assert_eq!(std::mem::size_of::<CallRequest>(), 48);
        assert_eq!(std::mem::offset_of!(CallRequest, function), 0x00);
        assert_eq!(std::mem::offset_of!(CallRequest, arg0), 0x08);
        assert_eq!(std::mem::offset_of!(CallRequest, arg1), 0x10);
        assert_eq!(std::mem::offset_of!(CallRequest, arg2), 0x18);
        assert_eq!(std::mem::offset_of!(CallRequest, arg3), 0x20);
        assert_eq!(std::mem::offset_of!(CallRequest, result), 0x28);
    }

    #[test]
    fn test_stub_bytes() {
        let stub = call_stub();
        assert_eq!(stub.len(), 37);
        assert_eq!(&stub[0..3], &[0x49, 0x89, 0xCA]);
        assert_eq!(&stub[stub.len() - 5..], &[0x49, 0x89, 0x42, 0x28, 0xC3]);
        assert_eq!(stub[stub.len() - 1], 0xC3);
    }

    #[test]
    fn test_call_request_new() {
        let req = CallRequest::new(0x1234, [1, 2, 3, 4]);
        assert_eq!(req.function, 0x1234);
        assert_eq!(req.arg3, 4);
        assert_eq!(req.result, 0);
    }
}
