//! OnyxEngine - Error Localization / Idiomas

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnyxLocale {
    EnUs = 0,
    #[default]
    PtBr = 1,
}

impl OnyxLocale {
    pub fn as_u32(self) -> u32 {
        self as u32
    }

    pub fn from_u32(val: u32) -> Self {
        match val {
            0 => Self::EnUs,
            1 => Self::PtBr,
            _ => Self::PtBr,
        }
    }

    pub fn tag(self) -> &'static str {
        match self {
            Self::EnUs => "en-US",
            Self::PtBr => "pt-BR",
        }
    }
}
