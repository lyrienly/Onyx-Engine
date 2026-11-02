//! OnyxEngine - Central Unified Error Codes
//! Standardized integer error codes across all subsystems, plugins, and UI.

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OnyxErrorCode {
    Success = 0,

    // ==========================================
    // General & ABI Domain (100 - 199)
    // ==========================================
    NullPointer = 101,
    InvalidArgument = 102,
    BufferTooSmall = 103,
    BufferOverflow = 104,
    IndexOutOfBounds = 105,
    InvalidState = 106,
    OperationCancelled = 107,
    OperationTimeout = 108,
    NotImplemented = 109,
    InternalError = 110,

    // ==========================================
    // Process Management Domain (1000 - 1099)
    // ==========================================
    ProcessNotFound = 1001,
    ProcessAccessDenied = 1002,
    ProcessAttachFailed = 1003,
    ProcessSnapshotFailed = 1004,
    ProcessSuspensionFailed = 1005,
    ProcessResumeFailed = 1006,
    ProcessInvalidHandle = 1007,
    ProcessThreadSnapshotFailed = 1008,
    ProcessArchitectureMismatch = 1009,
    ProcessAlreadyAttached = 1010,
    ProcessNotAttached = 1011,
    ProcessModuleNotFound = 1012,
    ProcessPebQueryFailed = 1013,
    ProcessCr3ResolveFailed = 1014,

    // ==========================================
    // Memory Operations Domain (1100 - 1199)
    // ==========================================
    MemoryReadFailed = 1101,
    MemoryWriteFailed = 1102,
    MemoryAllocFailed = 1103,
    MemoryProtectFailed = 1104,
    MemoryFreeFailed = 1105,
    MemoryQueryFailed = 1106,
    MemoryInvalidAddress = 1107,
    MemoryPageGuardEncountered = 1108,
    MemoryCopyOnWriteViolation = 1109,
    MemoryUnalignedAccess = 1110,
    MemoryZeroBytesTransferred = 1111,

    // ==========================================
    // Kernel & Driver (OwMemDriver) Domain (2000 - 2099)
    // ==========================================
    DriverNotConnected = 2001,
    DriverConnectionFailed = 2002,
    DriverIoctlFailed = 2003,
    DriverPhysicalReadFailed = 2004,
    DriverPhysicalWriteFailed = 2005,
    DriverCr3WalkFailed = 2006,
    DriverObCallbackFailed = 2007,
    DriverPteManipulationFailed = 2008,
    DriverPpidbCacheCleanFailed = 2009,
    DriverIntelPtUnsupported = 2010,
    DriverIntelPtInitFailed = 2011,
    DriverIntelPtBufferOverflow = 2012,
    DriverVmxOffloadFailed = 2013,
    DriverHvciIncompatible = 2014,
    DriverDkomFailed = 2015,
    DriverSeDebugGrantFailed = 2016,

    // ==========================================
    // Memory Scanner & Pointers Domain (3000 - 3099)
    // ==========================================
    ScannerPatternParseFailed = 3001,
    ScannerInvalidDataType = 3002,
    ScannerBufferOverflow = 3003,
    ScannerNoActiveScan = 3004,
    ScannerRegionQueryFailed = 3005,
    ScannerFileSaveFailed = 3006,
    ScannerFileReadFailed = 3007,
    PointerScannerAlreadyRunning = 3008,
    PointerScannerNotRunning = 3009,
    PointerChainBroken = 3010,
    PointerMaxDepthExceeded = 3011,
    PointerInvalidTargetAddress = 3012,
    PointerRescanDataMismatch = 3013,
    PointerMapEmpty = 3014,

    // ==========================================
    // Injections, Hooks, Detours & PE (4000 - 4099)
    // ==========================================
    InjectionDllNotFound = 4001,
    InjectionRemoteAllocFailed = 4002,
    InjectionWritePathFailed = 4003,
    InjectionThreadCreationFailed = 4004,
    InjectionLoadLibraryFailed = 4005,
    HookTrampolineFailed = 4006,
    HookTargetTooSmall = 4007,
    HookAlreadyInstalled = 4008,
    HookNotInstalled = 4009,
    ManualMapInvalidPeHeader = 4010,
    ManualMapRelocFailed = 4011,
    ManualMapImportResolveFailed = 4012,
    ManualMapTlsInitFailed = 4013,
    ManualMapEntryExecutionFailed = 4014,
    PeStripSectionNotFound = 4015,
    PeStripInvalidDosSignature = 4016,
    PeStripInvalidNtHeaders = 4017,
    CallstackSpoofGadgetNotFound = 4018,
    SyscallResolveFailed = 4019,
    SpeedhackInitFailed = 4020,
    AllochookFailed = 4021,

    // ==========================================
    // Debugger & Hardware Breakpoints (5000 - 5099)
    // ==========================================
    VehHandlerAlreadyRegistered = 5001,
    VehHandlerNotRegistered = 5002,
    VehHwSlotUnavailable = 5003,
    VehHwSlotInvalid = 5004,
    VehThreadContextFetchFailed = 5005,
    VehThreadContextSetFailed = 5006,
    PageGuardAllocationFailed = 5007,
    PageGuardHandlerFailed = 5008,
    GdbServerBindFailed = 5009,
    GdbPacketParseError = 5010,
    DisasmInstructionFailed = 5011,

    // ==========================================
    // Managed Runtimes (Mono, .NET, Lua) (6000 - 6099)
    // ==========================================
    MonoModuleNotFound = 6001,
    MonoRootDomainFailed = 6002,
    MonoThreadAttachFailed = 6003,
    MonoAssemblyLoadFailed = 6004,
    MonoImageOpenFailed = 6005,
    MonoClassLookupFailed = 6006,
    MonoMethodLookupFailed = 6007,
    MonoCompileFailed = 6008,
    DotNetRuntimeNotFound = 6009,
    DotNetClrtypeNotFound = 6010,
    LuaScriptExecutionError = 6011,
    LuaSyntaxError = 6012,

    // ==========================================
    // Plugins & Extension Tools (7000 - 7099)
    // ==========================================
    PluginNotFound = 7001,
    PluginInvalidExport = 7002,
    PluginInitFailed = 7003,
    AobToolSignatureGenerationFailed = 7004,
    AobToolMaskLengthMismatch = 7005,
    DllMapperInvalidImage = 7006,
    DllMapperSectionMappingFailed = 7007,
    DllMapperTlsFailed = 7008,
}

impl OnyxErrorCode {
    pub fn as_u32(self) -> u32 {
        self as u32
    }

    pub fn from_u32(val: u32) -> Self {
        match val {
            0 => Self::Success,
            101 => Self::NullPointer,
            102 => Self::InvalidArgument,
            103 => Self::BufferTooSmall,
            104 => Self::BufferOverflow,
            105 => Self::IndexOutOfBounds,
            106 => Self::InvalidState,
            107 => Self::OperationCancelled,
            108 => Self::OperationTimeout,
            109 => Self::NotImplemented,
            110 => Self::InternalError,

            1001 => Self::ProcessNotFound,
            1002 => Self::ProcessAccessDenied,
            1003 => Self::ProcessAttachFailed,
            1004 => Self::ProcessSnapshotFailed,
            1005 => Self::ProcessSuspensionFailed,
            1006 => Self::ProcessResumeFailed,
            1007 => Self::ProcessInvalidHandle,
            1008 => Self::ProcessThreadSnapshotFailed,
            1009 => Self::ProcessArchitectureMismatch,
            1010 => Self::ProcessAlreadyAttached,
            1011 => Self::ProcessNotAttached,
            1012 => Self::ProcessModuleNotFound,
            1013 => Self::ProcessPebQueryFailed,
            1014 => Self::ProcessCr3ResolveFailed,

            1101 => Self::MemoryReadFailed,
            1102 => Self::MemoryWriteFailed,
            1103 => Self::MemoryAllocFailed,
            1104 => Self::MemoryProtectFailed,
            1105 => Self::MemoryFreeFailed,
            1106 => Self::MemoryQueryFailed,
            1107 => Self::MemoryInvalidAddress,
            1108 => Self::MemoryPageGuardEncountered,
            1109 => Self::MemoryCopyOnWriteViolation,
            1110 => Self::MemoryUnalignedAccess,
            1111 => Self::MemoryZeroBytesTransferred,

            2001 => Self::DriverNotConnected,
            2002 => Self::DriverConnectionFailed,
            2003 => Self::DriverIoctlFailed,
            2004 => Self::DriverPhysicalReadFailed,
            2005 => Self::DriverPhysicalWriteFailed,
            2006 => Self::DriverCr3WalkFailed,
            2007 => Self::DriverObCallbackFailed,
            2008 => Self::DriverPteManipulationFailed,
            2009 => Self::DriverPpidbCacheCleanFailed,
            2010 => Self::DriverIntelPtUnsupported,
            2011 => Self::DriverIntelPtInitFailed,
            2012 => Self::DriverIntelPtBufferOverflow,
            2013 => Self::DriverVmxOffloadFailed,
            2014 => Self::DriverHvciIncompatible,
            2015 => Self::DriverDkomFailed,
            2016 => Self::DriverSeDebugGrantFailed,

            3001 => Self::ScannerPatternParseFailed,
            3002 => Self::ScannerInvalidDataType,
            3003 => Self::ScannerBufferOverflow,
            3004 => Self::ScannerNoActiveScan,
            3005 => Self::ScannerRegionQueryFailed,
            3006 => Self::ScannerFileSaveFailed,
            3007 => Self::ScannerFileReadFailed,
            3008 => Self::PointerScannerAlreadyRunning,
            3009 => Self::PointerScannerNotRunning,
            3010 => Self::PointerChainBroken,
            3011 => Self::PointerMaxDepthExceeded,
            3012 => Self::PointerInvalidTargetAddress,
            3013 => Self::PointerRescanDataMismatch,
            3014 => Self::PointerMapEmpty,

            4001 => Self::InjectionDllNotFound,
            4002 => Self::InjectionRemoteAllocFailed,
            4003 => Self::InjectionWritePathFailed,
            4004 => Self::InjectionThreadCreationFailed,
            4005 => Self::InjectionLoadLibraryFailed,
            4006 => Self::HookTrampolineFailed,
            4007 => Self::HookTargetTooSmall,
            4008 => Self::HookAlreadyInstalled,
            4009 => Self::HookNotInstalled,
            4010 => Self::ManualMapInvalidPeHeader,
            4011 => Self::ManualMapRelocFailed,
            4012 => Self::ManualMapImportResolveFailed,
            4013 => Self::ManualMapTlsInitFailed,
            4014 => Self::ManualMapEntryExecutionFailed,
            4015 => Self::PeStripSectionNotFound,
            4016 => Self::PeStripInvalidDosSignature,
            4017 => Self::PeStripInvalidNtHeaders,
            4018 => Self::CallstackSpoofGadgetNotFound,
            4019 => Self::SyscallResolveFailed,
            4020 => Self::SpeedhackInitFailed,
            4021 => Self::AllochookFailed,

            5001 => Self::VehHandlerAlreadyRegistered,
            5002 => Self::VehHandlerNotRegistered,
            5003 => Self::VehHwSlotUnavailable,
            5004 => Self::VehHwSlotInvalid,
            5005 => Self::VehThreadContextFetchFailed,
            5006 => Self::VehThreadContextSetFailed,
            5007 => Self::PageGuardAllocationFailed,
            5008 => Self::PageGuardHandlerFailed,
            5009 => Self::GdbServerBindFailed,
            5010 => Self::GdbPacketParseError,
            5011 => Self::DisasmInstructionFailed,

            6001 => Self::MonoModuleNotFound,
            6002 => Self::MonoRootDomainFailed,
            6003 => Self::MonoThreadAttachFailed,
            6004 => Self::MonoAssemblyLoadFailed,
            6005 => Self::MonoImageOpenFailed,
            6006 => Self::MonoClassLookupFailed,
            6007 => Self::MonoMethodLookupFailed,
            6008 => Self::MonoCompileFailed,
            6009 => Self::DotNetRuntimeNotFound,
            6010 => Self::DotNetClrtypeNotFound,
            6011 => Self::LuaScriptExecutionError,
            6012 => Self::LuaSyntaxError,

            7001 => Self::PluginNotFound,
            7002 => Self::PluginInvalidExport,
            7003 => Self::PluginInitFailed,
            7004 => Self::AobToolSignatureGenerationFailed,
            7005 => Self::AobToolMaskLengthMismatch,
            7006 => Self::DllMapperInvalidImage,
            7007 => Self::DllMapperSectionMappingFailed,
            7008 => Self::DllMapperTlsFailed,

            _ => Self::InternalError,
        }
    }
}
