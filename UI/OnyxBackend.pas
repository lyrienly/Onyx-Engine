unit OnyxBackend;

{$MODE Delphi}

interface

uses
  windows, sysutils, classes, NewKernelHandler, commontypedefs;

const
  OnyxBackendDLL = 'onyx_backend.dll';

type
  TOnyxProcessEntry = packed record
    pid: DWORD;
    name: array[0..259] of AnsiChar;
  end;
  POnyxProcessEntry = ^TOnyxProcessEntry;

  TOnyxModuleEntry = packed record
    base: PtrUInt;
    size: PtrUInt;
    name: array[0..259] of AnsiChar;
  end;
  POnyxModuleEntry = ^TOnyxModuleEntry;

  TOnyxMemoryRegion = packed record
    base: PtrUInt;
    size: PtrUInt;
    state: DWORD;
    protect: DWORD;
    region_type: DWORD;
  end;
  POnyxMemoryRegion = ^TOnyxMemoryRegion;

  TOnyxScanCandidate = packed record
    address: PtrUInt;
    current_val: array[0..63] of AnsiChar;
    previous_val: array[0..63] of AnsiChar;
  end;
  POnyxScanCandidate = ^TOnyxScanCandidate;

  TOnyxDisasmInsn = packed record
    address: PtrUInt;
    length: DWORD;
    bytes: array[0..15] of Byte;
    mnemonic: array[0..31] of AnsiChar;
    operands: array[0..95] of AnsiChar;
  end;
  POnyxDisasmInsn = ^TOnyxDisasmInsn;

  TOnyxPointerPathRecord = packed record
    module_name: array[0..259] of AnsiChar;
    base_offset: PtrUInt;
    offsets: array[0..15] of PtrUInt;
    offset_count: DWORD;
    final_address: PtrUInt;
  end;
  POnyxPointerPathRecord = ^TOnyxPointerPathRecord;

  TOnyxVehHit = packed record
    instruction_address: PtrUInt;
    count: PtrUInt;
    last_rax: UInt64;
    last_rbx: UInt64;
    last_rcx: UInt64;
    last_rdx: UInt64;
    last_rsi: UInt64;
    last_rdi: UInt64;
    last_rsp: UInt64;
    last_rbp: UInt64;
    instruction_text: array[0..63] of AnsiChar;
  end;
  POnyxVehHit = ^TOnyxVehHit;

  { Layout must match onyx_backend::types::OnyxVehSlot (#[repr(C)], 24 bytes).
    Não usar "packed": o Rust alinha address em 8 bytes. }
  TOnyxVehSlot = record
    index: DWORD;
    address: PtrUInt;
    bp_type: integer;
    size: integer;
  end;
  POnyxVehSlot = ^TOnyxVehSlot;
  TOnyxVehSlotArray = array[0..3] of TOnyxVehSlot;

  TOnyxCodecaveEntry = packed record
    address: PtrUInt;
    size: PtrUInt;
    byte_value: Byte;
  end;
  POnyxCodecaveEntry = ^TOnyxCodecaveEntry;

  TOnyxRipRelativeMatch = packed record
    instruction_address: PtrUInt;
    target_address: PtrUInt;
    mnemonic: array[0..31] of AnsiChar;
    operands: array[0..95] of AnsiChar;
  end;
  POnyxRipRelativeMatch = ^TOnyxRipRelativeMatch;

  TOnyxRegisterSnapshot = packed record
    rax: UInt64;
    rbx: UInt64;
    rcx: UInt64;
    rdx: UInt64;
    rsi: UInt64;
    rdi: UInt64;
    rbp: UInt64;
    rsp: UInt64;
    r8: UInt64;
    r9: UInt64;
    r10: UInt64;
    r11: UInt64;
    r12: UInt64;
    r13: UInt64;
    r14: UInt64;
    r15: UInt64;
    rip: UInt64;
    rflags: UInt64;
  end;
  POnyxRegisterSnapshot = ^TOnyxRegisterSnapshot;

  TOnyxRegisterComparison = packed record
    reg_name: array[0..15] of AnsiChar;
    reg_index: DWORD;
    g1_constant: integer;
    g1_sample: UInt64;
    g2_constant: integer;
    g2_sample: UInt64;
    distinguishes_groups: integer;
  end;
  POnyxRegisterComparison = ^TOnyxRegisterComparison;

  TOnyxStructureDifference = packed record
    offset: PtrUInt;
    g1_constant: integer;
    g1_value: UInt64;
    g2_constant: integer;
    g2_value: UInt64;
    differentiates: integer;
    value_size: DWORD;
  end;
  POnyxStructureDifference = ^TOnyxStructureDifference;

  TOnyxDissectBranch = packed record
    from_address: PtrUInt;
    to_address: PtrUInt;
    kind: DWORD;
  end;
  POnyxDissectBranch = ^TOnyxDissectBranch;

  TOnyxXRefEntry = packed record
    target_address: PtrUInt;
    caller_address: PtrUInt;
  end;
  POnyxXRefEntry = ^TOnyxXRefEntry;

  TOnyxStringReference = packed record
    instruction_address: PtrUInt;
    string_address: PtrUInt;
    text: array[0..127] of AnsiChar;
    is_unicode: integer;
    mnemonic: array[0..31] of AnsiChar;
    operands: array[0..95] of AnsiChar;
  end;
  POnyxStringReference = ^TOnyxStringReference;

  TOnyxPeSection = packed record
    name: array[0..15] of AnsiChar;
    virtual_address: PtrUInt;
    virtual_size: PtrUInt;
    raw_size: PtrUInt;
    characteristics: DWORD;
    is_executable: integer;
    is_writable: integer;
    is_readable: integer;
  end;
  POnyxPeSection = ^TOnyxPeSection;

  TOnyxPeImport = packed record
    module_name: array[0..127] of AnsiChar;
    function_name: array[0..127] of AnsiChar;
    ordinal: Word;
    iat_address: PtrUInt;
    resolved_address: PtrUInt;
  end;
  POnyxPeImport = ^TOnyxPeImport;

  TOnyxSignatureResult = packed record
    pattern: array[0..255] of AnsiChar;
    length: PtrUInt;
    match_count: PtrUInt;
    is_unique: integer;
  end;
  POnyxSignatureResult = ^TOnyxSignatureResult;

  TOnyxAobMatchResult = packed record
    address: UInt64;
    match_count: DWORD;
    is_unique: DWORD;
    module_name: array[0..127] of AnsiChar;
    module_base: UInt64;
    module_offset: UInt64;
    function_name: array[0..255] of AnsiChar;
    function_start: UInt64;
    function_offset: Int64;
    disasm_preview: array[0..511] of AnsiChar;
  end;
  POnyxAobMatchResult = ^TOnyxAobMatchResult;

const
  ONYX_MAP_ERASE_HEADERS    = 1;
  ONYX_MAP_PROTECT_SECTIONS = 2;
  ONYX_MAP_CALL_TLS         = 4;
  ONYX_MAP_THREAD_HIJACK    = 8;
  ONYX_MAP_USE_DRIVER       = 16;
  ONYX_MAP_WIPE_STUB        = 32;
  ONYX_MAP_MODULE_STOMP     = 64;
  ONYX_MAP_RESOLVE_PEB      = 128;
  ONYX_MAP_REGISTER_SEH     = 256;
  ONYX_MAP_INIT_COOKIE      = 512;

type
  TOnyxMapOptions = packed record
    struct_size: DWORD;
    flags: DWORD;
    preferred_base: UInt64;
  end;
  POnyxMapOptions = ^TOnyxMapOptions;

  TOnyxMapResult = packed record
    image_base: UInt64;
    entry_point: UInt64;
    dll_main_result: integer;
    flags_applied: DWORD;
    relocations: DWORD;
    imports: DWORD;
    error: array[0..255] of AnsiChar;
  end;
  POnyxMapResult = ^TOnyxMapResult;

const
  ONYX_PTR_PHASE_IDLE = 0;
  ONYX_PTR_PHASE_MAPPING = 1;
  ONYX_PTR_PHASE_SEARCHING = 2;
  ONYX_PTR_PHASE_RESCANNING = 3;
  ONYX_PTR_PHASE_COMPLETED = 4;
  ONYX_PTR_PHASE_CANCELLED = 5;
  ONYX_PTR_PHASE_FAILED = 6;

// Native Rust Backend Export Declarations
function onyx_backend_version: DWORD; stdcall; external OnyxBackendDLL;
function onyx_backend_ping: integer; stdcall; external OnyxBackendDLL;
function onyx_security_cloak_self: integer; stdcall; external OnyxBackendDLL;

function onyx_process_list(out_entries: Pointer; max_count: DWORD; out_total: PDWORD): integer; stdcall; external OnyxBackendDLL;
function onyx_process_attach(pid: DWORD): Pointer; stdcall; external OnyxBackendDLL;
procedure onyx_process_close(handle: Pointer); stdcall; external OnyxBackendDLL;
function onyx_process_suspend(handle: Pointer): integer; stdcall; external OnyxBackendDLL;
function onyx_process_resume(handle: Pointer): integer; stdcall; external OnyxBackendDLL;
function onyx_process_read(handle: Pointer; base_address: PtrUInt; buffer: Pointer; size: PtrUInt; out_bytes_read: PPtrUInt): integer; stdcall; external OnyxBackendDLL;
function onyx_process_write(handle: Pointer; base_address: PtrUInt; buffer: Pointer; size: PtrUInt; out_bytes_written: PPtrUInt): integer; stdcall; external OnyxBackendDLL;
function onyx_process_protect(handle: Pointer; base_address: PtrUInt; size: PtrUInt; new_protect: DWORD; old_protect: PDWORD): integer; stdcall; external OnyxBackendDLL;
function onyx_process_alloc(handle: Pointer; preferred_address: PtrUInt; size: PtrUInt; alloc_type: DWORD; protect: DWORD): PtrUInt; stdcall; external OnyxBackendDLL;
function onyx_process_free(handle: Pointer; base_address: PtrUInt; size: PtrUInt; free_type: DWORD): integer; stdcall; external OnyxBackendDLL;
function onyx_process_modules(handle: Pointer; out_modules: Pointer; max_count: DWORD; out_total: PDWORD): integer; stdcall; external OnyxBackendDLL;
function onyx_process_regions(handle: Pointer; out_regions: Pointer; max_count: DWORD; out_total: PDWORD): integer; stdcall; external OnyxBackendDLL;

// Lydumen Stealth & Ring-0 Kernel Engine
function onyx_kernel_connect(device_path: PAnsiChar): integer; stdcall; external OnyxBackendDLL;
function onyx_kernel_is_connected: integer; stdcall; external OnyxBackendDLL;
function onyx_kernel_hide_driver: integer; stdcall; external OnyxBackendDLL;
function onyx_kernel_strip_callbacks(restore: integer): integer; stdcall; external OnyxBackendDLL;
function onyx_kernel_clean_traces: integer; stdcall; external OnyxBackendDLL;
function onyx_kernel_set_protection(pid: DWORD; enable: integer): integer; stdcall; external OnyxBackendDLL;
function onyx_kernel_freeze_process(pid: DWORD; freeze: integer): integer; stdcall; external OnyxBackendDLL;
function onyx_kernel_cloak_symlink(new_symlink: PAnsiChar): integer; stdcall; external OnyxBackendDLL;
function onyx_kernel_enum_vad(pid: DWORD; out_modules: Pointer; max_count: DWORD; out_total: PDWORD): integer; stdcall; external OnyxBackendDLL;

// Process Watcher
function onyx_process_watcher_create: Pointer; stdcall; external OnyxBackendDLL;
procedure onyx_process_watcher_destroy(watcher: Pointer); stdcall; external OnyxBackendDLL;
procedure onyx_process_watcher_add_target(watcher: Pointer; target_name: PAnsiChar); stdcall; external OnyxBackendDLL;
function onyx_process_watcher_start(watcher: Pointer; poll_ms: DWORD): integer; stdcall; external OnyxBackendDLL;
procedure onyx_process_watcher_stop(watcher: Pointer); stdcall; external OnyxBackendDLL;
function onyx_process_watcher_poll(watcher: Pointer; out_entry: Pointer; out_event_type: PInteger): integer; stdcall; external OnyxBackendDLL;

// PDB & Debug Symbols
function onyx_symbol_init_pdb(process_handle: THandle; search_path: PAnsiChar): Pointer; stdcall; external OnyxBackendDLL;
procedure onyx_symbol_close_pdb(engine: Pointer); stdcall; external OnyxBackendDLL;
function onyx_symbol_load_module(engine: Pointer; image_path: PAnsiChar; base: PtrUInt; size: PtrUInt): UInt64; stdcall; external OnyxBackendDLL;
function onyx_symbol_resolve_name(engine: Pointer; name: PAnsiChar; out_address: PPtrUInt): integer; stdcall; external OnyxBackendDLL;
function onyx_symbol_resolve_address(engine: Pointer; address: PtrUInt; out_name: PAnsiChar; max_len: DWORD; out_disp: PPtrUInt): integer; stdcall; external OnyxBackendDLL;

// Codecave & RIP-Relative Scanners
function onyx_scan_codecaves(handle: Pointer; start: PtrUInt; stop: PtrUInt; min_size: PtrUInt; byte_type: integer; exec_only: integer; out_entries: Pointer; max_entries: DWORD; out_count: PDWORD): integer; stdcall; external OnyxBackendDLL;
function onyx_scan_rip_relative(handle: Pointer; start: PtrUInt; stop: PtrUInt; target_address: PtrUInt; has_target_filter: integer; out_matches: Pointer; max_matches: DWORD; out_count: PDWORD): integer; stdcall; external OnyxBackendDLL;

// Commonality & Structure Difference Analyzer
function onyx_commonality_analyze_registers(g1: Pointer; g1_count: DWORD; g2: Pointer; g2_count: DWORD; out_comparisons: Pointer; max_out: DWORD; out_count: PDWORD): integer; stdcall; external OnyxBackendDLL;
function onyx_commonality_analyze_structures(handle: Pointer; g1_ptrs: Pointer; g1_count: DWORD; g2_ptrs: Pointer; g2_count: DWORD; struct_size: PtrUInt; out_diffs: Pointer; max_diffs: DWORD; out_count: PDWORD): integer; stdcall; external OnyxBackendDLL;

function onyx_scanner_create(val_type_idx: integer): Pointer; stdcall; external OnyxBackendDLL;
procedure onyx_scanner_destroy(scanner: Pointer); stdcall; external OnyxBackendDLL;
function onyx_scanner_first_scan(scanner: Pointer; process: Pointer; scan_type: integer; val1_str: PAnsiChar; val2_str: PAnsiChar; is_hex: integer; fast_scan: integer; alignment: PtrUInt; start_addr: PtrUInt; stop_addr: PtrUInt; writable_only: integer; executable: integer; copy_on_write: integer): Int64; stdcall; external OnyxBackendDLL;
function onyx_scanner_next_scan(scanner: Pointer; process: Pointer; scan_type: integer; val1_str: PAnsiChar; val2_str: PAnsiChar; is_hex: integer): Int64; stdcall; external OnyxBackendDLL;
function onyx_scanner_undo(scanner: Pointer): integer; stdcall; external OnyxBackendDLL;
function onyx_scanner_get_count(scanner: Pointer): Int64; stdcall; external OnyxBackendDLL;
function onyx_scanner_get_results(scanner: Pointer; out_candidates: Pointer; max_count: DWORD): Int64; stdcall; external OnyxBackendDLL;
function onyx_scanner_save_results_file(scanner: Pointer; file_path: PAnsiChar): Int64; stdcall; external OnyxBackendDLL;

function onyx_disasm_instruction(address: PtrUInt; bytes: PByte; length: PtrUInt; out_insn: Pointer): integer; stdcall; external OnyxBackendDLL;
function onyx_disasm_block(address: PtrUInt; bytes: PByte; length: PtrUInt; max_instructions: DWORD; out_insns: Pointer; out_count: PDWORD): integer; stdcall; external OnyxBackendDLL;

// Code Dissection & XRefs
function onyx_dissect_code(handle: Pointer; start: PtrUInt; stop: PtrUInt; out_branches: Pointer; max_branches: DWORD; out_branch_count: PDWORD; out_xrefs: Pointer; max_xrefs: DWORD; out_xref_count: PDWORD): integer; stdcall; external OnyxBackendDLL;

// String Referencer
function onyx_scan_string_references(handle: Pointer; start: PtrUInt; stop: PtrUInt; min_string_len: PtrUInt; out_refs: Pointer; max_refs: DWORD; out_count: PDWORD): integer; stdcall; external OnyxBackendDLL;

// PE Sections & IAT Parser
function onyx_pe_parse_sections(handle: Pointer; module_base: PtrUInt; out_sections: Pointer; max_sections: DWORD; out_count: PDWORD): integer; stdcall; external OnyxBackendDLL;
function onyx_pe_parse_imports(handle: Pointer; module_base: PtrUInt; out_imports: Pointer; max_imports: DWORD; out_count: PDWORD): integer; stdcall; external OnyxBackendDLL;

// Unique AOB Signature Generator
function onyx_generate_aob_signature(handle: Pointer; target_address: PtrUInt; scan_start: PtrUInt; scan_stop: PtrUInt; max_len: PtrUInt; out_result: Pointer): integer; stdcall; external OnyxBackendDLL;

function onyx_freezer_create(process: Pointer; interval_ms: UInt64): Pointer; stdcall; external OnyxBackendDLL;
function onyx_freezer_set_process(freezer: Pointer; process: Pointer): integer; stdcall; external OnyxBackendDLL;
procedure onyx_freezer_destroy(freezer: Pointer); stdcall; external OnyxBackendDLL;
function onyx_freezer_add(freezer: Pointer; address: PtrUInt; val_type_idx: integer; val_str: PAnsiChar; description: PAnsiChar): PtrUInt; stdcall; external OnyxBackendDLL;
function onyx_freezer_update(freezer: Pointer; entry_id: PtrUInt; val_type_idx: integer; val_str: PAnsiChar): integer; stdcall; external OnyxBackendDLL;
function onyx_freezer_remove(freezer: Pointer; entry_id: PtrUInt): integer; stdcall; external OnyxBackendDLL;
procedure onyx_freezer_clear(freezer: Pointer); stdcall; external OnyxBackendDLL;

function onyx_pointer_resolve(proc: Pointer; base_addr: PtrUInt; offsets: PPtrUInt; offset_count: PtrUInt): PtrUInt; stdcall; external OnyxBackendDLL;
function onyx_pointer_eval_path(proc: Pointer; module_name: PAnsiChar; base_offset: PtrUInt; offsets: PPtrUInt; offset_count: PtrUInt): PtrUInt; stdcall; external OnyxBackendDLL;
function onyx_pointer_scanner_create: Pointer; stdcall; external OnyxBackendDLL;
procedure onyx_pointer_scanner_destroy(session: Pointer); stdcall; external OnyxBackendDLL;
function onyx_pointer_scanner_start_scan(session: Pointer; proc: Pointer; target_addr: PtrUInt; max_depth: PtrUInt; max_offset: PtrUInt; alignment: PtrUInt; max_results: PtrUInt): integer; stdcall; external OnyxBackendDLL;
function onyx_pointer_scanner_start_rescan(session: Pointer; proc: Pointer; new_target_addr: PtrUInt): integer; stdcall; external OnyxBackendDLL;
function onyx_pointer_scanner_start_value_rescan(session: Pointer; proc: Pointer; val_bytes: Pointer; val_len: DWORD): integer; stdcall; external OnyxBackendDLL;
function onyx_pointer_scanner_cancel(session: Pointer): integer; stdcall; external OnyxBackendDLL;
function onyx_pointer_scanner_get_status(session: Pointer; out_phase: PDWORD; out_progress: PSingle; out_found_count: PPtrUInt): integer; stdcall; external OnyxBackendDLL;
function onyx_pointer_scanner_get_count(session: Pointer): PtrUInt; stdcall; external OnyxBackendDLL;
function onyx_pointer_scanner_get_path(session: Pointer; index: PtrUInt; out_record: POnyxPointerPathRecord): integer; stdcall; external OnyxBackendDLL;
function onyx_pointer_scanner_save_results(session: Pointer; file_path: PAnsiChar): integer; stdcall; external OnyxBackendDLL;
function onyx_pointer_scanner_load_results(session: Pointer; file_path: PAnsiChar): integer; stdcall; external OnyxBackendDLL;
function onyx_pointer_scanner_save_map(session: Pointer; proc: Pointer; file_path: PAnsiChar): integer; stdcall; external OnyxBackendDLL;
function onyx_pointer_scanner_load_map(session: Pointer; file_path: PAnsiChar): integer; stdcall; external OnyxBackendDLL;
function onyx_pointer_scanner_start_offline_scan(session: Pointer; target_addr: PtrUInt; max_depth: PtrUInt; max_offset: PtrUInt; alignment: PtrUInt; max_results: PtrUInt): integer; stdcall; external OnyxBackendDLL;
function onyx_pointer_scanner_intersect_file(session: Pointer; other_results_file: PAnsiChar): integer; stdcall; external OnyxBackendDLL;

function onyx_speedhack_init(process: Pointer; initial_speed: Single): integer; stdcall; external OnyxBackendDLL;
function onyx_speedhack_set(process: Pointer; multiplier: Single): integer; stdcall; external OnyxBackendDLL;
function onyx_speedhack_is_active(process: Pointer): integer; stdcall; external OnyxBackendDLL;
function onyx_speedhack_reset(process: Pointer): integer; stdcall; external OnyxBackendDLL;

function onyx_mono_detect(process: Pointer): integer; stdcall; external OnyxBackendDLL;
function onyx_mono_dissect(process: Pointer): integer; stdcall; external OnyxBackendDLL;
function onyx_mono_class_count: integer; stdcall; external OnyxBackendDLL;
function onyx_mono_get_class_info(index: integer; out_name: PAnsiChar; max_len: DWORD; out_addr: PPtrUInt; out_fields_count: PDWORD): integer; stdcall; external OnyxBackendDLL;
function onyx_mono_find_field_offset(class_name: PAnsiChar; field_name: PAnsiChar): integer; stdcall; external OnyxBackendDLL;
function onyx_mono_find_method_address(class_name: PAnsiChar; method_name: PAnsiChar): PtrUInt; stdcall; external OnyxBackendDLL;
function onyx_mono_generate_hook(method_name: PAnsiChar; method_addr: PtrUInt; out_script: PAnsiChar; max_len: DWORD): integer; stdcall; external OnyxBackendDLL;
function onyx_mono_compile_method(process: Pointer; class_name: PAnsiChar; method_name: PAnsiChar): PtrUInt; stdcall; external OnyxBackendDLL;
function onyx_mono_read_field_value(process: Pointer; instance_address: PtrUInt; class_name: PAnsiChar; field_name: PAnsiChar; out_val: PAnsiChar; max_len: DWORD): integer; stdcall; external OnyxBackendDLL;
function onyx_mono_get_assembly_count: integer; stdcall; external OnyxBackendDLL;
function onyx_mono_get_assembly_name(index: integer; out_name: PAnsiChar; max_len: DWORD): integer; stdcall; external OnyxBackendDLL;
function onyx_mono_dissect_clr_object(process: Pointer; object_address: PtrUInt; out_mt: PPtrUInt; out_eeclass: PPtrUInt; out_size: PDWORD): integer; stdcall; external OnyxBackendDLL;

function onyx_veh_inject(process: Pointer; dll_path: PAnsiChar): integer; stdcall; external OnyxBackendDLL;
function onyx_veh_init(process: Pointer): integer; stdcall; external OnyxBackendDLL;
function onyx_veh_set_hw_bp(process: Pointer; address: PtrUInt; bp_type: integer; size: integer): integer; stdcall; external OnyxBackendDLL;
function onyx_veh_clear_hw_bp(process: Pointer; index: PtrUInt): integer; stdcall; external OnyxBackendDLL;
function onyx_veh_poll_hit(process: Pointer; out_rip: PPtrUInt; out_thread_id: PDWORD): integer; stdcall; external OnyxBackendDLL;
function onyx_veh_monitor_address(process: Pointer; address: PtrUInt; bp_type: integer; size: integer; duration_secs: UInt64; out_hits: Pointer; max_hits: DWORD; out_count: PDWORD): integer; stdcall; external OnyxBackendDLL;
function onyx_veh_slot_status(process: Pointer; out_slots: Pointer; max_slots: DWORD; out_count: PDWORD): integer; stdcall; external OnyxBackendDLL;
function onyx_veh_verify_slots(process: Pointer): integer; stdcall; external OnyxBackendDLL;
procedure onyx_veh_cleanup; stdcall; external OnyxBackendDLL;

var
  CurrentOnyxProcessHandle: Pointer = nil;
  CurrentOnyxPID: DWORD = 0;
  CurrentOnyxScanner: Pointer = nil;
  GlobalOnyxPointerScanner: Pointer = nil;
  OriginalRPM: TReadProcessMemory = nil;
  OriginalWPM: TWriteProcessMemory = nil;
  OriginalOpenProcess: TOpenProcess = nil;

function InitOnyxBackend: Boolean;
procedure HookKernelHandlerWithOnyx;
function OnyxEnsureAttachedProcess: Pointer;

function OnyxStartPointerScan(targetAddr: PtrUInt; maxDepth: integer = 5; maxOffset: PtrUInt = $1000; alignment: integer = 4; maxResults: integer = 20000): Boolean;
function OnyxStartPointerRescan(newTargetAddr: PtrUInt): Boolean;
function OnyxStartPointerValueRescan(valBytes: Pointer; valLen: DWORD): Boolean;
procedure OnyxCancelPointerScan;
function OnyxGetPointerScanProgress(var phase: DWORD; var progressPct: Single; var foundCount: PtrUInt): Boolean;
function OnyxGetPointerScanCount: PtrUInt;
function OnyxGetPointerScanPath(index: PtrUInt; var recordOut: TOnyxPointerPathRecord): Boolean;
function OnyxSavePointerScan(filePath: string): Boolean;
function OnyxLoadPointerScan(filePath: string): Boolean;

function OnyxDoFirstScan(
  folder: string;
  varTypeOrd: integer;
  scanOptOrd: integer;
  val1: string;
  val2: string;
  isHex: boolean;
  fastScan: boolean;
  alignment: PtrUInt;
  startAddr: PtrUInt;
  stopAddr: PtrUInt;
  writable: boolean;
  executable: boolean;
  copyOnWrite: boolean;
  var outFound: UInt64;
  var outFirstAddr: PtrUInt
): Boolean;

function OnyxDoNextScan(
  folder: string;
  scanOptOrd: integer;
  val1: string;
  val2: string;
  isHex: boolean;
  var outFound: UInt64
): Boolean;

function OnyxDoUndoScan(folder: string; var outFound: UInt64): Boolean;

function OnyxEnsureFreezer: Pointer;
function OnyxFreezeRecord(address: PtrUInt; varTypeOrd: integer; valStr: string; desc: string): PtrUInt;
function OnyxUpdateFrozenRecord(entryId: PtrUInt; varTypeOrd: integer; valStr: string): Boolean;
procedure OnyxUnfreezeRecord(entryId: PtrUInt);
procedure OnyxClearFreezer;
function OnyxGetProcessList(ProcessList: TStrings; NoPID: boolean = false; noProcessInfo: boolean = false): Boolean;

function OnyxVehInject(dllPath: string = ''): Boolean;
function OnyxVehSetHardwareBreakpoint(address: PtrUInt; bpType: integer = 1; size: integer = 4): integer;
function OnyxVehClearHardwareBreakpoint(index: PtrUInt): Boolean;
function OnyxVehClearHardwareBreakpointCode(index: PtrUInt): integer;
function OnyxVehPollHit(var hitRip: PtrUInt; var threadId: DWORD): Boolean;
function OnyxVehSlotStatus(var slots: TOnyxVehSlotArray): integer;
function OnyxVehVerifySlots: integer;
function OnyxVehHasActiveBreakpoints: Boolean;
function OnyxVehErrorText(code: integer): string;

function OnyxMonoDetect: integer;
function OnyxMonoDissect: integer;
function OnyxMonoGetClassCount: integer;
function OnyxMonoGetClassInfo(index: integer; var className: string; var classAddr: PtrUInt; var fieldsCount: DWORD): Boolean;
function OnyxMonoFindFieldOffset(className, fieldName: string): integer;
function OnyxMonoFindMethodAddress(className, methodName: string): PtrUInt;
function OnyxMonoGenerateHook(methodName: string; methodAddr: PtrUInt): string;
function OnyxMonoCompileMethod(className, methodName: string): PtrUInt;
function OnyxMonoReadFieldValue(instanceAddress: PtrUInt; className, fieldName: string): string;
function OnyxMonoGetAssemblyCount: integer;
function OnyxMonoGetAssemblyName(index: integer): string;
function OnyxMonoDissectClrObject(objectAddress: PtrUInt; var outMt, outEeClass: PtrUInt; var outSize: DWORD): Boolean;
procedure RegisterOnyxLua(L: Pointer);

function OnyxValidateAOBPlugin(pid: DWORD; pattern: PAnsiChar; module_filter: PAnsiChar; out_result: POnyxAobMatchResult): integer;
function OnyxGenerateAOBPlugin(pid: DWORD; target_address: UInt64; max_len: DWORD; out_pattern: PAnsiChar; buf_size: DWORD): integer;
procedure OnyxUnloadAOBPlugin;
function OnyxMapDllPlugin(pid: DWORD; dll_path: PAnsiChar; options: POnyxMapOptions; out_result: POnyxMapResult): integer;

procedure OnyxUnloadDllMapperPlugin;

implementation

uses
  ProcessHandlerUnit, disassembler, lastdisassembledata, speedhack2, lua;

type
  TOnyxDisasmBridge = class
  public
    function DisasmOverride(sender: TObject; address: ptruint; var ldd: TLastDisassembleData; var output: string; var description: string): boolean;
  end;

  TOnyxSpeedhackBridge = class
  public
    function OnActivate(out r: boolean; out error: string): boolean;
    function OnSetSpeed(speed: single; out r: boolean; out error: string): boolean;
  end;

var
  OnyxBridgeInstance: TOnyxDisasmBridge = nil;
  OnyxSpeedhackBridgeInstance: TOnyxSpeedhackBridge = nil;

function TOnyxSpeedhackBridge.OnActivate(out r: boolean; out error: string): boolean;
var
  pProc: Pointer;
begin
  pProc := OnyxEnsureAttachedProcess;
  if pProc = nil then
  begin
    r := False;
    error := 'Nenhum processo selecionado para o Speedhack.';
    Exit(True);
  end;

  if onyx_speedhack_init(pProc, 1.0) = 1 then
  begin
    r := True;
    error := '';
  end
  else
  begin
    r := False;
    error := 'Falha ao injetar speedhack_dll.dll via Rust backend.';
  end;

  Result := True;
end;

function TOnyxSpeedhackBridge.OnSetSpeed(speed: single; out r: boolean; out error: string): boolean;
var
  pProc: Pointer;
begin
  pProc := OnyxEnsureAttachedProcess;
  if pProc = nil then
  begin
    r := False;
    error := 'Processo desconectado.';
    Exit(True);
  end;

  if onyx_speedhack_set(pProc, speed) = 1 then
  begin
    r := True;
    error := '';
  end
  else
  begin
    r := False;
    error := 'Falha ao atualizar velocidade via pipe IPC.';
  end;

  Result := True;
end;

function TOnyxDisasmBridge.DisasmOverride(sender: TObject; address: ptruint; var ldd: TLastDisassembleData; var output: string; var description: string): boolean;
var
  buf: array[0..15] of Byte;
  bytesRead: PtrUInt;
  insn: TOnyxDisasmInsn;
  res: integer;
  i: integer;
  mnemStr, opStr: string;
  curPid: DWORD;
begin
  Result := False;

  curPid := processid;
  if (CurrentOnyxProcessHandle = nil) and (curPid <> 0) then
  begin
    CurrentOnyxProcessHandle := onyx_process_attach(curPid);
    CurrentOnyxPID := curPid;
  end;

  if CurrentOnyxProcessHandle = nil then Exit;

  bytesRead := 0;
  if (onyx_process_read(CurrentOnyxProcessHandle, address, @buf, 16, @bytesRead) <> 1) or (bytesRead = 0) then
    Exit;

  res := onyx_disasm_instruction(address, @buf, bytesRead, @insn);
  if (res = 1) and (insn.length > 0) then
  begin
    ldd.address := insn.address;
    mnemStr := PAnsiChar(@insn.mnemonic[0]);
    opStr := PAnsiChar(@insn.operands[0]);
    ldd.opcode := mnemStr;
    ldd.parameters := opStr;
    SetLength(ldd.Bytes, insn.length);
    for i := 0 to insn.length - 1 do
      ldd.Bytes[i] := insn.bytes[i];

    if opStr <> '' then
      output := IntToHex(address, 8) + ' - ' + mnemStr + ' ' + opStr
    else
      output := IntToHex(address, 8) + ' - ' + mnemStr;

    description := '';
    Result := True;
  end;
end;

function OnyxDoFirstScan(
  folder: string;
  varTypeOrd: integer;
  scanOptOrd: integer;
  val1: string;
  val2: string;
  isHex: boolean;
  fastScan: boolean;
  alignment: PtrUInt;
  startAddr: PtrUInt;
  stopAddr: PtrUInt;
  writable: boolean;
  executable: boolean;
  copyOnWrite: boolean;
  var outFound: UInt64;
  var outFirstAddr: PtrUInt
): Boolean;
var
  count: Int64;
  res: Int64;
  filePath: AnsiString;
  curPid: DWORD;
  cand: TOnyxScanCandidate;
begin
  Result := False;
  outFound := 0;
  outFirstAddr := 0;

  curPid := processid;
  if curPid = 0 then Exit;

  if (CurrentOnyxProcessHandle = nil) or (CurrentOnyxPID <> curPid) then
  begin
    if CurrentOnyxProcessHandle <> nil then
      onyx_process_close(CurrentOnyxProcessHandle);
    CurrentOnyxProcessHandle := onyx_process_attach(curPid);
    CurrentOnyxPID := curPid;
  end;

  if CurrentOnyxProcessHandle = nil then Exit;

  if CurrentOnyxScanner <> nil then
  begin
    onyx_scanner_destroy(CurrentOnyxScanner);
    CurrentOnyxScanner := nil;
  end;

  CurrentOnyxScanner := onyx_scanner_create(varTypeOrd);
  if CurrentOnyxScanner = nil then Exit;

  count := onyx_scanner_first_scan(
    CurrentOnyxScanner,
    CurrentOnyxProcessHandle,
    scanOptOrd,
    PAnsiChar(AnsiString(val1)),
    PAnsiChar(AnsiString(val2)),
    ord(isHex),
    ord(fastScan),
    alignment,
    startAddr,
    stopAddr,
    ord(writable),
    ord(executable),
    ord(copyOnWrite)
  );

  if count < 0 then Exit;

  filePath := AnsiString(folder + 'ADDRESSES.TMP');
  res := onyx_scanner_save_results_file(CurrentOnyxScanner, PAnsiChar(filePath));
  if res < 0 then Exit;

  outFound := UInt64(count);
  if count > 0 then
  begin
    if onyx_scanner_get_results(CurrentOnyxScanner, @cand, 1) > 0 then
      outFirstAddr := cand.address;
  end;

  Result := True;
end;

function OnyxDoNextScan(
  folder: string;
  scanOptOrd: integer;
  val1: string;
  val2: string;
  isHex: boolean;
  var outFound: UInt64
): Boolean;
var
  count: Int64;
  res: Int64;
  filePath: AnsiString;
  dummyFile: TFileStream;
begin
  Result := False;
  outFound := 0;

  if (CurrentOnyxScanner = nil) or (CurrentOnyxProcessHandle = nil) then Exit;

  // Prepare UNDO files for OnyxEngine compatibility
  DeleteFile(folder + 'ADDRESSES.UNDO');
  RenameFile(folder + 'ADDRESSES.TMP', folder + 'ADDRESSES.UNDO');
  DeleteFile(folder + 'MEMORY.UNDO');
  try
    dummyFile := TFileStream.Create(folder + 'MEMORY.UNDO', fmCreate);
    dummyFile.WriteBuffer(count, sizeof(count));
    dummyFile.Free;
  except
  end;

  count := onyx_scanner_next_scan(
    CurrentOnyxScanner,
    CurrentOnyxProcessHandle,
    scanOptOrd,
    PAnsiChar(AnsiString(val1)),
    PAnsiChar(AnsiString(val2)),
    ord(isHex)
  );

  if count < 0 then Exit;

  filePath := AnsiString(folder + 'ADDRESSES.TMP');
  res := onyx_scanner_save_results_file(CurrentOnyxScanner, PAnsiChar(filePath));
  if res < 0 then Exit;

  outFound := UInt64(count);
  Result := True;
end;

function OnyxDoUndoScan(folder: string; var outFound: UInt64): Boolean;
var
  res: integer;
  saved: Int64;
  filePath: AnsiString;
begin
  Result := False;
  if CurrentOnyxScanner <> nil then
  begin
    res := onyx_scanner_undo(CurrentOnyxScanner);
    if res = 1 then
    begin
      filePath := AnsiString(folder + 'ADDRESSES.TMP');
      saved := onyx_scanner_save_results_file(CurrentOnyxScanner, PAnsiChar(filePath));
      if saved >= 0 then
      begin
        outFound := UInt64(saved);
        Result := True;
      end;
    end;
  end;
end;

function OnyxReadProcessMemory(hProcess: THandle; lpBaseAddress, lpBuffer: Pointer; nSize: size_t; var lpNumberOfBytesRead: PTRUINT): BOOL; stdcall;
var
  res: integer;
  bytesRead: PtrUInt;
begin
  if CurrentOnyxProcessHandle <> nil then
  begin
    res := onyx_process_read(CurrentOnyxProcessHandle, PtrUInt(lpBaseAddress), lpBuffer, nSize, @bytesRead);
    if res = 1 then
    begin
      lpNumberOfBytesRead := bytesRead;
      Exit(True);
    end;
  end;

  if Assigned(OriginalRPM) then
    Result := OriginalRPM(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)
  else
    Result := False;
end;

function OnyxWriteProcessMemory(hProcess: THandle; const lpBaseAddress: Pointer; lpBuffer: Pointer; nSize: size_t; var lpNumberOfBytesWritten: PTRUINT): BOOL; stdcall;
var
  res: integer;
  bytesWritten: PtrUInt;
begin
  if CurrentOnyxProcessHandle <> nil then
  begin
    res := onyx_process_write(CurrentOnyxProcessHandle, PtrUInt(lpBaseAddress), lpBuffer, nSize, @bytesWritten);
    if res = 1 then
    begin
      lpNumberOfBytesWritten := bytesWritten;
      Exit(True);
    end;
  end;

  if Assigned(OriginalWPM) then
    Result := OriginalWPM(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)
  else
    Result := False;
end;

function OnyxOpenProcess(dwDesiredAccess: DWORD; bInheritHandle: BOOL; dwProcessId: DWORD): THandle; stdcall;
var
  h: THandle;
begin
  if (CurrentOnyxProcessHandle <> nil) and (CurrentOnyxPID <> dwProcessId) then
  begin
    onyx_process_close(CurrentOnyxProcessHandle);
    CurrentOnyxProcessHandle := nil;
  end;

  CurrentOnyxProcessHandle := onyx_process_attach(dwProcessId);
  CurrentOnyxPID := dwProcessId;

  h := 0;
  if Assigned(OriginalOpenProcess) then
    h := OriginalOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);

  // If usermode OpenProcess was stripped or blocked by ObRegisterCallbacks,
  // return a synthetic valid handle so the OnyxEngine UI never errors out,
  // since memory operations are already intercepted and handled via Ring-0 CR3 in Rust!
  if (h = 0) or (h = INVALID_HANDLE_VALUE) then
  begin
    if CurrentOnyxProcessHandle <> nil then
      Result := THandle($FFFF0000 or (dwProcessId and $FFFF))
    else
      Result := 0;
  end
  else
    Result := h;
end;

procedure HookKernelHandlerWithOnyx;
begin
  if not Assigned(OriginalRPM) then
  begin
    OriginalRPM := ReadProcessMemoryActual;
    ReadProcessMemoryActual := @OnyxReadProcessMemory;
  end;

  if not Assigned(OriginalWPM) then
  begin
    OriginalWPM := WriteProcessMemoryActual;
    WriteProcessMemoryActual := @OnyxWriteProcessMemory;
  end;

  if not Assigned(OriginalOpenProcess) then
  begin
    OriginalOpenProcess := OpenProcess;
    OpenProcess := @OnyxOpenProcess;
  end;
end;

function OnyxEnsureAttachedProcess: Pointer;
var
  curPid: DWORD;
begin
  curPid := ProcessHandlerUnit.ProcessID;
  if curPid = 0 then
    Exit(nil);

  if (CurrentOnyxProcessHandle = nil) or (CurrentOnyxPID <> curPid) then
  begin
    if CurrentOnyxProcessHandle <> nil then
      onyx_process_close(CurrentOnyxProcessHandle);
    CurrentOnyxProcessHandle := onyx_process_attach(curPid);
    CurrentOnyxPID := curPid;
  end;

  Result := CurrentOnyxProcessHandle;
end;

function EnsureGlobalPointerScanner: Pointer;
begin
  if GlobalOnyxPointerScanner = nil then
    GlobalOnyxPointerScanner := onyx_pointer_scanner_create;
  Result := GlobalOnyxPointerScanner;
end;

function OnyxStartPointerScan(targetAddr: PtrUInt; maxDepth: integer = 5; maxOffset: PtrUInt = $1000; alignment: integer = 4; maxResults: integer = 20000): Boolean;
var
  pProc, pScan: Pointer;
begin
  pProc := OnyxEnsureAttachedProcess;
  if pProc = nil then Exit(False);
  pScan := EnsureGlobalPointerScanner;
  if pScan = nil then Exit(False);

  Result := onyx_pointer_scanner_start_scan(pScan, pProc, targetAddr, maxDepth, maxOffset, alignment, maxResults) = 1;
end;

function OnyxStartPointerRescan(newTargetAddr: PtrUInt): Boolean;
var
  pProc, pScan: Pointer;
begin
  pProc := OnyxEnsureAttachedProcess;
  if pProc = nil then Exit(False);
  pScan := EnsureGlobalPointerScanner;
  if pScan = nil then Exit(False);

  Result := onyx_pointer_scanner_start_rescan(pScan, pProc, newTargetAddr) = 1;
end;

function OnyxStartPointerValueRescan(valBytes: Pointer; valLen: DWORD): Boolean;
var
  pProc, pScan: Pointer;
begin
  pProc := OnyxEnsureAttachedProcess;
  if pProc = nil then Exit(False);
  pScan := EnsureGlobalPointerScanner;
  if pScan = nil then Exit(False);

  Result := onyx_pointer_scanner_start_value_rescan(pScan, pProc, valBytes, valLen) = 1;
end;

procedure OnyxCancelPointerScan;
begin
  if GlobalOnyxPointerScanner <> nil then
    onyx_pointer_scanner_cancel(GlobalOnyxPointerScanner);
end;

function OnyxGetPointerScanProgress(var phase: DWORD; var progressPct: Single; var foundCount: PtrUInt): Boolean;
begin
  if GlobalOnyxPointerScanner = nil then Exit(False);
  Result := onyx_pointer_scanner_get_status(GlobalOnyxPointerScanner, @phase, @progressPct, @foundCount) = 1;
end;

function OnyxGetPointerScanCount: PtrUInt;
begin
  if GlobalOnyxPointerScanner = nil then Exit(0);
  Result := onyx_pointer_scanner_get_count(GlobalOnyxPointerScanner);
end;

function OnyxGetPointerScanPath(index: PtrUInt; var recordOut: TOnyxPointerPathRecord): Boolean;
begin
  if GlobalOnyxPointerScanner = nil then Exit(False);
  Result := onyx_pointer_scanner_get_path(GlobalOnyxPointerScanner, index, @recordOut) = 1;
end;

function OnyxSavePointerScan(filePath: string): Boolean;
begin
  if GlobalOnyxPointerScanner = nil then Exit(False);
  Result := onyx_pointer_scanner_save_results(GlobalOnyxPointerScanner, PAnsiChar(filePath)) = 1;
end;

function OnyxLoadPointerScan(filePath: string): Boolean;
var
  pScan: Pointer;
begin
  pScan := EnsureGlobalPointerScanner;
  if pScan = nil then Exit(False);
  Result := onyx_pointer_scanner_load_results(pScan, PAnsiChar(filePath)) = 1;
end;

var
  GlobalOnyxFreezer: Pointer = nil;
  GlobalOnyxFreezerPID: DWORD = 0;

function OnyxEnsureFreezer: Pointer;
var
  pProc: Pointer;
begin
  pProc := OnyxEnsureAttachedProcess;
  if pProc = nil then Exit(nil);

  if (GlobalOnyxFreezer <> nil) and (GlobalOnyxFreezerPID <> CurrentOnyxPID) then
  begin
    onyx_freezer_destroy(GlobalOnyxFreezer);
    GlobalOnyxFreezer := nil;
  end;

  if GlobalOnyxFreezer = nil then
  begin
    GlobalOnyxFreezer := onyx_freezer_create(pProc, 50);
    GlobalOnyxFreezerPID := CurrentOnyxPID;
  end
  else
  begin
    onyx_freezer_set_process(GlobalOnyxFreezer, pProc);
  end;

  Result := GlobalOnyxFreezer;
end;

function OnyxFreezeRecord(address: PtrUInt; varTypeOrd: integer; valStr: string; desc: string): PtrUInt;
var
  f: Pointer;
begin
  Result := 0;
  f := OnyxEnsureFreezer;
  if f = nil then Exit;
  Result := onyx_freezer_add(f, address, varTypeOrd, PAnsiChar(AnsiString(valStr)), PAnsiChar(AnsiString(desc)));
end;

function OnyxUpdateFrozenRecord(entryId: PtrUInt; varTypeOrd: integer; valStr: string): Boolean;
var
  f: Pointer;
begin
  Result := False;
  f := OnyxEnsureFreezer;
  if (f = nil) or (entryId = 0) then Exit;
  Result := onyx_freezer_update(f, entryId, varTypeOrd, PAnsiChar(AnsiString(valStr))) = 1;
end;

procedure OnyxUnfreezeRecord(entryId: PtrUInt);
begin
  if (GlobalOnyxFreezer <> nil) and (entryId <> 0) then
    onyx_freezer_remove(GlobalOnyxFreezer, entryId);
end;

procedure OnyxClearFreezer;
begin
  if GlobalOnyxFreezer <> nil then
    onyx_freezer_clear(GlobalOnyxFreezer);
end;

function OnyxGetProcessList(ProcessList: TStrings; NoPID: boolean = false; noProcessInfo: boolean = false): Boolean;
var
  entries: array[0..1023] of TOnyxProcessEntry;
  total: DWORD;
  count, i: integer;
  s: string;
  nameStr: string;
  pli: PProcessListInfo;
begin
  Result := False;
  total := 0;
  count := onyx_process_list(@entries[0], 1024, @total);
  if count <= 0 then Exit;

  for i := 0 to count - 1 do
  begin
    if entries[i].pid <> 0 then
    begin
      pli := nil;
      if not noProcessInfo then
      begin
        GetMem(pli, SizeOf(TProcessListInfo));
        pli^.processID := entries[i].pid;
        pli^.winhandle := 0;
        pli^.processIcon := 0;
      end;

      if NoPID then
        s := ''
      else
        s := IntToHex(entries[i].pid, 8) + '-';

      nameStr := StrPas(PAnsiChar(@entries[i].name[0]));
      s := s + ExtractFileName(nameStr);

      if noProcessInfo or (pli = nil) then
        ProcessList.Add(s)
      else
        ProcessList.AddObject(s, TObject(pli));
    end;
  end;

  Result := True;
end;

function OnyxVehInject(dllPath: string = ''): Boolean;
var
  pProc: Pointer;
  pPath: PAnsiChar;
  ansiStr: AnsiString;
begin
  pProc := OnyxEnsureAttachedProcess;
  if pProc = nil then Exit(False);
  if dllPath <> '' then
  begin
    ansiStr := AnsiString(dllPath);
    pPath := PAnsiChar(ansiStr);
  end
  else
    pPath := nil;
  Result := onyx_veh_inject(pProc, pPath) = 1;
end;

function OnyxVehSetHardwareBreakpoint(address: PtrUInt; bpType: integer = 1; size: integer = 4): integer;
var
  pProc: Pointer;
begin
  pProc := OnyxEnsureAttachedProcess;
  if pProc = nil then Exit(-1);
  Result := onyx_veh_set_hw_bp(pProc, address, bpType, size);
end;

function OnyxVehClearHardwareBreakpointCode(index: PtrUInt): integer;
var
  pProc: Pointer;
begin
  pProc := OnyxEnsureAttachedProcess;
  if pProc = nil then Exit(-5);
  Result := onyx_veh_clear_hw_bp(pProc, index);
end;

function OnyxVehClearHardwareBreakpoint(index: PtrUInt): Boolean;
begin
  Result := OnyxVehClearHardwareBreakpointCode(index) = 1;
end;

function OnyxVehPollHit(var hitRip: PtrUInt; var threadId: DWORD): Boolean;
var
  pProc: Pointer;
  rRip: PtrUInt;
  rTid: DWORD;
begin
  hitRip := 0;
  threadId := 0;
  pProc := OnyxEnsureAttachedProcess;
  if pProc = nil then Exit(False);
  rRip := 0;
  rTid := 0;
  if onyx_veh_poll_hit(pProc, @rRip, @rTid) = 1 then
  begin
    hitRip := rRip;
    threadId := rTid;
    Result := True;
  end
  else
    Result := False;
end;

function OnyxVehSlotStatus(var slots: TOnyxVehSlotArray): integer;
var
  pProc: Pointer;
  used: integer;
begin
  FillChar(slots, SizeOf(slots), 0);
  Result := 0;

  pProc := OnyxEnsureAttachedProcess;
  if pProc = nil then Exit;

  used := onyx_veh_slot_status(pProc, @slots[0], Length(slots), nil);
  if used < 0 then
    Exit;

  if used > Length(slots) then
    used := Length(slots);

  Result := used;
end;

function OnyxVehVerifySlots: integer;
var
  pProc: Pointer;
begin
  pProc := OnyxEnsureAttachedProcess;
  if pProc = nil then Exit(-5);
  Result := onyx_veh_verify_slots(pProc);
end;

function OnyxVehHasActiveBreakpoints: Boolean;
begin
  Result := False;

  // Deliberately avoid OnyxEnsureAttachedProcess: this probe must not attach,
  // it only reports whether the current session already owns DR slots.
  if CurrentOnyxProcessHandle = nil then
    Exit;

  if CurrentOnyxPID <> ProcessHandlerUnit.ProcessID then
    Exit;

  Result := onyx_veh_slot_status(CurrentOnyxProcessHandle, nil, 0, nil) > 0;
end;

function OnyxVehErrorText(code: integer): string;
begin
  case code of
    -2: Result := 'All 4 hardware breakpoint slots are in use';
    -3: Result := 'Invalid hardware breakpoint slot (must be 0..3)';
    -4: Result := 'Target process has no active threads';
    -5: Result := 'Failed to update thread debug registers';
  else
    if code < 0 then
      Result := 'Unknown hardware breakpoint error (' + IntToStr(code) + ')'
    else
      Result := '';
  end;
end;

function OnyxMonoDetect: integer;
var
  pProc: Pointer;
begin
  pProc := OnyxEnsureAttachedProcess;
  if pProc = nil then Exit(0);
  Result := onyx_mono_detect(pProc);
end;

function OnyxMonoDissect: integer;
var
  pProc: Pointer;
begin
  pProc := OnyxEnsureAttachedProcess;
  if pProc = nil then Exit(0);
  Result := onyx_mono_dissect(pProc);
end;

function OnyxMonoGetClassCount: integer;
begin
  Result := onyx_mono_class_count;
end;

function OnyxMonoGetClassInfo(index: integer; var className: string; var classAddr: PtrUInt; var fieldsCount: DWORD): Boolean;
var
  buf: array[0..259] of AnsiChar;
  addr: PtrUInt;
  fc: DWORD;
begin
  className := '';
  classAddr := 0;
  fieldsCount := 0;
  addr := 0;
  fc := 0;
  FillChar(buf, SizeOf(buf), 0);
  if onyx_mono_get_class_info(index, @buf[0], SizeOf(buf), @addr, @fc) = 1 then
  begin
    className := StrPas(PAnsiChar(@buf[0]));
    classAddr := addr;
    fieldsCount := fc;
    Result := True;
  end
  else
    Result := False;
end;

function OnyxMonoFindFieldOffset(className, fieldName: string): integer;
var
  cAnsi, fAnsi: AnsiString;
begin
  cAnsi := AnsiString(className);
  fAnsi := AnsiString(fieldName);
  Result := onyx_mono_find_field_offset(PAnsiChar(cAnsi), PAnsiChar(fAnsi));
end;

function OnyxMonoFindMethodAddress(className, methodName: string): PtrUInt;
var
  cAnsi, mAnsi: AnsiString;
begin
  cAnsi := AnsiString(className);
  mAnsi := AnsiString(methodName);
  Result := onyx_mono_find_method_address(PAnsiChar(cAnsi), PAnsiChar(mAnsi));
end;

function OnyxMonoGenerateHook(methodName: string; methodAddr: PtrUInt): string;
var
  buf: array[0..4095] of AnsiChar;
  mAnsi: AnsiString;
begin
  FillChar(buf, SizeOf(buf), 0);
  mAnsi := AnsiString(methodName);
  if onyx_mono_generate_hook(PAnsiChar(mAnsi), methodAddr, @buf[0], SizeOf(buf)) = 1 then
    Result := StrPas(PAnsiChar(@buf[0]))
  else
    Result := '';
end;

function OnyxMonoCompileMethod(className, methodName: string): PtrUInt;
var
  hProc: Pointer;
  cAnsi, mAnsi: AnsiString;
begin
  hProc := OnyxEnsureAttachedProcess;
  if hProc = nil then Exit(0);
  cAnsi := AnsiString(className);
  mAnsi := AnsiString(methodName);
  Result := onyx_mono_compile_method(hProc, PAnsiChar(cAnsi), PAnsiChar(mAnsi));
end;

function OnyxMonoReadFieldValue(instanceAddress: PtrUInt; className, fieldName: string): string;
var
  hProc: Pointer;
  cAnsi, fAnsi: AnsiString;
  buf: array[0..255] of AnsiChar;
begin
  hProc := OnyxEnsureAttachedProcess;
  if hProc = nil then Exit('???');
  cAnsi := AnsiString(className);
  fAnsi := AnsiString(fieldName);
  FillChar(buf, SizeOf(buf), 0);
  if onyx_mono_read_field_value(hProc, instanceAddress, PAnsiChar(cAnsi), PAnsiChar(fAnsi), @buf[0], SizeOf(buf)) = 1 then
    Result := StrPas(PAnsiChar(@buf[0]))
  else
    Result := '???';
end;

function OnyxMonoGetAssemblyCount: integer;
begin
  Result := onyx_mono_get_assembly_count;
end;

function OnyxMonoGetAssemblyName(index: integer): string;
var
  buf: array[0..255] of AnsiChar;
begin
  FillChar(buf, SizeOf(buf), 0);
  if onyx_mono_get_assembly_name(index, @buf[0], SizeOf(buf)) = 1 then
    Result := StrPas(PAnsiChar(@buf[0]))
  else
    Result := '';
end;

function OnyxMonoDissectClrObject(objectAddress: PtrUInt; var outMt, outEeClass: PtrUInt; var outSize: DWORD): Boolean;
var
  hProc: Pointer;
  mt, ee: PtrUInt;
  sz: DWORD;
begin
  hProc := OnyxEnsureAttachedProcess;
  if hProc = nil then Exit(False);
  mt := 0;
  ee := 0;
  sz := 0;
  if onyx_mono_dissect_clr_object(hProc, objectAddress, @mt, @ee, @sz) = 1 then
  begin
    outMt := mt;
    outEeClass := ee;
    outSize := sz;
    Result := True;
  end
  else
    Result := False;
end;


function lua_onyx_veh_inject(L: PLua_State): integer; cdecl;
var
  dllPath: string;
  ok: Boolean;
begin
  dllPath := '';
  if lua_gettop(L) >= 1 then
    dllPath := lua_tostring(L, 1);
  ok := OnyxVehInject(dllPath);
  lua_pushboolean(L, ok);
  Result := 1;
end;

function lua_onyx_veh_set_hw_bp(L: PLua_State): integer; cdecl;
var
  addr: PtrUInt;
  bpType: integer;
  size: integer;
  slot: integer;
begin
  if lua_gettop(L) >= 1 then
  begin
    addr := lua_tointeger(L, 1);
    bpType := 1;
    size := 4;
    if lua_gettop(L) >= 2 then
      bpType := lua_tointeger(L, 2);
    if lua_gettop(L) >= 3 then
      size := lua_tointeger(L, 3);
    slot := OnyxVehSetHardwareBreakpoint(addr, bpType, size);
    lua_pushinteger(L, slot);
    Result := 1;
  end
  else
  begin
    lua_pushinteger(L, -1);
    Result := 1;
  end;
end;

function lua_onyx_veh_clear_hw_bp(L: PLua_State): integer; cdecl;
var
  idx: PtrUInt;
begin
  if lua_gettop(L) >= 1 then
  begin
    idx := lua_tointeger(L, 1);
    // Código cru: 1 = sucesso, negativo = erro (mesma convenção de onyx_veh_set_hw_bp).
    lua_pushinteger(L, OnyxVehClearHardwareBreakpointCode(idx));
    Result := 1;
  end
  else
  begin
    lua_pushinteger(L, -3);
    Result := 1;
  end;
end;

function lua_onyx_veh_poll_hit(L: PLua_State): integer; cdecl;
var
  hitRip: PtrUInt;
  threadId: DWORD;
  hit: Boolean;
begin
  hit := OnyxVehPollHit(hitRip, threadId);
  if hit then
  begin
    lua_pushinteger(L, hitRip);
    lua_pushinteger(L, threadId);
    Result := 2;
  end
  else
  begin
    lua_pushnil(L);
    Result := 1;
  end;
end;

function lua_onyx_veh_slot_status(L: PLua_State): integer; cdecl;
var
  slots: TOnyxVehSlotArray;
  used, i: integer;
begin
  used := OnyxVehSlotStatus(slots);

  lua_newtable(L);
  for i := 0 to used - 1 do
  begin
    lua_pushinteger(L, i + 1);
    lua_createtable(L, 0, 4);
    lua_pushinteger(L, slots[i].index);
    lua_setfield(L, -2, PChar('index'));
    lua_pushinteger(L, Int64(slots[i].address));
    lua_setfield(L, -2, PChar('address'));
    lua_pushinteger(L, slots[i].bp_type);
    lua_setfield(L, -2, PChar('bp_type'));
    lua_pushinteger(L, slots[i].size);
    lua_setfield(L, -2, PChar('size'));
    lua_settable(L, -3);
  end;

  Result := 1;
end;

function lua_onyx_veh_error_text(L: PLua_State): integer; cdecl;
var
  code: integer;
  text: string;
begin
  code := 0;
  if lua_gettop(L) >= 1 then
    code := lua_tointeger(L, 1);

  text := OnyxVehErrorText(code);
  lua_pushstring(L, PChar(text));
  Result := 1;
end;

function lua_onyx_veh_has_active_bp(L: PLua_State): integer; cdecl;
begin
  lua_pushboolean(L, OnyxVehHasActiveBreakpoints);
  Result := 1;
end;

function lua_onyx_veh_verify_slots(L: PLua_State): integer; cdecl;
begin
  // 1 = registro confere com o hardware, 0 = divergente, negativo = erro.
  lua_pushinteger(L, OnyxVehVerifySlots);
  Result := 1;
end;

function lua_onyx_mono_detect(L: PLua_State): integer; cdecl;
begin
  lua_pushinteger(L, OnyxMonoDetect);
  Result := 1;
end;

function lua_onyx_mono_dissect(L: PLua_State): integer; cdecl;
begin
  lua_pushinteger(L, OnyxMonoDissect);
  Result := 1;
end;

function lua_onyx_mono_class_count(L: PLua_State): integer; cdecl;
begin
  lua_pushinteger(L, OnyxMonoGetClassCount);
  Result := 1;
end;

function lua_onyx_mono_find_field_offset(L: PLua_State): integer; cdecl;
var
  cls, fld: string;
begin
  if lua_gettop(L) >= 2 then
  begin
    cls := lua_tostring(L, 1);
    fld := lua_tostring(L, 2);
    lua_pushinteger(L, OnyxMonoFindFieldOffset(cls, fld));
  end
  else
    lua_pushinteger(L, -1);
  Result := 1;
end;

function lua_onyx_mono_find_method_address(L: PLua_State): integer; cdecl;
var
  cls, meth: string;
begin
  if lua_gettop(L) >= 2 then
  begin
    cls := lua_tostring(L, 1);
    meth := lua_tostring(L, 2);
    lua_pushinteger(L, OnyxMonoFindMethodAddress(cls, meth));
  end
  else
    lua_pushinteger(L, 0);
  Result := 1;
end;

function lua_onyx_mono_generate_hook(L: PLua_State): integer; cdecl;
var
  meth: string;
  addr: PtrUInt;
  script: string;
begin
  if lua_gettop(L) >= 2 then
  begin
    meth := lua_tostring(L, 1);
    addr := lua_tointeger(L, 2);
    script := OnyxMonoGenerateHook(meth, addr);
    lua_pushstring(L, PAnsiChar(AnsiString(script)));
  end
  else
    lua_pushstring(L, '');
  Result := 1;
end;

procedure RegisterOnyxLua(L: Pointer);
var
  state: PLua_State;
begin
  if L = nil then Exit;
  state := PLua_State(L);

  lua.lua_register(state, 'onyx_veh_inject', @lua_onyx_veh_inject);
  lua.lua_register(state, 'onyx_veh_set_hw_bp', @lua_onyx_veh_set_hw_bp);
  lua.lua_register(state, 'onyx_veh_clear_hw_bp', @lua_onyx_veh_clear_hw_bp);
  lua.lua_register(state, 'onyx_veh_poll_hit', @lua_onyx_veh_poll_hit);
lua.lua_register(state, 'onyx_veh_slot_status', @lua_onyx_veh_slot_status);
lua.lua_register(state, 'onyx_veh_error_text', @lua_onyx_veh_error_text);
lua.lua_register(state, 'onyx_veh_has_active_bp', @lua_onyx_veh_has_active_bp);
lua.lua_register(state, 'onyx_veh_verify_slots', @lua_onyx_veh_verify_slots);

  lua.lua_register(state, 'onyx_mono_detect', @lua_onyx_mono_detect);
  lua.lua_register(state, 'onyx_mono_dissect', @lua_onyx_mono_dissect);
  lua.lua_register(state, 'onyx_mono_class_count', @lua_onyx_mono_class_count);
  lua.lua_register(state, 'onyx_mono_find_field_offset', @lua_onyx_mono_find_field_offset);
  lua.lua_register(state, 'onyx_mono_find_method_address', @lua_onyx_mono_find_method_address);
  lua.lua_register(state, 'onyx_mono_generate_hook', @lua_onyx_mono_generate_hook);
end;

function InitOnyxBackend: Boolean;
var
  v: DWORD;
begin
  try
    v := onyx_backend_version;
    Result := (v >= 100) and (onyx_backend_ping = 1);
    if Result then
    begin
      try
        onyx_security_cloak_self;
      except
      end;
      HookKernelHandlerWithOnyx;
      if OnyxBridgeInstance = nil then
      begin
        OnyxBridgeInstance := TOnyxDisasmBridge.Create;
        registerGlobalDisassembleOverride(OnyxBridgeInstance.DisasmOverride);
      end;

      if OnyxSpeedhackBridgeInstance = nil then
      begin
        OnyxSpeedhackBridgeInstance := TOnyxSpeedhackBridge.Create;
        registerSpeedhackCallbacks(OnyxSpeedhackBridgeInstance.OnActivate, OnyxSpeedhackBridgeInstance.OnSetSpeed);
      end;
    end;
  except
    Result := False;
  end;
end;

type
  TOnyxPluginValidateAOBFn = function(pid: DWORD; pattern: PAnsiChar; module_filter: PAnsiChar; out_result: POnyxAobMatchResult): integer; stdcall;
  TOnyxPluginGenerateAOBFn = function(pid: DWORD; target_address: UInt64; max_len: DWORD; out_pattern_buf: PAnsiChar; buf_size: DWORD): integer; stdcall;

var
  hAobToolPlugin: THandle = 0;
  fnAobValidate: TOnyxPluginValidateAOBFn = nil;
  fnAobGenerate: TOnyxPluginGenerateAOBFn = nil;

function EnsureAobToolPlugin: Boolean;
var
  candidates: array[0..4] of string;
  i: integer;
  baseDir: string;
begin
  if (hAobToolPlugin <> 0) and Assigned(fnAobValidate) then
    Exit(True);

  baseDir := ExtractFilePath(ParamStr(0));
  candidates[0] := baseDir + 'plugins\onyx_aob_tool.dll';
  candidates[1] := baseDir + 'bin\plugins\onyx_aob_tool.dll';
  candidates[2] := 'plugins\onyx_aob_tool.dll';
  candidates[3] := 'bin\plugins\onyx_aob_tool.dll';
  candidates[4] := 'onyx_aob_tool.dll';

  for i := 0 to 4 do
  begin
    if FileExists(candidates[i]) then
    begin
      hAobToolPlugin := LoadLibraryA(PAnsiChar(AnsiString(candidates[i])));
      if hAobToolPlugin <> 0 then Break;
    end;
  end;

  if hAobToolPlugin = 0 then
    hAobToolPlugin := LoadLibraryA('onyx_aob_tool.dll');

  if hAobToolPlugin <> 0 then
  begin
    fnAobValidate := TOnyxPluginValidateAOBFn(GetProcAddress(hAobToolPlugin, 'OnyxPlugin_ValidateAOB'));
    fnAobGenerate := TOnyxPluginGenerateAOBFn(GetProcAddress(hAobToolPlugin, 'OnyxPlugin_GenerateAOB'));
    Result := Assigned(fnAobValidate);
  end
  else
    Result := False;
end;

function OnyxValidateAOBPlugin(pid: DWORD; pattern: PAnsiChar; module_filter: PAnsiChar; out_result: POnyxAobMatchResult): integer;
begin
  if not EnsureAobToolPlugin then Exit(-2);
  if Assigned(fnAobValidate) then
    Result := fnAobValidate(pid, pattern, module_filter, out_result)
  else
    Result := -5;
end;

function OnyxGenerateAOBPlugin(pid: DWORD; target_address: UInt64; max_len: DWORD; out_pattern: PAnsiChar; buf_size: DWORD): integer;
begin
  if not EnsureAobToolPlugin then Exit(-2);
  if Assigned(fnAobGenerate) then
    Result := fnAobGenerate(pid, target_address, max_len, out_pattern, buf_size)
  else
    Result := -5;
end;

procedure OnyxUnloadAOBPlugin;
begin
  if hAobToolPlugin <> 0 then
  begin
    FreeLibrary(hAobToolPlugin);
    hAobToolPlugin := 0;
  end;
  fnAobValidate := nil;
  fnAobGenerate := nil;
end;

type
  TOnyxPluginHostGetPidFn = function: DWORD; stdcall;
  TOnyxPluginHostGetHandleFn = function: THandle; stdcall;
  TOnyxPluginHostAPI = packed record
    struct_size: DWORD;
    get_target_pid: TOnyxPluginHostGetPidFn;
    get_target_handle: TOnyxPluginHostGetHandleFn;
    read_memory: Pointer;
    write_memory: Pointer;
    resolve_symbol: Pointer;
    log_message: Pointer;
  end;
  POnyxPluginHostAPI = ^TOnyxPluginHostAPI;

  TOnyxPluginInitFn = function(host_api: POnyxPluginHostAPI): integer; stdcall;
  TOnyxPluginMapDllPidFn = function(pid: DWORD; dll_path: PAnsiChar; options: POnyxMapOptions; out_result: POnyxMapResult): integer; stdcall;
  TOnyxPluginMapDllNamedFn = function(target_name: PAnsiChar; dll_path: PAnsiChar; options: POnyxMapOptions; out_result: POnyxMapResult): integer; stdcall;

var
  hDllMapperPlugin: THandle = 0;
  fnDllMapperInit: TOnyxPluginInitFn = nil;
  fnDllMapDllPid: TOnyxPluginMapDllPidFn = nil;
  fnDllMapDllNamed: TOnyxPluginMapDllNamedFn = nil;
  dllMapperHostAPI: TOnyxPluginHostAPI;

function HostPluginGetPid: DWORD; stdcall;
begin
  Result := processid;
end;

function HostPluginGetHandle: THandle; stdcall;
begin
  Result := processhandle;
end;

function EnsureDllMapperPlugin: Boolean;
var
  candidates: array[0..4] of string;
  i: integer;
  baseDir: string;
begin
  if (hDllMapperPlugin <> 0) and Assigned(fnDllMapDllPid) then
    Exit(True);

  baseDir := ExtractFilePath(ParamStr(0));
  candidates[0] := baseDir + 'plugins\onyx_dll_mapper.dll';
  candidates[1] := baseDir + 'bin\plugins\onyx_dll_mapper.dll';
  candidates[2] := 'plugins\onyx_dll_mapper.dll';
  candidates[3] := 'bin\plugins\onyx_dll_mapper.dll';
  candidates[4] := 'onyx_dll_mapper.dll';

  for i := 0 to 4 do
  begin
    if FileExists(candidates[i]) then
    begin
      hDllMapperPlugin := LoadLibraryA(PAnsiChar(AnsiString(candidates[i])));
      if hDllMapperPlugin <> 0 then Break;
    end;
  end;

  if hDllMapperPlugin = 0 then
    hDllMapperPlugin := LoadLibraryA('onyx_dll_mapper.dll');

  if hDllMapperPlugin <> 0 then
  begin
    fnDllMapperInit := TOnyxPluginInitFn(GetProcAddress(hDllMapperPlugin, 'OnyxPlugin_Init'));
    fnDllMapDllPid := TOnyxPluginMapDllPidFn(GetProcAddress(hDllMapperPlugin, 'OnyxPlugin_MapDllPid'));
    fnDllMapDllNamed := TOnyxPluginMapDllNamedFn(GetProcAddress(hDllMapperPlugin, 'OnyxPlugin_MapDllNamed'));

    if Assigned(fnDllMapperInit) then
    begin
      FillChar(dllMapperHostAPI, SizeOf(dllMapperHostAPI), 0);
      dllMapperHostAPI.struct_size := SizeOf(dllMapperHostAPI);
      dllMapperHostAPI.get_target_pid := @HostPluginGetPid;
      dllMapperHostAPI.get_target_handle := @HostPluginGetHandle;
      fnDllMapperInit(@dllMapperHostAPI);
    end;

    Result := Assigned(fnDllMapDllPid);
  end
  else
    Result := False;
end;

function OnyxMapDllPlugin(pid: DWORD; dll_path: PAnsiChar; options: POnyxMapOptions; out_result: POnyxMapResult): integer;
begin
  if not EnsureDllMapperPlugin then Exit(-2);
  if Assigned(fnDllMapDllPid) then
    Result := fnDllMapDllPid(pid, dll_path, options, out_result)
  else
    Result := -5;
end;

function OnyxMapDllNamedPlugin(target_name: PAnsiChar; dll_path: PAnsiChar; options: POnyxMapOptions; out_result: POnyxMapResult): integer;
begin
  if not EnsureDllMapperPlugin then Exit(-2);
  if Assigned(fnDllMapDllNamed) then
    Result := fnDllMapDllNamed(target_name, dll_path, options, out_result)
  else
    Result := -5;
end;

procedure OnyxUnloadDllMapperPlugin;
begin
  if hDllMapperPlugin <> 0 then
  begin
    FreeLibrary(hDllMapperPlugin);
    hDllMapperPlugin := 0;
  end;
  fnDllMapperInit := nil;
  fnDllMapDllPid := nil;
  fnDllMapDllNamed := nil;
end;

initialization
  InitOnyxBackend;

finalization
  if hAobToolPlugin <> 0 then
  begin
    FreeLibrary(hAobToolPlugin);
    hAobToolPlugin := 0;
  end;
  if GlobalOnyxFreezer <> nil then
  begin
    onyx_freezer_destroy(GlobalOnyxFreezer);
    GlobalOnyxFreezer := nil;
  end;

  if GlobalOnyxPointerScanner <> nil then
  begin
    onyx_pointer_scanner_destroy(GlobalOnyxPointerScanner);
    GlobalOnyxPointerScanner := nil;
  end;

  if OnyxSpeedhackBridgeInstance <> nil then
  begin
    FreeAndNil(OnyxSpeedhackBridgeInstance);
  end;

  if CurrentOnyxScanner <> nil then
  begin
    onyx_scanner_destroy(CurrentOnyxScanner);
    CurrentOnyxScanner := nil;
  end;

  if OnyxBridgeInstance <> nil then
  begin
    FreeAndNil(OnyxBridgeInstance);
  end;

  if CurrentOnyxProcessHandle <> nil then
  begin
    onyx_process_close(CurrentOnyxProcessHandle);
    CurrentOnyxProcessHandle := nil;
  end;

  onyx_veh_cleanup;

end.
