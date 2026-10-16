unit OnyxBackend;

{$MODE Delphi}

interface

uses
  windows, sysutils, classes, NewKernelHandler;

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

function onyx_process_list(out_entries: Pointer; max_count: DWORD; out_total: PDWORD): integer; stdcall; external OnyxBackendDLL;
function onyx_process_attach(pid: DWORD): Pointer; stdcall; external OnyxBackendDLL;
procedure onyx_process_close(handle: Pointer); stdcall; external OnyxBackendDLL;
function onyx_process_read(handle: Pointer; base_address: PtrUInt; buffer: Pointer; size: PtrUInt; out_bytes_read: PPtrUInt): integer; stdcall; external OnyxBackendDLL;
function onyx_process_write(handle: Pointer; base_address: PtrUInt; buffer: Pointer; size: PtrUInt; out_bytes_written: PPtrUInt): integer; stdcall; external OnyxBackendDLL;
function onyx_process_protect(handle: Pointer; base_address: PtrUInt; size: PtrUInt; new_protect: DWORD; old_protect: PDWORD): integer; stdcall; external OnyxBackendDLL;
function onyx_process_alloc(handle: Pointer; preferred_address: PtrUInt; size: PtrUInt; alloc_type: DWORD; protect: DWORD): PtrUInt; stdcall; external OnyxBackendDLL;
function onyx_process_free(handle: Pointer; base_address: PtrUInt; size: PtrUInt; free_type: DWORD): integer; stdcall; external OnyxBackendDLL;
function onyx_process_modules(handle: Pointer; out_modules: Pointer; max_count: DWORD; out_total: PDWORD): integer; stdcall; external OnyxBackendDLL;
function onyx_process_regions(handle: Pointer; out_regions: Pointer; max_count: DWORD; out_total: PDWORD): integer; stdcall; external OnyxBackendDLL;

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

function onyx_freezer_create(process: Pointer; interval_ms: UInt64): Pointer; stdcall; external OnyxBackendDLL;
procedure onyx_freezer_destroy(freezer: Pointer); stdcall; external OnyxBackendDLL;
function onyx_freezer_add(freezer: Pointer; address: PtrUInt; val_type_idx: integer; val_str: PAnsiChar; description: PAnsiChar): PtrUInt; stdcall; external OnyxBackendDLL;
function onyx_freezer_remove(freezer: Pointer; entry_id: PtrUInt): integer; stdcall; external OnyxBackendDLL;
procedure onyx_freezer_clear(freezer: Pointer); stdcall; external OnyxBackendDLL;

function onyx_pointer_resolve(proc: Pointer; base_addr: PtrUInt; offsets: PPtrUInt; offset_count: PtrUInt): PtrUInt; stdcall; external OnyxBackendDLL;
function onyx_pointer_eval_path(proc: Pointer; module_name: PAnsiChar; base_offset: PtrUInt; offsets: PPtrUInt; offset_count: PtrUInt): PtrUInt; stdcall; external OnyxBackendDLL;
function onyx_pointer_scanner_create: Pointer; stdcall; external OnyxBackendDLL;
procedure onyx_pointer_scanner_destroy(session: Pointer); stdcall; external OnyxBackendDLL;
function onyx_pointer_scanner_start_scan(session: Pointer; proc: Pointer; target_addr: PtrUInt; max_depth: PtrUInt; max_offset: PtrUInt; alignment: PtrUInt; max_results: PtrUInt): integer; stdcall; external OnyxBackendDLL;
function onyx_pointer_scanner_start_rescan(session: Pointer; proc: Pointer; new_target_addr: PtrUInt): integer; stdcall; external OnyxBackendDLL;
function onyx_pointer_scanner_cancel(session: Pointer): integer; stdcall; external OnyxBackendDLL;
function onyx_pointer_scanner_get_status(session: Pointer; out_phase: PDWORD; out_progress: PSingle; out_found_count: PPtrUInt): integer; stdcall; external OnyxBackendDLL;
function onyx_pointer_scanner_get_count(session: Pointer): PtrUInt; stdcall; external OnyxBackendDLL;
function onyx_pointer_scanner_get_path(session: Pointer; index: PtrUInt; out_record: POnyxPointerPathRecord): integer; stdcall; external OnyxBackendDLL;
function onyx_pointer_scanner_save_results(session: Pointer; file_path: PAnsiChar): integer; stdcall; external OnyxBackendDLL;
function onyx_pointer_scanner_load_results(session: Pointer; file_path: PAnsiChar): integer; stdcall; external OnyxBackendDLL;

function onyx_speedhack_set(process: Pointer; multiplier: Single): integer; stdcall; external OnyxBackendDLL;
function onyx_mono_detect(process: Pointer): integer; stdcall; external OnyxBackendDLL;
function onyx_mono_dissect(process: Pointer): integer; stdcall; external OnyxBackendDLL;
function onyx_mono_class_count: integer; stdcall; external OnyxBackendDLL;

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
  var outFound: UInt64
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

implementation

uses
  ProcessHandlerUnit, disassembler, lastdisassembledata;

type
  TOnyxDisasmBridge = class
  public
    function DisasmOverride(sender: TObject; address: ptruint; var ldd: TLastDisassembleData; var output: string; var description: string): boolean;
  end;

var
  OnyxBridgeInstance: TOnyxDisasmBridge = nil;

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
  var outFound: UInt64
): Boolean;
var
  count: Int64;
  res: Int64;
  filePath: AnsiString;
  curPid: DWORD;
begin
  Result := False;
  outFound := 0;

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

  // Prepare UNDO files for Cheat Engine compatibility
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
begin
  if (CurrentOnyxProcessHandle <> nil) and (CurrentOnyxPID <> dwProcessId) then
  begin
    onyx_process_close(CurrentOnyxProcessHandle);
    CurrentOnyxProcessHandle := nil;
  end;

  CurrentOnyxProcessHandle := onyx_process_attach(dwProcessId);
  CurrentOnyxPID := dwProcessId;

  if Assigned(OriginalOpenProcess) then
    Result := OriginalOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
  else
    Result := THandle(CurrentOnyxProcessHandle);
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

function InitOnyxBackend: Boolean;
var
  v: DWORD;
begin
  try
    v := onyx_backend_version;
    Result := (v >= 100) and (onyx_backend_ping = 1);
    if Result then
    begin
      HookKernelHandlerWithOnyx;
      if OnyxBridgeInstance = nil then
      begin
        OnyxBridgeInstance := TOnyxDisasmBridge.Create;
        registerGlobalDisassembleOverride(OnyxBridgeInstance.DisasmOverride);
      end;
    end;
  except
    Result := False;
  end;
end;

initialization
  InitOnyxBackend;

finalization
  if GlobalOnyxPointerScanner <> nil then
  begin
    onyx_pointer_scanner_destroy(GlobalOnyxPointerScanner);
    GlobalOnyxPointerScanner := nil;
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

end.
