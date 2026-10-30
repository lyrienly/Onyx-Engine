unit frmManualMapperUnit;

{$MODE Delphi}

interface

uses
  Windows, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
  StdCtrls, ExtCtrls, ProcessHandlerUnit, NewKernelHandler, betterControls, OnyxBackend;

type
  TfrmManualMapper = class(TForm)
    pnlHeader: TPanel;
    lblTitle: TLabel;
    lblSubtitle: TLabel;
    gbTarget: TGroupBox;
    lblTarget: TLabel;
    cbTarget: TComboBox;
    btnRefreshTarget: TButton;
    gbDll: TGroupBox;
    lblDll: TLabel;
    edtDllPath: TEdit;
    btnBrowse: TButton;
    gbMode: TGroupBox;
    cbAutoStealth: TCheckBox;
    pnlDriverStatus: TPanel;
    lblDriverStatus: TLabel;
    pnlManualOptions: TPanel;
    cbEraseHeaders: TCheckBox;
    cbProtectSections: TCheckBox;
    cbCallTls: TCheckBox;
    cbResolvePeb: TCheckBox;
    cbRegisterSeh: TCheckBox;
    cbInitCookie: TCheckBox;
    cbThreadHijack: TCheckBox;
    cbUseDriver: TCheckBox;
    cbModuleStomp: TCheckBox;
    cbWipeStub: TCheckBox;
    gbResults: TGroupBox;
    pnlStatusBadge: TPanel;
    lblStatus: TLabel;
    lblImageBase: TLabel;
    edtImageBase: TEdit;
    lblEntryPoint: TLabel;
    edtEntryPoint: TEdit;
    lblDllMainResult: TLabel;
    edtDllMainResult: TEdit;
    lblStats: TLabel;
    edtStats: TEdit;
    lblLog: TLabel;
    mmoLog: TMemo;
    pnlBottom: TPanel;
    btnInject: TButton;
    btnOpenMemView: TButton;
    btnClose: TButton;
    OpenDialog1: TOpenDialog;
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure btnRefreshTargetClick(Sender: TObject);
    procedure cbTargetChange(Sender: TObject);
    procedure cbAutoStealthChange(Sender: TObject);
    procedure btnBrowseClick(Sender: TObject);
    procedure btnInjectClick(Sender: TObject);
    procedure btnOpenMemViewClick(Sender: TObject);
    procedure btnCloseClick(Sender: TObject);
  private
    lastMappedBase: UInt64;
    procedure PopulateProcessList;
    procedure UpdateDriverStatus;
    function GetSelectedPid: DWORD;
    function GetSelectedProcessName: string;
  public
  end;

var
  frmManualMapper: TfrmManualMapper;

implementation

{$R *.lfm}

uses
  MemoryBrowserFormUnit, processlist, ProcessWindowUnit, NewKernelHandler;

procedure TfrmManualMapper.FormCreate(Sender: TObject);
begin
  lastMappedBase := 0;
  pnlStatusBadge.Color := $282828;
  lblStatus.Font.Color := $AAAAAA;
  lblStatus.Caption := 'Aguardando configuração de injeção...';
end;

procedure TfrmManualMapper.FormShow(Sender: TObject);
begin
  PopulateProcessList;
  UpdateDriverStatus;
  cbAutoStealth.Checked := True;
  pnlManualOptions.Visible := False;
  if (edtDllPath.Text = '') and edtDllPath.CanFocus then
    edtDllPath.SetFocus;
end;

procedure TfrmManualMapper.UpdateDriverStatus;
begin
  if DBKLoaded then
  begin
    pnlDriverStatus.Color := $1E3326;
    lblDriverStatus.Font.Color := $00E676;
    lblDriverStatus.Caption := 'Driver Kernel DBK: ATIVO (Elevação Ring-0 e bypass VAD automáticos)';
  end
  else
  begin
    pnlDriverStatus.Color := $1F2B38;
    lblDriverStatus.Font.Color := $00E5FF;
    lblDriverStatus.Caption := 'Driver Kernel DBK: DESATIVADO (Modo Furtivo User-Mode automático: PEB EAT + SEH + TLS)';
  end;
end;

procedure TfrmManualMapper.PopulateProcessList;
var
  i: integer;
  currentHex: string;
  selectedIndex: integer;
begin
  cbTarget.Items.BeginUpdate;
  try
    cbTarget.Items.Clear;
    GetProcessList(cbTarget.Items);
  finally
    cbTarget.Items.EndUpdate;
  end;

  selectedIndex := -1;
  if processid <> 0 then
  begin
    currentHex := IntToHex(processid, 8);
    for i := 0 to cbTarget.Items.Count - 1 do
    begin
      if Pos(currentHex, cbTarget.Items[i]) = 1 then
      begin
        selectedIndex := i;
        Break;
      end;
    end;
  end;

  if (selectedIndex = -1) and (cbTarget.Items.Count > 0) then
    selectedIndex := 0;

  if selectedIndex >= 0 then
    cbTarget.ItemIndex := selectedIndex;
end;

function TfrmManualMapper.GetSelectedPid: DWORD;
var
  sel: string;
  dashPos: integer;
  hexStr: string;
begin
  Result := 0;
  if cbTarget.ItemIndex >= 0 then
    sel := cbTarget.Items[cbTarget.ItemIndex]
  else
    sel := Trim(cbTarget.Text);

  if sel = '' then Exit;

  dashPos := Pos('-', sel);
  if dashPos > 0 then
  begin
    hexStr := Trim(Copy(sel, 1, dashPos - 1));
    Result := StrToIntDef('$' + hexStr, 0);
  end
  else
    Result := StrToIntDef(sel, 0);
end;

function TfrmManualMapper.GetSelectedProcessName: string;
var
  sel: string;
  dashPos: integer;
begin
  if cbTarget.ItemIndex >= 0 then
    sel := cbTarget.Items[cbTarget.ItemIndex]
  else
    sel := Trim(cbTarget.Text);

  dashPos := Pos('-', sel);
  if dashPos > 0 then
    Result := Trim(Copy(sel, dashPos + 1, Length(sel)))
  else
    Result := sel;
end;

procedure TfrmManualMapper.btnRefreshTargetClick(Sender: TObject);
var
  resu: TModalResult;
  selectedText: string;
  i: integer;
begin
  if ProcessWindow = nil then
    ProcessWindow := TProcessWindow.Create(Application);

  resu := ProcessWindow.ShowModal;
  if (resu = mrOk) or (ProcessWindow.ModalResult = mrOk) then
  begin
    PopulateProcessList;

    if (ProcessWindow.ProcessList.ItemIndex >= 0) and
       (ProcessWindow.ProcessList.Items.Count > ProcessWindow.ProcessList.ItemIndex) then
    begin
      selectedText := ProcessWindow.ProcessList.Items[ProcessWindow.ProcessList.ItemIndex];
      for i := 0 to cbTarget.Items.Count - 1 do
      begin
        if (cbTarget.Items[i] = selectedText) or
           ((processid <> 0) and (Pos(IntToHex(processid, 8), cbTarget.Items[i]) = 1)) then
        begin
          cbTarget.ItemIndex := i;
          Break;
        end;
      end;
    end;

    UpdateDriverStatus;
  end;
end;

procedure TfrmManualMapper.cbTargetChange(Sender: TObject);
var
  newPid: DWORD;
begin
  newPid := GetSelectedPid;
  if newPid <> 0 then
    processid := newPid;
  UpdateDriverStatus;
end;

procedure TfrmManualMapper.cbAutoStealthChange(Sender: TObject);
begin
  pnlManualOptions.Visible := not cbAutoStealth.Checked;
  if not cbAutoStealth.Checked then
    Height := 690
  else
    Height := 600;
end;

procedure TfrmManualMapper.btnBrowseClick(Sender: TObject);
begin
  if OpenDialog1.Execute then
    edtDllPath.Text := OpenDialog1.FileName;
end;

procedure TfrmManualMapper.btnInjectClick(Sender: TObject);
var
  dllPath: string;
  targetPid: DWORD;
  targetName: string;
  opts: TOnyxMapOptions;
  resData: TOnyxMapResult;
  flags: DWORD;
  rc: integer;
begin
  dllPath := Trim(edtDllPath.Text);
  if dllPath = '' then
  begin
    MessageDlg('Aviso', 'Selecione uma DLL para injeção manual.', mtWarning, [mbOK], 0);
    Exit;
  end;

  if not FileExists(dllPath) then
  begin
    MessageDlg('Erro', 'Arquivo DLL não encontrado no caminho especificado.', mtError, [mbOK], 0);
    Exit;
  end;

  targetPid := GetSelectedPid;
  if targetPid = 0 then
  begin
    MessageDlg('Aviso', 'Selecione um processo alvo na lista suspensa.', mtWarning, [mbOK], 0);
    Exit;
  end;

  targetName := GetSelectedProcessName;

  if cbAutoStealth.Checked then
  begin
    flags := ONYX_MAP_AUTO;
  end
  else
  begin
    flags := 0;
    if cbEraseHeaders.Checked then flags := flags or ONYX_MAP_ERASE_HEADERS;
    if cbProtectSections.Checked then flags := flags or ONYX_MAP_PROTECT_SECTIONS;
    if cbCallTls.Checked then flags := flags or ONYX_MAP_CALL_TLS;
    if cbThreadHijack.Checked then flags := flags or ONYX_MAP_THREAD_HIJACK;
    if cbUseDriver.Checked then flags := flags or ONYX_MAP_USE_DRIVER;
    if cbWipeStub.Checked then flags := flags or ONYX_MAP_WIPE_STUB;
    if cbModuleStomp.Checked then flags := flags or ONYX_MAP_MODULE_STOMP;
    if cbResolvePeb.Checked then flags := flags or ONYX_MAP_RESOLVE_PEB;
    if cbRegisterSeh.Checked then flags := flags or ONYX_MAP_REGISTER_SEH;
    if cbInitCookie.Checked then flags := flags or ONYX_MAP_INIT_COOKIE;
  end;

  FillChar(opts, SizeOf(opts), 0);
  opts.struct_size := SizeOf(opts);
  opts.flags := flags;

  FillChar(resData, SizeOf(resData), 0);

  rc := OnyxMapDllPlugin(targetPid, PAnsiChar(AnsiString(dllPath)), @opts, @resData);

  if rc = 0 then
  begin
    lastMappedBase := resData.image_base;
    pnlStatusBadge.Color := $25382E;
    lblStatus.Font.Color := $00E676;
    lblStatus.Caption := 'SUCESSO: DLL Mapeada e Executada com Êxito';

    edtImageBase.Text := '0x' + IntToHex(resData.image_base, 12);
    edtEntryPoint.Text := '0x' + IntToHex(resData.entry_point, 12);
    if resData.dll_main_result = 1 then
      edtDllMainResult.Text := '1 (TRUE - Sucesso)'
    else
      edtDllMainResult.Text := Format('%d', [resData.dll_main_result]);

    edtStats.Text := Format('%d relocações aplicadas | %d imports resolvidos', [resData.relocations, resData.imports]);

    mmoLog.Lines.Clear;
    mmoLog.Lines.Add(Format('[+] DLL: %s', [ExtractFileName(dllPath)]));
    mmoLog.Lines.Add(Format('[+] Alvo: PID %d (%s)', [targetPid, targetName]));
    mmoLog.Lines.Add(Format('[+] Base Alocada: 0x%X', [resData.image_base]));
    mmoLog.Lines.Add(Format('[+] EntryPoint: 0x%X', [resData.entry_point]));
    if DBKLoaded then
      mmoLog.Lines.Add('[+] Modo: Kernel Driver (DBK Ring-0)')
    else
      mmoLog.Lines.Add('[+] Modo: User-Mode Stealth Avançado');
    mmoLog.Lines.Add('[+] PE Headers zerados (anti-memory dump)');
    mmoLog.Lines.Add('[+] Imports resolvidos via PEB/EAT');
    mmoLog.Lines.Add('[+] Runtime Function Table (SEH) registrada');
    mmoLog.Lines.Add('[+] Security Cookie inicializado');
  end
  else
  begin
    lastMappedBase := 0;
    pnlStatusBadge.Color := $382020;
    lblStatus.Font.Color := $5050FF;
    lblStatus.Caption := Format('FALHA NA INJEÇÃO (Código de Erro: %d)', [rc]);

    edtImageBase.Text := '-';
    edtEntryPoint.Text := '-';
    edtDllMainResult.Text := '-';
    edtStats.Text := '-';

    mmoLog.Lines.Clear;
    mmoLog.Lines.Add(Format('[-] Falha ao mapear DLL: %s', [dllPath]));
    mmoLog.Lines.Add(Format('[-] Alvo: PID %d (%s)', [targetPid, targetName]));
    if resData.error[0] <> #0 then
      mmoLog.Lines.Add(Format('[-] Detalhes: %s', [string(resData.error)]))
    else
      mmoLog.Lines.Add(Format('[-] Erro interno retornado pelo plugin: %d', [rc]));
  end;
end;

procedure TfrmManualMapper.btnOpenMemViewClick(Sender: TObject);
begin
  if lastMappedBase <> 0 then
  begin
    if memorybrowser = nil then
      memorybrowser := TMemoryBrowser.Create(Application);
    memorybrowser.memoryaddress := lastMappedBase;
    memorybrowser.Show;
    memorybrowser.BringToFront;
  end
  else
  begin
    MessageDlg('Aviso', 'Nenhuma DLL mapeada recentemente para visualizar.', mtInformation, [mbOK], 0);
  end;
end;

procedure TfrmManualMapper.btnCloseClick(Sender: TObject);
begin
  Close;
end;

end.
