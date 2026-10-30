unit frmManualMapperUnit;

{$MODE Delphi}

interface

uses
  Windows, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
  StdCtrls, ExtCtrls, ProcessHandlerUnit, betterControls, OnyxBackend;

type
  TfrmManualMapper = class(TForm)
    pnlHeader: TPanel;
    lblTitle: TLabel;
    lblSubtitle: TLabel;
    gbTarget: TGroupBox;
    lblTarget: TLabel;
    edtTarget: TEdit;
    btnRefreshTarget: TButton;
    gbDll: TGroupBox;
    lblDll: TLabel;
    edtDllPath: TEdit;
    btnBrowse: TButton;
    gbOptions: TGroupBox;
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
    procedure btnBrowseClick(Sender: TObject);
    procedure btnInjectClick(Sender: TObject);
    procedure btnOpenMemViewClick(Sender: TObject);
    procedure btnCloseClick(Sender: TObject);
  private
    lastMappedBase: UInt64;
    procedure UpdateTargetDisplay;
  public
  end;

var
  frmManualMapper: TfrmManualMapper;

implementation

{$R *.lfm}

uses
  MemoryBrowserFormUnit, processlist;

function GetCurrentTargetName: string;
var
  modName: string;
begin
  if processid <> 0 then
  begin
    modName := ExtractFileName(GetFirstModuleName(processid));
    if modName <> '' then
      Exit(modName);
    Exit(Format('PID %d', [processid]));
  end;
  Result := 'Nenhum processo';
end;

procedure TfrmManualMapper.FormCreate(Sender: TObject);
begin
  lastMappedBase := 0;
  pnlStatusBadge.Color := $282828;
  lblStatus.Font.Color := $AAAAAA;
  lblStatus.Caption := 'Aguardando configuração de injeção...';
end;

procedure TfrmManualMapper.FormShow(Sender: TObject);
begin
  UpdateTargetDisplay;
  if (edtDllPath.Text = '') and edtDllPath.CanFocus then
    edtDllPath.SetFocus;
end;

procedure TfrmManualMapper.UpdateTargetDisplay;
begin
  if (processid <> 0) and (processhandle <> 0) then
    edtTarget.Text := Format('[PID: %d (0x%X)] %s', [processid, processid, GetCurrentTargetName])
  else
    edtTarget.Text := 'Nenhum processo anexado no OnyxEngine';
end;

procedure TfrmManualMapper.btnRefreshTargetClick(Sender: TObject);
begin
  UpdateTargetDisplay;
end;

procedure TfrmManualMapper.btnBrowseClick(Sender: TObject);
begin
  if OpenDialog1.Execute then
    edtDllPath.Text := OpenDialog1.FileName;
end;

procedure TfrmManualMapper.btnInjectClick(Sender: TObject);
var
  dllPath: string;
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

  if (processid = 0) or (processhandle = 0) then
  begin
    MessageDlg('Aviso', 'Nenhum processo alvo está anexado. Anexe um processo primeiro.', mtWarning, [mbOK], 0);
    Exit;
  end;

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

  FillChar(opts, SizeOf(opts), 0);
  opts.struct_size := SizeOf(opts);
  opts.flags := flags;

  FillChar(resData, SizeOf(resData), 0);

  rc := OnyxMapDllPlugin(processid, PAnsiChar(AnsiString(dllPath)), @opts, @resData);

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
    mmoLog.Lines.Add(Format('[+] Alvo: PID %d (%s)', [processid, GetCurrentTargetName]));
    mmoLog.Lines.Add(Format('[+] Base Alocada: 0x%X', [resData.image_base]));
    mmoLog.Lines.Add(Format('[+] EntryPoint: 0x%X', [resData.entry_point]));
    mmoLog.Lines.Add(Format('[+] Flags: 0x%X', [resData.flags_applied]));
    if cbEraseHeaders.Checked then
      mmoLog.Lines.Add('[+] PE Headers zerados (anti-memory dump)');
    if cbResolvePeb.Checked then
      mmoLog.Lines.Add('[+] Imports resolvidos diretamente via PEB/EAT');
    if cbRegisterSeh.Checked then
      mmoLog.Lines.Add('[+] Runtime Function Table (SEH) registrada');
    if cbInitCookie.Checked then
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
