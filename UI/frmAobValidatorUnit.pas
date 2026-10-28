unit frmAobValidatorUnit;

{$MODE Delphi}

interface

uses
  Windows, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
  StdCtrls, ExtCtrls, Clipbrd, betterControls, ProcessHandlerUnit,
  symbolhandler, OnyxBackend;

type
  TfrmAobValidator = class(TForm)
    pnlHeader: TPanel;
    lblTitle: TLabel;
    lblSubtitle: TLabel;
    gbInput: TGroupBox;
    lblAob: TLabel;
    edtAob: TEdit;
    lblModule: TLabel;
    edtModule: TEdit;
    btnValidate: TButton;
    btnGenerate: TButton;
    gbResults: TGroupBox;
    pnlStatusBadge: TPanel;
    lblStatus: TLabel;
    lblAddress: TLabel;
    edtAddress: TEdit;
    lblModuleOffset: TLabel;
    edtModuleOffset: TEdit;
    lblFunction: TLabel;
    edtFunction: TEdit;
    lblFuncOffset: TLabel;
    edtFuncOffset: TEdit;
    lblDisasm: TLabel;
    mmoDisasm: TMemo;
    pnlBottom: TPanel;
    btnCopyAob: TButton;
    btnCopyAA: TButton;
    btnOpenMemView: TButton;
    btnClose: TButton;
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure btnValidateClick(Sender: TObject);
    procedure btnGenerateClick(Sender: TObject);
    procedure btnCopyAobClick(Sender: TObject);
    procedure btnCopyAAClick(Sender: TObject);
    procedure btnOpenMemViewClick(Sender: TObject);
    procedure btnCloseClick(Sender: TObject);
  private
    lastFoundAddress: UInt64;
    function CleanAobString(const s: string): string;
  public
    procedure SetTargetAddress(addr: UInt64);
  end;

var
  frmAobValidator: TfrmAobValidator;

implementation

{$R *.lfm}

uses
  MemoryBrowserFormUnit;

procedure TfrmAobValidator.FormCreate(Sender: TObject);
begin
  lastFoundAddress := 0;
  pnlStatusBadge.Color := $282828;
  lblStatus.Font.Color := $AAAAAA;
  lblStatus.Caption := 'Aguardando validação...';
end;

procedure TfrmAobValidator.FormShow(Sender: TObject);
begin
  if (edtAob.Text = '') and (lastFoundAddress <> 0) then
    edtAddress.Text := '0x' + IntToHex(lastFoundAddress, 8);
  if edtAob.CanFocus then
    edtAob.SetFocus;
end;

procedure TfrmAobValidator.SetTargetAddress(addr: UInt64);
begin
  lastFoundAddress := addr;
  edtAddress.Text := '0x' + IntToHex(addr, 8);
end;

function TfrmAobValidator.CleanAobString(const s: string): string;
var
  t: string;
  p1, p2: integer;
begin
  t := Trim(s);
  // Se o usuário colou aobscanmodule(name, module, 48 89 ...)
  p1 := Pos('(', t);
  p2 := Pos(')', t);
  if (p1 > 0) and (p2 > p1) then
  begin
    t := Copy(t, p1 + 1, p2 - p1 - 1);
    // Pega o último argumento (onde fica a AOB)
    while Pos(',', t) > 0 do
      Delete(t, 1, Pos(',', t));
    t := Trim(t);
  end;
  Result := t;
end;

procedure TfrmAobValidator.btnValidateClick(Sender: TObject);
var
  pattern: string;
  modFilter: string;
  resData: TOnyxAobMatchResult;
  rc: integer;
  symName: string;
begin
  pattern := CleanAobString(edtAob.Text);
  if pattern = '' then
  begin
    MessageDlg('Aviso', 'Insira uma assinatura AOB para validar.', mtWarning, [mbOK], 0);
    Exit;
  end;

  modFilter := Trim(edtModule.Text);
  FillChar(resData, SizeOf(resData), 0);

  rc := OnyxValidateAOBPlugin(processid, PAnsiChar(AnsiString(pattern)), PAnsiChar(AnsiString(modFilter)), @resData);

  if (rc = 0) and (resData.match_count > 0) then
  begin
    lastFoundAddress := resData.address;
    edtAddress.Text := '0x' + IntToHex(resData.address, 12);

    if resData.module_name[0] <> #0 then
      edtModuleOffset.Text := Format('%s + 0x%X', [resData.module_name, resData.module_offset])
    else
      edtModuleOffset.Text := 'Memória Dinâmica / Heap';

    symName := string(resData.function_name);
    if (symName = '') or (Pos('sub_', symName) = 1) then
    begin
      // Tenta fallback com o symbolhandler interno do CE
      symName := symhandler.getNameFromAddress(resData.address);
    end;
    edtFunction.Text := symName;

    if resData.function_offset >= 0 then
      edtFuncOffset.Text := Format('+ 0x%X bytes do início', [resData.function_offset])
    else
      edtFuncOffset.Text := 'Início da função';

    mmoDisasm.Lines.Text := string(resData.disasm_preview);

    if resData.is_unique = 1 then
    begin
      pnlStatusBadge.Color := $25382E;
      lblStatus.Font.Color := $00E676;
      lblStatus.Caption := 'ASSINATURA ÚNICA (1 Match no Processo)';
    end
    else
    begin
      pnlStatusBadge.Color := $383520;
      lblStatus.Font.Color := $00E5FF;
      lblStatus.Caption := Format('MÚLTIPLAS OCORRÊNCIAS (%d Matches)', [resData.match_count]);
    end;
  end
  else
  begin
    lastFoundAddress := 0;
    pnlStatusBadge.Color := $382020;
    lblStatus.Font.Color := $5050FF;
    lblStatus.Caption := 'NENHUMA OCORRÊNCIA ENCONTRADA (0 Matches)';
    edtAddress.Text := '-';
    edtModuleOffset.Text := '-';
    edtFunction.Text := '-';
    edtFuncOffset.Text := '-';
    mmoDisasm.Lines.Clear;
  end;
end;

procedure TfrmAobValidator.btnGenerateClick(Sender: TObject);
var
  inputStr: string;
  targetAddr: UInt64;
  buf: array[0..511] of AnsiChar;
  rc: integer;
  genPat: string;
begin
  inputStr := Trim(edtAddress.Text);
  if (inputStr = '') or (inputStr = '-') then
    inputStr := Trim(edtAob.Text);

  if inputStr = '' then
  begin
    MessageDlg('Aviso', 'Informe um endereço ou símbolo no campo Endereço/AOB.', mtWarning, [mbOK], 0);
    Exit;
  end;

  targetAddr := symhandler.getAddressFromName(inputStr);
  if targetAddr = 0 then
  begin
    MessageDlg('Erro', 'Não foi possível resolver o endereço: ' + inputStr, mtError, [mbOK], 0);
    Exit;
  end;

  FillChar(buf, SizeOf(buf), 0);
  rc := OnyxGenerateAOBPlugin(processid, targetAddr, 64, @buf[0], SizeOf(buf));
  if rc = 0 then
  begin
    genPat := string(buf);
    edtAob.Text := genPat;
    Clipboard.AsText := genPat;
    btnValidateClick(Self);
    ShowMessage('AOB única gerada com sucesso e copiada para a Área de Transferência!');
  end
  else
  begin
    MessageDlg('Erro', 'Falha ao gerar assinatura para o endereço selecionado.', mtError, [mbOK], 0);
  end;
end;

procedure TfrmAobValidator.btnCopyAobClick(Sender: TObject);
begin
  if edtAob.Text <> '' then
  begin
    Clipboard.AsText := edtAob.Text;
    ShowMessage('AOB copiada para a Área de Transferência!');
  end;
end;

procedure TfrmAobValidator.btnCopyAAClick(Sender: TObject);
var
  modName: string;
  aaScript: string;
begin
  if edtAob.Text = '' then Exit;
  modName := Trim(edtModule.Text);
  if modName = '' then
    modName := 'process.exe';

  aaScript := Format(
    '// Assinatura gerada pelo Onyx SigMaker'#13#10 +
    '[ENABLE]'#13#10 +
    'aobscanmodule(INJECT, %s, %s)'#13#10 +
    'alloc(newmem, $1000, INJECT)'#13#10 +
    'label(returnhere)'#13#10#13#10 +
    'newmem:'#13#10 +
    '  // Seu código injetado aqui'#13#10 +
    '  jmp returnhere'#13#10#13#10 +
    'INJECT:'#13#10 +
    '  jmp newmem'#13#10 +
    'returnhere:'#13#10#13#10 +
    '[DISABLE]'#13#10 +
    'dealloc(newmem)',
    [modName, edtAob.Text]
  );

  Clipboard.AsText := aaScript;
  ShowMessage('Template AutoAssembler copiado!');
end;

procedure TfrmAobValidator.btnOpenMemViewClick(Sender: TObject);
begin
  if lastFoundAddress <> 0 then
  begin
    MemoryBrowser.disassemblerview.SelectedAddress := lastFoundAddress;
    MemoryBrowser.Show;
  end
  else
    MessageDlg('Aviso', 'Nenhum endereço válido selecionado.', mtWarning, [mbOK], 0);
end;

procedure TfrmAobValidator.btnCloseClick(Sender: TObject);
begin
  Close;
end;

end.
