unit OnyxInstance;

{$mode delphi}

// Nome de classe de janela e de mutex de instancia unica gerados em runtime.
// Nenhum dos dois fica como constante estatica no binario:
//  - a classe de janela recebe um token aleatorio por processo;
//  - o mutex usa um hash do caminho do executavel, igual para todas as
//    instancias da mesma instalacao (necessario para detectar a segunda).

interface

uses
  SysUtils
  {$ifdef windows}, Windows{$endif};

{ Nome de classe usado pelo TMainForm.CreateParams. Gerado uma vez por processo. }
function OnyxWindowClassName: string;

{ Cria o mutex de instancia unica. Retorna False quando ja existe outra instancia
  da mesma instalacao em execucao. }
function OnyxAcquireSingleInstance: boolean;

procedure OnyxReleaseSingleInstance;

implementation

var
  FWindowClassName: string;
  FSeed: cardinal;
  {$ifdef windows}
  FMutex: THandle = 0;
  {$endif}

function NextRandom: cardinal;
begin
  // xorshift32: nao mexe no RandSeed global do aplicativo
  FSeed := FSeed xor (FSeed shl 13);
  FSeed := FSeed xor (FSeed shr 17);
  FSeed := FSeed xor (FSeed shl 5);
  Result := FSeed;
end;

function RandomToken(len: integer): string;
const
  alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
var
  i: integer;
begin
  Result := '';
  for i := 1 to len do
    Result := Result + alphabet[(NextRandom mod Length(alphabet)) + 1];
end;

function Fnv1a32(const value: string): cardinal;
var
  i: integer;
begin
  Result := 2166136261;
  for i := 1 to Length(value) do
  begin
    Result := Result xor Ord(value[i]);
    Result := Result * 16777619;
  end;
end;

function OnyxWindowClassName: string;
begin
  if FWindowClassName = '' then
    FWindowClassName := 'W' + RandomToken(11);
  Result := FWindowClassName;
end;

{$ifdef windows}
function InstanceMutexName: string;
var
  digest: cardinal;
begin
  // Mesma instalacao => mesmo caminho => mesmo nome. Nao e um literal no binario.
  digest := Fnv1a32(LowerCase(ExpandFileName(ParamStr(0))));
  Result := 'Local\' + IntToHex(digest, 8) + '-' + IntToHex(digest xor $9E3779B9, 8);
end;
{$endif}

function OnyxAcquireSingleInstance: boolean;
{$ifdef windows}
var
  name: WideString;
{$endif}
begin
  Result := True;

  {$ifdef windows}
  name := WideString(InstanceMutexName);
  FMutex := CreateMutexW(nil, False, PWideChar(name));
  if FMutex = 0 then
    Exit(True); // sem mutex, nao bloqueia a inicializacao

  if GetLastError = ERROR_ALREADY_EXISTS then
    Result := False;
  {$endif}
end;

procedure OnyxReleaseSingleInstance;
begin
  {$ifdef windows}
  if FMutex <> 0 then
  begin
    CloseHandle(FMutex);
    FMutex := 0;
  end;
  {$endif}
end;

initialization
  {$ifdef windows}
  FSeed := cardinal(GetTickCount64) xor (cardinal(GetCurrentThreadId) shl 16) xor $9E3779B9;
  {$else}
  FSeed := cardinal(Trunc(Now * 86400000)) xor $9E3779B9;
  {$endif}
  if FSeed = 0 then
    FSeed := $1234567;

finalization
  OnyxReleaseSingleInstance;

end.
