unit lz4decode;

{$mode objfpc}{$H+}

// Decoder de bloco LZ4 (formato "LZ4 block", sem frame/magic).
// Usado pelo cliente de rede para descomprimir CMD_READPROCESSMEMORY quando
// o servidor responde com COMPRESSION_LZ4.

interface

uses
  SysUtils;

const
  COMPRESSION_LZ4 = 10;

{ Descomprime src (srcSize bytes) em dst (dstCapacity bytes).
  Retorna o numero de bytes escritos, ou -1 em caso de stream invalido. }
function LZ4_Decompress(src: PByte; srcSize: PtrInt; dst: PByte; dstCapacity: PtrInt): PtrInt;

implementation

function LZ4_Decompress(src: PByte; srcSize: PtrInt; dst: PByte; dstCapacity: PtrInt): PtrInt;
var
  ip, iend: PtrInt;
  op, oend: PtrInt;
  token, litLen, matchLen, offset: PtrInt;
  match: PtrInt;
begin
  ip := 0;
  op := 0;
  iend := srcSize;
  oend := dstCapacity;

  while ip < iend do
  begin
    token := src[ip];
    Inc(ip);

    litLen := token shr 4;
    if litLen = 15 then
    begin
      repeat
        if ip >= iend then Exit(-1);
        litLen := litLen + src[ip];
        Inc(ip);
      until src[ip - 1] <> 255;
    end;

    if litLen > 0 then
    begin
      if (ip + litLen > iend) or (op + litLen > oend) then Exit(-1);
      Move(src[ip], dst[op], litLen);
      Inc(ip, litLen);
      Inc(op, litLen);
    end;

    // Ultima sequencia do bloco: nao ha match apos os literais.
    if ip >= iend then
      Break;

    if ip + 2 > iend then Exit(-1);
    offset := src[ip] or (src[ip + 1] shl 8);
    Inc(ip, 2);

    if (offset = 0) or (offset > op) then Exit(-1);

    matchLen := token and 15;
    if matchLen = 15 then
    begin
      repeat
        if ip >= iend then Exit(-1);
        matchLen := matchLen + src[ip];
        Inc(ip);
      until src[ip - 1] <> 255;
    end;
    Inc(matchLen, 4); // MINMATCH

    if op + matchLen > oend then Exit(-1);

    match := op - offset;
    while matchLen > 0 do
    begin
      dst[op] := dst[match];
      Inc(op);
      Inc(match);
      Dec(matchLen);
    end;
  end;

  Result := op;
end;

end.
