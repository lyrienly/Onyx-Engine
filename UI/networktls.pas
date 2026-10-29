unit networktls;

{$mode delphi}

// Cliente TLS para o ceserver usando os bindings OpenSSL do FPC.
// Verificacao por pinning: o SHA-256 do certificado apresentado e comparado
// com o valor esperado (hex). Sem pin salvo, o chamador pode aceitar (TOFU)
// e persistir o valor retornado em peerPin.

interface

uses
  SysUtils, Sockets, ctypes, openssl;

function TLSClientConnect(asocket: TSocket; const expectedPin: string;
  out peerPin: string; out err: string): Boolean;
procedure TLSClientDisconnect;
function TLSSend(asocket: TSocket; buffer: Pointer; size: Integer): Integer;
function TLSReceive(asocket: TSocket; buffer: Pointer; size: Integer): Integer;
function TLSActive: Boolean;

implementation

var
  tlsCtx: PSSL_CTX = nil;
  tlsSsl: PSSL = nil;
  tlsSocket: TSocket = -1;

function TLSActive: Boolean;
begin
  Result := tlsSsl <> nil;
end;

function PinOf(cert: PX509): string;
var
  md: string;
  len: cInt;
  i: Integer;
begin
  Result := '';
  if cert = nil then
    Exit;

  SetLength(md, 64);
  len := 0;
  if X509Digest(cert, PEVP_MD(EVP_sha256()), md, len) = 1 then
    for i := 1 to len do
      Result := Result + LowerCase(IntToHex(Ord(md[i]), 2));
end;

function TLSClientConnect(asocket: TSocket; const expectedPin: string;
  out peerPin: string; out err: string): Boolean;
var
  cert: PX509;
begin
  Result := False;
  err := '';
  peerPin := '';

  if tlsSsl <> nil then
    TLSClientDisconnect;

  if not InitSSLInterface then
  begin
    err := 'OpenSSL initialization failed';
    Exit;
  end;

  tlsCtx := SslCtxNew(SslTLSMethod());
  if tlsCtx = nil then
  begin
    err := 'SSL_CTX_new failed';
    Exit;
  end;

  // Self-signed + pinning: a verificacao da cadeia e feita pelo fingerprint.
  SslCtxSetVerify(tlsCtx, SSL_VERIFY_NONE, nil);

  tlsSsl := SslNew(tlsCtx);
  if tlsSsl = nil then
  begin
    err := 'SSL_new failed';
    SslCtxFree(tlsCtx);
    tlsCtx := nil;
    Exit;
  end;

  if SslSetFd(tlsSsl, cInt(asocket)) <> 1 then
  begin
    err := 'SSL_set_fd failed';
    SslFree(tlsSsl);
    tlsSsl := nil;
    SslCtxFree(tlsCtx);
    tlsCtx := nil;
    Exit;
  end;

  if SslConnect(tlsSsl) <= 0 then
  begin
    err := 'TLS handshake failed';
    SslFree(tlsSsl);
    tlsSsl := nil;
    SslCtxFree(tlsCtx);
    tlsCtx := nil;
    Exit;
  end;

  cert := SslGetPeerCertificate(tlsSsl);
  peerPin := PinOf(cert);
  if cert <> nil then
    X509Free(cert);

  if (expectedPin <> '') and (not SameText(expectedPin, peerPin)) then
  begin
    err := 'TLS fingerprint mismatch';
    SslShutdown(tlsSsl);
    SslFree(tlsSsl);
    tlsSsl := nil;
    SslCtxFree(tlsCtx);
    tlsCtx := nil;
    Exit;
  end;

  tlsSocket := asocket;
  Result := True;
end;

procedure TLSClientDisconnect;
begin
  if tlsSsl <> nil then
  begin
    SslShutdown(tlsSsl);
    SslFree(tlsSsl);
    tlsSsl := nil;
  end;

  if tlsCtx <> nil then
  begin
    SslCtxFree(tlsCtx);
    tlsCtx := nil;
  end;

  tlsSocket := -1;
end;

function TLSSend(asocket: TSocket; buffer: Pointer; size: Integer): Integer;
var
  written, e: cInt;
begin
  Result := 0;

  if (tlsSsl = nil) or (asocket <> tlsSocket) then
    Exit(-1);

  while Result < size do
  begin
    written := SslWrite(tlsSsl, PAnsiChar(buffer) + Result, size - Result);
    if written <= 0 then
    begin
      e := SslGetError(tlsSsl, written);
      if (e = SSL_ERROR_WANT_WRITE) or (e = SSL_ERROR_WANT_READ) then
        Continue;
      Exit(-1);
    end;
    Inc(Result, written);
  end;
end;

function TLSReceive(asocket: TSocket; buffer: Pointer; size: Integer): Integer;
var
  got, e: cInt;
begin
  Result := 0;

  if (tlsSsl = nil) or (asocket <> tlsSocket) then
    Exit(-1);

  while Result < size do
  begin
    got := SslRead(tlsSsl, PAnsiChar(buffer) + Result, size - Result);
    if got <= 0 then
    begin
      e := SslGetError(tlsSsl, got);
      if (e = SSL_ERROR_WANT_READ) or (e = SSL_ERROR_WANT_WRITE) then
        Continue;
      Exit(-1);
    end;
    Inc(Result, got);
  end;
end;

end.
