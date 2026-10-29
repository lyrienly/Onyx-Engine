unit frmNetworkDataCompressionUnit;

{$mode delphi}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ComCtrls, betterControls;

type

  { TfrmNetworkDataCompression }

  TfrmNetworkDataCompression = class(TForm)
    cbLZ4: TCheckBox;
    Label1: TLabel;
    lblMaxCompression: TLabel;
    lblNone: TLabel;
    tbCompressionLevel: TTrackBar;
    procedure cbLZ4Change(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure tbCompressionLevelChange(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  frmNetworkDataCompression: TfrmNetworkDataCompression;

implementation

{$R *.lfm}

{ TfrmNetworkDataCompression }

uses networkConfig, lz4decode;

procedure TfrmNetworkDataCompression.cbLZ4Change(Sender: TObject);
begin
  tbCompressionLevel.Enabled := not cbLZ4.Checked;
  if cbLZ4.Checked then
    networkcompression := COMPRESSION_LZ4
  else
    networkcompression := tbCompressionLevel.Position;
end;

procedure TfrmNetworkDataCompression.tbCompressionLevelChange(Sender: TObject);
begin
  if not cbLZ4.Checked then
    networkcompression := tbCompressionLevel.Position;
end;

procedure TfrmNetworkDataCompression.FormShow(Sender: TObject);
begin
  cbLZ4.Checked := networkcompression = COMPRESSION_LZ4;
  tbCompressionLevel.Enabled := not cbLZ4.Checked;
  if not cbLZ4.Checked then
    tbCompressionLevel.Position := networkcompression;

  width:=(screen.PixelsPerInch div 96)*320;
  height:=(screen.PixelsPerInch div 96)*220;
end;

end.

