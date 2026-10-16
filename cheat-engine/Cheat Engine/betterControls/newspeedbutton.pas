unit newSpeedButton; //for some reason parentfont does not work

{$mode objfpc}{$H+}

interface

uses
  jwawindows, windows, Classes, SysUtils, Controls, StdCtrls, Buttons;

type
  TNewSpeedButton=class(TSpeedButton)
  private
    darkmode: boolean;
  protected
    procedure PaintBackground(var PaintRect: TRect); override;
    procedure SetParent(NewParent: TWinControl); override;
  public
  end;


implementation

uses betterControls, themes, Graphics;

procedure TNewSpeedButton.PaintBackground(var PaintRect: TRect);
begin
  if ShouldAppsUseDarkMode and darkmode then
  begin
    case FState of
      bsUp:
      begin
        Canvas.Brush.Color := Color;
        Canvas.Pen.Color := Color;
      end;
      bsDisabled:
      begin
        Canvas.Brush.Color := Color;
        Canvas.Pen.Color := Color;
      end;
      bsHot:
      begin
        Canvas.Brush.Color := incColor(Color, 18);
        Canvas.Pen.Color := $4E4E4E;
      end;
      bsDown:
      begin
        Canvas.Brush.Color := incColor(Color, 32);
        Canvas.Pen.Color := $00B478;
      end;
    end;

    Canvas.RoundRect(PaintRect.Left, PaintRect.Top, PaintRect.Right, PaintRect.Bottom, 4, 4);
  end
  else
    inherited PaintBackground(paintrect);
end;

procedure TNewSpeedButton.SetParent(NewParent: TWinControl);
begin
  inherited SetParent(newparent);

  if (NewParent<>nil) and ShouldAppsUseDarkMode then
  begin
    darkmode:=true;
    color:=ColorSet.TextBackground;
  end;
end;

end.

