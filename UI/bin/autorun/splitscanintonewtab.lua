
function splitScanIntoNewTab()
  if MainForm.miAddTab.enabled then
    local filename=getCurrentMemscan().ScanresultFolder..'.splitscan.savestate'

    saveMemoryScan_internal(filename)

    MainForm.miAddTab.doClick()

    loadMemoryScan_internal(filename)
  end
end

local mi=createMenuItem(MainForm.Menu)
mi.Caption=translate('Split scan into new tab')
mi.ShortCut=textToShortCut('Ctrl+Alt+T')
mi.OnClick=splitScanIntoNewTab
mi.ImageIndex=MainForm.miAddTab.ImageIndex
MainForm.Menu.Items[0].Insert(MainForm.miAddTab.MenuIndex+1,mi)

