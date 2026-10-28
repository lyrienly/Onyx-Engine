if getTranslationFolder()~='' then
  loadPOFile(getTranslationFolder()..'SaveSessions.po')
end

if cheatEngineIs64Bit() then
  if string.find(package.cpath, 'clibs64')==nil then
    package.cpath=package.cpath..[[;.\clibs64\?.dll]]
  end
else
  if string.find(package.cpath, 'clibs32')==nil then
    package.cpath=package.cpath..[[;.\clibs32\?.dll]]
  end
end

require("lfs")

function loadMemoryScan_internal(filename)

	local ms=getCurrentMemscan()
	local mf=getMainForm()

	local input,err=createFileStream(filename,fmOpenRead or fmShareDenyNone)
  if input==nil then
    MessageDialog(err, mtError,mbOK)
    return
  end

	local scanvalue=input.readAnsiString()
  local originalFromAddress=input.readAnsiString()
  local originalToAddress=input.readAnsiString()
	local scantype=input.readByte()
	local vartype=input.readByte()
  local formhex=input.readByte()==1
  local memscanhex=input.readByte()==1

	local savedscancount=input.readByte()

	local savedscans={}
	for i=1,savedscancount do
		savedscans[i]=input.readAnsiString()
	end

	if ms.LastScanType~="stNewScan" then
    mf.btnNewScan.doClick()
  end

	mf.scanvalue.Text='123'
	mf.vartype.itemindex=vartype
	mf.scantype.itemindex=0

	mf.cbWritable.setState(cbGrayed)
	mf.cbExecutable.setState(cbGrayed)
	mf.cbCopyOnWrite.setState(cbGrayed)

  mf.FromAddress.Text=string.format("%x", getAddress("kernel32.dll"))
  mf.ToAddress.Text=string.format("%x", getAddress("kernel32.dll")+1)

  local oldOnScanDone=ms.OnScanDone
  local oldOnInitialScanDone=ms.OnInitialScanDone
  ms.OnScanDone=function(m)
    ms.OnScanDone=oldOnScanDone
    ms.OnInitialScanDone=oldOnInitialScanDone

    for i=1, savedscancount do
      ms.saveCurrentResults(savedscans[i])
    end

    local fl=ms.FoundList;

    if ms.OnScanStart then
      ms.OnScanStart()
    end

    fl.deinitialize()

    local filecount=input.readByte()

    for i=1, filecount do

      local name=input.readAnsiString()

      local filesize=input.readQword()

      local trycount=0
      local output,err
      while trycount<20 do
        output,err=createFileStream(getCurrentMemscan().ScanresultFolder..name, fmCreate)
        if not output then
          trycount=trycount+1
          sleep(100)
        else
          break
        end
      end

      if not output then
        MessageDialog(err, mtError,mbOK)
        input.destroy()
        return
      end

      if filesize>0  then
        output.CopyFrom(input, filesize)
      end
      output.destroy()
    end

    input.destroy()

    if oldOnInitialScanDone then
      oldOnInitialScanDone(m)
    end

    if oldOnScanDone then
      oldOnScanDone(m)
    end

    ms.Hexadecimal=memscanhex
    fl.initialize()

    mf.scanvalue.Text=scanvalue
    mf.vartype.itemindex=vartype
    mf.scantype.itemindex=scantype

    mf.FromAddress.Text=originalFromAddress
    mf.ToAddress.Text=originalToAddress
    mf.foundcountlabel.Caption=fl.Count

    mf.cbHexadecimal.Checked=formhex

  end
  ms.OnInitialScanDone=nil

  mf.btnNewScan.doClick()

  ms.waitTillDone()
end

function loadMemoryScan()

	if getOpenedProcessID()==0 then
    messageDialog(translate("Open a process first"), mtError, mbOK)
    return
	end

	local dialog=createOpenDialog()
	dialog.DefaultExt=".CS"
	dialog.Filter=translate("Cheat Engine Scan files").." (*.CS)|*.CS"
	dialog.FilterIndex=1
  dialog.Options="[ofEnableSizing]"

	if dialog.execute()==false then return end

  loadMemoryScan_internal(dialog.Filename)
	dialog.destroy()
end

function saveMemoryScan_internal(filename)
  local i,j

  local output,err=createFileStream(filename,fmCreate)
  if output==nil then
    MessageDialog(err, mtError,mbOK)
    return
  end

  local mf=getMainForm()

  output.writeAnsiString(mf.scanvalue.Text)
  output.writeAnsiString(mf.fromAddress.Text)
  output.writeAnsiString(mf.toAddress.Text)
  output.writeByte(mf.scantype.ItemIndex)
  output.writeByte(mf.VarType.ItemIndex)
  output.writeByte(mf.cbHexadecimal.Checked and 1 or 0)
  output.writeByte(getCurrentMemscan().Hexadecimal and 1 or 0)

  local files={}

  local olddir=lfs.currentdir()
  lfs.chdir(getCurrentMemscan().ScanresultFolder)

  for file in lfs.dir('.') do
    if string.sub(file,1,1)~='.' then
      local f={}
      f.name=file
      f.size=lfs.attributes(file).size

      if extractFileExt(file)~='.lock' then
        table.insert(files, f)
      end
    end
  end

  local savedscans={}
  for i=1,#files do
    local ext=files[i].name:match("%.([^%.]+)$")

    if (string.upper(ext)~='FIRST') and
       (string.upper(ext)~='TMP')   and
       (string.upper(ext)~='UNDO')  then

      local found=false

      for j=1,#savedscans do
        if savedscans[j]==ext then
          found=true
          break
        end
      end

      if found==false then
        table.insert(savedscans, found)
      end
    end
  end

  output.writeByte(#savedscans)

  for i=1,#savedscans do
    output.writeAnsiString(savedscans[i])
  end

  output.writeByte(#files)
  for i=1, #files do

    output.writeAnsiString(files[i].name)

    local input,err=createFileStream(getCurrentMemscan().ScanresultFolder..files[i].name,fmOpenRead | fmShareDenyNone)

    if input==nil then
      MessageDialog(err, mtError,mbOK)
      output.destroy()
      return
    else

      output.writeQword(input.Size)
      output.CopyFrom(input,input.Size)
      input.destroy()
    end
  end
  lfs.chdir(olddir)

  output.destroy()

end

function saveMemoryScan()
	if getOpenedProcessID()==0 then
    messageDialog(translate("Open a process first"), mtError, mbOK)
    return
	end

  local dialog=createSaveDialog()
  dialog.DefaultExt=".CS"
  dialog.Filter=translate("Cheat Engine Scan files").." (*.CS)|*.CS"
  dialog.FilterIndex=1
  dialog.Options="[ofEnableSizing,ofOVerwritePrompt]"

  if dialog.execute()==false then return nil end

  saveMemoryScan_internal(dialog.Filename)
  dialog.destroy()
end

local mf=getMainForm()

SaveScanSession={}

SaveScanSession.miSaveScanSession=createMenuItem(mf.Menu)
SaveScanSession.miSaveScanSession.caption=translate('Save scan session')

SaveScanSession.miSaveScanSession.Shortcut='Ctrl+Alt+Shift+S'
SaveScanSession.miSaveScanSession.OnClick=saveMemoryScan
SaveScanSession.miSaveScanSession.Enabled=false

local s=createPicture()
s.LoadFromFile(getCheatEngineDir()..[[autorun\images\export128x128.png]])
local ii=MainForm.mfImageList.add(s.Bitmap)
SaveScanSession.miSaveScanSession.ImageIndex=ii
s.destroy()

mf.Menu.Items[0].insert(9, SaveScanSession.miSaveScanSession)

SaveScanSession.miLoadScanSession=createMenuItem(mf.Menu)
SaveScanSession.miLoadScanSession.caption=translate('Load scan session')

SaveScanSession.miLoadScanSession.Shortcut='Ctrl+Alt+Shift+O'
SaveScanSession.miLoadScanSession.OnClick=loadMemoryScan
SaveScanSession.miLoadScanSession.Enabled=false

local s=createPicture()
s.LoadFromFile(getCheatEngineDir()..[[autorun\images\import128x128.png]])
local ii=MainForm.mfImageList.add(s.Bitmap)
SaveScanSession.miLoadScanSession.ImageIndex=ii
s.destroy()

mf.Menu.Items[0].insert(10, SaveScanSession.miLoadScanSession)

local mi=createMenuItem(mf.Menu)
mi.caption='-'
mf.Menu.Items[0].insert(11, mi)

mi.Visible=MainForm.miSignTable.Visible

local oldFileMenuClick=mf.Menu.Items[0].OnClick

mf.Menu.Items[0].OnClick=function(sender)
  if (oldFileMenuClick) then
    oldFileMenuClick(sender)
  end

  local enable=getCurrentMemscan().lastScanWasRegionScan==false

  SaveScanSession.miSaveScanSession.Enabled=enable
  SaveScanSession.miLoadScanSession.Enabled=true
end

