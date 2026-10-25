if getTranslationFolder()~='' then
  loadPOFile(getTranslationFolder()..'autosave.po')
end

require("lfs")

autosave={}

local AutoSaveSettings=getSettings('Auto Save')
local AutoSaveVersion=1

autosave.getPath=function()
  local path=AutoSaveSettings['SavePath']
  if (path==nil) or (path=='') then

    path=os.getenv("LOCALAPPDATA")
    if (path==nil) or (path=='') then
      path=getCheatEngineDir()
    end
  end

  if string.sub(path,#path)~='\\' then
    path=path..'\\'
  end

  return path
end

function autosave.saveState()

  local pid=AutoSaveSettings['ProcessID']
  if pid and pid~='' then
    pid=tonumber(pid)
    if pid~=getCheatEngineProcessID() then

      if getProcessList()[pid]==nil then

        messageDialog(translate('Another instance of Cheat Engine has crashed and it created an autosave.  Autosave disabled until you go to settings and click ok'), mtWarning, mbOk)
        return false
      end
    end
  end

  AutoSaveSettings['ProcessID']=getCheatEngineProcessID()
  local path, err=autosave.getPath()
  if path==nil then
    messageDialog(translate('Failure to obtain a location to save the autosave data'), mtError, mbOk)
    return false
  end

  path=path..'Cheat Engine AutoSave';
  lfs.mkdir(path)

  local r,err=saveTable(path..[[\table.ct]])
  if (r==nil) or (r==false) then
    if err==nil then
      err=translate('Unknown Reason')
    end
    messageDialog(translate('Failure to autosave table : ')..err, mtError, mbOk)
    return false
  end

  local cestate,err=createFileStream(path..[[\state.dat]], fmCreate)
  if cestate==nil then
    messageDialog(translate('Failure to autosave state : ')..err, mtError, mbOk)
    return false
  end

  local i
  local luaforms={}
  local aaforms={}
  for i=getFormCount()-1,0,-1 do
    local f=getForm(i)

    if (f.ClassName=='TfrmLuaEngine') and f.Visible then
      local e={}
      e.history=f.mOutput.Lines.Text
      e.script=f.mScript.Lines.Text
      e.filename=f.savedialog1.FileName
      e.Left=f.Left
      e.Top=f.Top
      e.Width=f.Width
      e.Height=f.Height

      if f.MiView.Visible then
        local temp=luaforms[1]
        luaforms[1]=e
        temp=e
      end

      if e then
        table.insert(luaforms,e)
      end

    elseif (f.ClassName=='TfrmAutoInject') and f.Visible then
      if (f.IsEditing==false) and (f.ScriptMode~='smLua') then

        e={}
        e.Filename=f.savedialog1.FileName
        e.Left=f.Left
        e.Top=f.Top
        e.Width=f.Width
        e.Height=f.Height
        e.ScriptCount=f.TabCount
        e.Scripts={}
        local j
        for j=0,f.TabCount-1 do
          e.Scripts[j+1]=f.TabScript[j]
        end

        table.insert(aaforms,e)
      end
    end
  end

  cestate.writeDword(AutoSaveVersion)
  cestate.writeDword(#luaforms)
  for i=1,#luaforms do
    cestate.writeAnsiString(luaforms[i].history)
    cestate.writeAnsiString(luaforms[i].script)
    cestate.writeAnsiString(luaforms[i].filename)
    cestate.writeDword(luaforms[i].Left)
    cestate.writeDword(luaforms[i].Top)
    cestate.writeDword(luaforms[i].Width)
    cestate.writeDword(luaforms[i].Height)
  end

  cestate.writeDword(#aaforms)
  for i=1,#aaforms do
    cestate.writeDword(aaforms[i].ScriptCount)
    for j=1,#aaforms[i].Scripts do
      cestate.writeAnsiString(aaforms[i].Scripts[j])
    end
    cestate.writeAnsiString(aaforms[i].Filename)
    cestate.writeDword(aaforms[i].Left)
    cestate.writeDword(aaforms[i].Top)
    cestate.writeDword(aaforms[i].Width)
    cestate.writeDword(aaforms[i].Height)
  end

  cestate.destroy()

  return true
end

function autosave.loadState()

  AutoSaveSettings['ProcessID']=getCheatEngineProcessID()
  local path=autosave.getPath()..'Cheat Engine AutoSave\\';

  r,err=loadTable(path..'table.ct')
  if (r==nil) or (r==false) then
    if err==nil then
      err=translate('Unknown Reason')
    end
    messageDialog(string.format(translate('Failure to load autosave at %s  . Error: %s'), path, err), mtError, mbOk)
    return false
  end

  local cestate,err=createFileStream(path..[[state.dat]], fmOpenRead)
  if cestate then
    local i
    local version=cestate.readDword()
    if version~=AutoSaveVersion then

      messageDialog(translate('The saved state belongs to a different autosave version that is not currently implemented'), mtError, mbOk)
      return false
    end
    local luaformcount=cestate.readDword()

    for i=1,luaformcount do
      local f=createLuaEngine()
      f.mOutput.Lines.Text=cestate.readAnsiString()
      f.mScript.Lines.Text=cestate.readAnsiString()
      f.SaveDialog1.FileName=cestate.readAnsiString()
      f.Left=cestate.readDword()
      f.Top=cestate.readDword()
      f.Width=cestate.readDword()
      f.Height=cestate.readDword()

      f.show()
    end

    local aacount=cestate.readDword()

    for i=1,aacount do
      f=createAutoAssemblerForm()

      local count=cestate.readDword()

      if count>0 then
        f.TabCount=count
        local j
        for j=0,count-1 do
          f.TabScript[j]=cestate.readAnsiString()
        end
      end

      f.SaveDialog1.FileName=cestate.readAnsiString()
      f.Left=cestate.readDword()
      f.Top=cestate.readDword()
      f.Width=cestate.readDword()
      f.Height=cestate.readDword()

      f.show()
    end

    cestate.destroy()
    return true
  else

    return false
  end

end

autosave.applySettings=function()
  local interval=tonumber(AutoSaveSettings['Interval'])

  if autosave.Timer then

    autosave.Timer.destroy()
    autosave.Timer=nil
  end

  if interval and (interval>0) then

    autosave.Timer=createTimer(nil)
    autosave.Timer.Interval=interval*1000
    autosave.Timer.OnTimer=function(t)

      if autosave.saveState()~=true then

        autosave.Timer.destroy()
        autosave.Timer=nil
      end
    end
    autosave.Enabled=true
  else

  end
end

local oldMainFormOnClose=MainForm.OnClose
MainForm.OnClose=function(s, ca)
  AutoSaveSettings['ProcessID']=nil
  if oldMainFormOnClose then
    return oldMainFormOnClose(s, ca)
  else
    return ca
  end
end

local sf=getSettingsForm()
autosave.settingsTab=sf.SettingsPageControl.addTab()

autosave.settingsEdtInterval=createEdit(autosave.settingsTab)
autosave.settingsEdtInterval.Text=AutoSaveSettings['Interval']
autosave.settingsEdtInterval.Align='alTop'

autosave.settingsLblInterval=createLabel(autosave.settingsTab)
autosave.settingsLblInterval.Caption=translate('Auto Save Interval (In seconds. 0 is disabled)')
autosave.settingsLblInterval.Align='alTop'

local insertNode=sf.SettingsTreeView.Items[3]
local node=sf.SettingsTreeView.Items.insert(insertNode, translate("Auto Save"))
node.data=userDataToInteger(autosave.settingsTab)

local originalSettingsCloseEvent=sf.OnClose
sf.OnClose=function(s, closeAction)

  local r=closeAction
  if originalSettingsCloseEvent then
    r=originalSettingsCloseEvent(s, closeAction)
  end

  if s.ModalResult==mrOK then

    AutoSaveSettings['Interval']=autosave.settingsEdtInterval.Text

    autosave.applySettings()
  end
  return r
end

pid=AutoSaveSettings['ProcessID']
if (pid) and (pid ~= '') and (getProcessList()[tonumber(pid)]==nil) then

  AutoSaveSettings['ProcessID']=nil

  if messageDialog(translate('Cheat Engine did not properly close last time. Do you wish to restore your work?'), mtInformation, mbYes, mbNo)==mrYes then
    autosave.loadState()
  end
end

autosave.applySettings()

