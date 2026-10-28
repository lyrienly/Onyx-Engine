
if getTranslationFolder()~='' then
  loadPOFile(getTranslationFolder()..'VersionCheck.po')
end

local vsettings=getSettings("VersionCheck")

local VersionCheckThread

function CheckVersion(automatic)

  if versionCheckThread==nil then
    versionCheckThread=createThread(function(t)
        local i=getInternet('CEVersionCheck')
        local r=i.getURL('https://cheatengine.org/latestversion.txt')

        if r then
          local sl=createStringlist()
          local newerVersion=false
          local latestVersionCompleteBuildNumber
          local latestVersionNumber
          local latestVersionString
          sl.Text=r

          if sl.Count<3 then
            t.synchronize(function()
              if automatic then
                messageDialog(translate('Unable to check version (Invalid content, not enough lines)'), mtError,mbOK)
              end
              versionCheckThread=nil
            end)
            sl.destroy()
            i.destroy()
            return
          end

          latestVersionCompleteBuildNumber=tonumber(sl[0])
          latestVersionNumber=tonumber(sl[1])
          latestVersionString=sl[2]

          sl.destroy()
          sl=nil

          if (latestVersionCompleteBuildNumber==nil) or (latestVersionNumber==nil) then
            t.synchronize(function()
              if automatic then
                messageDialog(translate('Unable to check version (Invalid content)'), mtError, mbOK)
              end
              versionCheckThread=nil
            end)
            i.destroy()
            return
          end

          local fv=getCheatEngineFileVersion()

          if fv then
            if latestVersionCompleteBuildNumber>fv then
              newerVersion=true
            end
          else

            if latestVersionNumber>getCEVersion() then
              newerVersion=true
            end
          end

          t.synchronize(function()
            if newerVersion then
              if messageDialog(string.format(translate('Cheat Engine %s is available at www.cheatengine.org. Go there now?'),latestVersionString), mtConfirmation, mbYes, mbNo)==mrYes then
                shellExecute('https://cheatengine.org/?versioncheck=1')
              else
                if automatic then
                  local NewInterval=(tonumber(vsettings.Value['CheckInterval']) or 1)*2
                  local r=inputQuery(string.format(translate('Update to %s'),latestVersionString),translate('In how many days should I notify you again?'), NewInterval)
                  NewInterval=tonumber(r)
                  if NewInterval then
                    vsettings.Value['CheckInterval']=NewInterval
                  else

                    vsettings.Value['CheckInterval']=(tonumber(vsettings.Value['CheckInterval']) or 1)*2
                  end
                end
              end
            else
              if not automatic then
                showMessage(string.format(translate('You are up to date. The latest version is %s'),latestVersionString))
              end
            end

            versionCheckThread=nil
          end)

          vsettings.Value['LastCheck']=os.time()
        else
          t.synchronize(function()
            if not automatic then
              messageDialog(translate("Unable to check version (Can't connect)"), mtError, mbOK)
            end
            versionCheckThread=nil
          end)
        end

        i.destroy()
    end)
  end

end

if vsettings then
  if vsettings.Value['CheckOnLaunch']=='1' then
    local LastCheck=tonumber(vsettings.Value['LastCheck']) or 0
    local CheckInterval=tonumber(vsettings.Value['CheckInterval']) or 1
    if (LastCheck+CheckInterval*60*60*24)<os.time() then
      CheckVersion(true)
    end
  end
end

local mi=createMenuItem(MainForm.MainMenu)
mi.Caption=translate('Check for new version')
mi.ImageIndex=15

mi.OnClick=function(mi) CheckVersion(false) end

MainForm.miHelp.insert(MainForm.miAbout.MenuIndex,mi)

local sf=getSettingsForm()

local cbCheckForUpdatesOnLaunch=createCheckBox(sf)
local lblInterval=createLabel(sf)
local edtInterval=createEdit(sf)
local parent=sf.cbShowUndo.Parent

cbCheckForUpdatesOnLaunch.Checked=vsettings.Value['CheckOnLaunch']=='1'
cbCheckForUpdatesOnLaunch.Caption=translate('Check for updates when Cheat Engine starts')..'.'
cbCheckForUpdatesOnLaunch.Parent=parent
cbCheckForUpdatesOnLaunch.AnchorSideTop.Control=edtInterval
cbCheckForUpdatesOnLaunch.AnchorSideTop.Side=asrCenter
cbCheckForUpdatesOnLaunch.AnchorSideLeft=sf.cbShowUndo.AnchorSideLeft

cbCheckForUpdatesOnLaunch.OnChange=function()
  lblInterval.Enabled=cbCheckForUpdatesOnLaunch.Checked
  edtInterval.Enabled=cbCheckForUpdatesOnLaunch.Checked
end

cbCheckForUpdatesOnLaunch.OnChange(cbCheckForUpdatesOnLaunch)

lblInterval.Caption=translate('Interval(days):')
lblInterval.Parent=parent
lblInterval.AnchorSideTop.Control=cbCheckForUpdatesOnLaunch
lblInterval.AnchorSideTop.Side=asrCenter
lblInterval.AnchorSideLeft.Control=cbCheckForUpdatesOnLaunch
lblInterval.AnchorSideLeft.Side=asrRight

if vsettings then
  edtInterval.Text=tonumber(vsettings.Value['CheckInterval']) or '1'
else
  edtInterval.Text='1'
end

edtInterval.ClientWidth=sf.Canvas.getTextWidth(' XX ');
edtInterval.Parent=parent
edtInterval.AnchorSideTop = sf.cbShowUndo.AnchorSideTop
edtInterval.AnchorSideLeft.Control=lblInterval
edtInterval.AnchorSideLeft.Side=asrRight

sf.cbShowUndo.AnchorSideTop.Control=edtInterval
sf.cbShowUndo.AnchorSideTop.Side=asrBottom

sf.cbShowUndo.AnchorSideLeft.Control=cbCheckForUpdatesOnLaunch
sf.cbShowUndo.AnchorSideLeft.Side=asrLeft

local oldSettingsFormClose=sf.OnClose

sf.OnClose=function(f, closeAction)
  local result=closeAction
  if sf.ModalResult==mrOK then
    vsettings.Value['CheckOnLaunch']=cbCheckForUpdatesOnLaunch.Checked
    vsettings.Value['CheckInterval']=edtInterval.Text
  end

  if oldSettingsFormClose then
    return oldSettingsFormClose(f, closeAction);
  end
end

