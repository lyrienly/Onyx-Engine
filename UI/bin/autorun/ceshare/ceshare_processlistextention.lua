
function ceshare.GetCurrentProcessList()
  ceshare.currentprocesslist={}

  for pid,name in pairs(getProcessList()) do
    local md5name=stringToMD5String(string.lower(name))

    if ceshare.processlist and ceshare.processlist[md5name] then
      local e={}
      e.pid=pid
      e.name=name
      e.md5=md5name
      table.insert(ceshare.currentprocesslist,e)
    end
  end

  return ceshare.currentprocesslist
end

function ceshare.DownloadProcessList()

  local i=ceshare.getInternet()
  local processlist=i.getURL(ceshare.base..'processlist.txt')

  if processlist==nil then
    return
  end

  if processlist:sub(1,1)=='<' then
    return
  end

  local f=io.open(ceshare.path..[[processlist.txt]],'wb')
  if f then
    f:write(processlist)
    f:close()

    synchronize(function() ceshare.settings.Value.LastProcessListDownload=os.time() end )
  end
end

function ceshare.LoadProcessList()

  local lastdownload=''
  if getOperatingSystem()==0 then
    lastdownload=ceshare.settings.Value.LastProcessListDownload
  else

    synchronize(function() lastdownload=ceshare.settings.Value.LastProcessListDownload end)
  end

  if (lastdownload==nil) or (lastdownload=='') or (os.time()>(tonumber(lastdownload)+3600))  then
    outputDebugString('redownload');
    if inMainThread() then

      createThread(ceshare.LoadProcessList)
      return
    else

      ceshare.DownloadProcessList()
    end

  end

  local processlist
  local f=io.open(ceshare.path..[[processlist.txt]],'rb')
  if not f then
    ceshare.DownloadProcessList()
    f=io.open(ceshare.path..[[processlist.txt]],'rb')
  end

  if f then
    processlist=f:read("*all")
    f:close()
  else
    return false
  end

  local sl=createStringList()
  sl.Text=processlist
  ceshare.processlist={}
  for i=0,sl.Count-1 do
    local s=sl[i]
    if #s==32 then
      ceshare.processlist[sl[i]]=true
    end
  end

  local ceml=enumModules(getCheatEngineProcessID())
  if ceml then
    local cemodule=ceml[1]
    if cemodule then
      ceshare.processlist[stringToMD5String(string.lower(cemodule.Name))]=nil
    end
  end

  sl.destroy()
end

function ceshare.SystemHasKnownProcess()
  if not ceshare.processlist then return false end

  for pid,name in pairs(getProcessList()) do
    local md5name=stringToMD5String(string.lower(name))
    if ceshare.processlist[md5name] then
      return true
    end
  end

  return false
end

registerFormAddNotification(function(s)

  if s.ClassName=='TProcessWindow' then

    s.registerCreateCallback(function(s2)

      local OriginalOnShow=s2.OnShow
      s2.OnShow=function(s)
        OriginalOnShow(s)

        if ceshare.ProcessListTab then
          if ceshare.SystemHasKnownProcess() then
            ceshare.ProcessListTab.ImageIndex=11
          else
            ceshare.ProcessListTab.ImageIndex=-1
          end
        end
      end

    end)

    s.registerFirstShowCallback(function(s2)
      local OriginalProcessListDrawItem=s2.ProcessList.OnDrawItem

      ceshare.GetCurrentProcessList()

      ceshare.ProcessListWindow=s2

      local ts=s2.TabHeader.addTab()
      ts.Caption=translate('CEShare')
      ceshare.ProcessListTab=ts
      ts.Name='tsCEShare'

      s2.TabHeader.Images=MainForm.mfImageList

      if ceshare.SystemHasKnownProcess() then
        ts.ImageIndex=11
      else
        ts.ImageIndex=-1
      end

      ceshare.ProcessWindowCEShare=ts

      local OriginalOnDestroy=s2.OnDestroy
      s2.OnDestroy=function(sender)
        ceshare.settings.Value.ProcessListLastTab=s2.TabHeader.TabIndex
        if OriginalOnDestroy then
          OriginalOnDestroy(sender)
        end
      end

      local OriginalProcessListOnDblClick=s2.ProcessList.OnDblClick

      if getOperatingSystem()==0 then
        s2.ProcessList.OnDrawItem=function(sender, index, rect, state)
          local r=OriginalProcessListDrawItem(sender, index, rect, state)
          if s2.TabHeader.ActivePage.Name=='tsCEShare' then

            if ceshare.processiconcache then
              local iconhandle=ceshare.processiconcache[ceshare.currentprocesslist[index+1].pid]
              if iconhandle then

                local senderdc=sender.Canvas.Handle
                local ih=sender.ItemHeight

                executeCodeLocalEx('DrawIconEx',senderdc,0,rect.Top,iconhandle,ih,ih,0,0,3)

              end
            end

          end

          return r
        end
      end

      local oldTabChange=s2.TabHeader.OnChange

      local oldKeyPress=s2.ProcessList.OnKeyPress

      s2.ProcessList.OnKeyPress=function(sender, key)
        if s2.TabHeader.ActivePage.Name=='tsCEShare' then
          return key
        else
          return oldKeyPress(sender,key)
        end
      end

      s2.TabHeader.OnChange=function(th)

        if s2.TabHeader.ActivePage.Name=='tsCEShare' then
          s2.ProcessList.OnKeyPress=nil

          s2.ProcessList.Items.clear()

          if ceshare.processlist==nil then return end

          ceshare.currentprocesslist={}

          for pid,name in pairs(getProcessList()) do
            local md5name=stringToMD5String(string.lower(name))

            if ceshare.processlist[md5name] then
              local e={}
              e.pid=pid
              e.name=name
              e.md5=md5name
              table.insert(ceshare.currentprocesslist,e)

              s2.ProcessList.Items.add(string.format('%.8x-%s',pid,name))

              if ceshare.processiconcache==nil then
                ceshare.processiconcache={}
              end

              if (ceshare.processiconcache[pid]==nil) and (getOperatingSystem()==0) then
                local mi=enumModules(pid)
                if mi then
                  local mainmodule=mi[1]
                  if mainmodule then
                    local path=mainmodule.PathToFile
                    if path then
                      ceshare.processiconcache[pid]=executeCodeLocalEx('ExtractIconA',0x00400000,path,0)
                    end
                  end
                end
              end
            end
          end

        else
          s2.ProcessList.OnKeyPress=oldKeyPress
          oldTabChange(th)
        end
      end

      local ProcessListLastTab=tonumber(ceshare.settings.Value.ProcessListLastTab)
      if ProcessListLastTab==nil then
        ProcessListLastTab=ci
      end

      if s2.TabHeader.ClassName=='TPageControl' then

        local w

        local i
        w=0

        for i=1,s2.TabHeader.PageCount do
          local r=s2.TabHeader.tabRect(i-1)
          local tw=r.Right-r.Left
          w=w+tw
        end

        if s2.ClientWidth<w then
          s2.ClientWidth=w+16*(getScreenDPI()/96)+s2.Canvas.getTextWidth(' X ')
        end
      end

      s2.TabHeader.TabIndex=ProcessListLastTab
      s2.TabHeader.OnChange(s2.TabHeader)

      local oldOnShow=s2.OnShow
      s2.OnShow=function(s)
        if oldOnShow then
          if s2.TabHeader.TabIndex==ci then

            s2.TabHeader.OnChange(s2.TabHeader)
          end
          oldOnShow(s)
        end
      end
    end)
  end
end)

ceshare.originalOnProcessOpened=MainForm.OnProcessOpened
MainForm.OnProcessOpened=function(processid, processhandle, caption)
  if ceshare.originalOnProcessOpened then
    ceshare.originalOnProcessOpened(processid, processhandle, caption)
  end

  if ceshare.ProcessListWindow and (ceshare.ProcessListWindow.TabHeader.TabIndex==ceshare.ProcessWindowCEShareTabIndex) then

    local app=getApplication()
    if (AddressList.Count==0) and
       (app.AdvancedOptions.CodeList2.Items.Count==0) and
       (app.Comments.Memo1.Lines.Count==0) then
         MainForm.miCheckForCheats.DoClick()
    end
  end
end

ceshare.LoadProcessList()

