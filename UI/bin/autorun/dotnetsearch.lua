
if getTranslationFolder()~='' then
  loadPOFile(getTranslationFolder()..'dotnetsearch.po')
end

function spawnDotNetSearchDialog(DataSource, frmDotNetInfo, searchtype)

  local currentScan
  local searchresults={}

  local frmSearch=createFormFromFile(getAutorunPath()..'forms'..pathsep..'DotNetSearch.frm')

  _G.frmSearch=frmSearch

  if searchtype==0 then
    frmSearch.Caption=translate('Find Class')
    frmSearch.cbLimitToCurrentBase.Caption=translate('Limit to current image')

    frmSearch.cbLimitToCurrentBase.Enabled=frmDotNetInfo.lbImages.ItemIndex>=0
    frmSearch.lvResults.Columns.delete(2)
  elseif searchtype==1 then
    frmSearch.Caption=translate('Find Field')
    frmSearch.cbLimitToCurrentBase.Caption=translate('Limit to current class')
    frmSearch.cbLimitToCurrentBase.Enabled=frmDotNetInfo.lvClasses.ItemIndex>=0
    frmSearch.lvResults.Columns[2].Caption='Field'
  elseif searchtype==2 then
    frmSearch.Caption=translate('Find Method')
    frmSearch.cbLimitToCurrentBase.Caption=translate('Limit to current class')
    frmSearch.cbLimitToCurrentBase.Enabled=frmDotNetInfo.lvClasses.ItemIndex>=0
    frmSearch.lvResults.Columns[2].Caption='Method'
  else
    return nil,'no'
  end

  frmSearch.OnClose=function(ca)
    if currentScan then
      currentScan.terminate()
    end
    frmSearch=nil
    return caFree
  end

  frmSearch.lvResults.OnDblClick=function()

    local i
    local index=frmSearch.lvResults.ItemIndex
    if index==-1 then
      return
    end

    index=index+1
    if index<=#searchresults then
      local r=searchresults[index]
      if r then

        frmDotNetInfo.edtClassFilter.Text=''

        frmDotNetInfo.lbDomains.ItemIndex=r.DomainIndex-1
        frmDotNetInfo.lbImages.ItemIndex=r.ImageIndex-1

        local timeout=getTickCount()
        while frmDotNetInfo.lvClasses.Items.Count<r.ClassIndex do
          CheckSynchronize(100)

          if getTickCount()>timeout+10000 then return end
        end

        frmDotNetInfo.lvClasses.ItemIndex=r.ClassIndex-1
        frmDotNetInfo.lvClasses.Items[frmDotNetInfo.lvClasses.ItemIndex].makeVisible(false)

        if searchtype==1 then

          frmDotNetInfo.lvFields.Index=r.FieldIndex-1
        elseif searchtype==2 then

          frmDotNetInfo.lvMethods.Index=r.MethodIndex-1
        end

      end
    end

  end

  frmSearch.show()

  local oldOnClose=frmDotNetInfo.OnClose
  frmDotNetInfo.OnClose=function(closeAction)
    if currentScan then
      currentScan.terminate()
    end

    if oldOnClose then
      return oldOnClose(closeAction)
    else
      return closeAction
    end
  end

  frmSearch.btnScan.OnClick=function()
    if currentScan then
      print("Canceling scan")

      currentScan.terminate()
      currentScan=nil
      frmSearch.btnScan.Caption='   '..translate('Search')..'   '
    else

      local searchInput=frmSearch.edtSearchInput.Text
      local baseScanOnly=frmSearch.cbLimitToCurrentBase.checked
      local caseSensitive=frmSearch.cbCaseSensitive.checked
      local ImageListIndex=frmDotNetInfo.lbImages.ItemIndex

      if not caseSensitive then
        searchInput=searchInput:upper()
      end

      if searchInput~='' then
        frmSearch.btnScan.Caption=translate('Stop')
        frmSearch.lvResults.Items.clear()

        currentScan=createThread(function(t)

          if t.Terminated then return end

          local i,j,k,l
          local currentDomainIndex=1
          local currentImageIndex=1
          local currentClassIndex=1
          local currentFieldIndex=1
          local currentMethodIndex=1

          if baseScanOnly and ImageListIndex~=-1 then
            currentImageIndex=ImageListIndex+1
          end

          if DataSource.Domains==nil then
            DataSource.getDomains()
          end

          if t.Terminated then return end

          for i=currentDomainIndex,#DataSource.Domains do

            if DataSource.Domains[i].Images==nil then
              DataSource.getImages(DataSource.Domains[i])
            end

            if DataSource.Domains[i].Images==nil then return end

            for j=currentImageIndex,#DataSource.Domains[i].Images do

              local HasToFetchClasses=false

              synchronize(function()

                if t.Terminated then return end
                if DataSource.Domains[i].Images[j].Classes==nil then
                  HasToFetchClasses=true
                  DataSource.Domains[i].Images[j].Classes={}
                  DataSource.Domains[i].Images[j].Classes.Busy=true
                end
              end)

              if HasToFetchClasses then

                DataSource.getClasses(DataSource.Domains[i].Images[j])
                DataSource.Domains[i].Images[j].Classes.Busy=false
              end

              for k=1,#DataSource.Domains[i].Images[j].Classes do
                if searchtype==0 then

                  local fullname=DataSource.Domains[i].Images[j].Classes[k].FullName
                  if fullname==nil then
                    name=DataSource.Domains[i].Images[j].Classes[k].Name
                  end

                  local name=fullname

                  if not caseSensitive then
                    name=name:upper()
                  end

                  if name:find(searchInput) then
                    synchronize(function()

                      if t.Terminated then return end
                      local li=frmSearch.lvResults.Items.add()
                      li.Caption=DataSource.Domains[i].Images[j].FileName
                      li.SubItems.add(fullname)

                      local e={}
                      e.DomainIndex=i
                      e.ImageIndex=j
                      e.ClassIndex=k
                      searchresults[li.Index+1]=e

                    end)
                  end
                elseif searchtype==1 then

                  if DataSource.Domains[i].Images[j].Classes[k].Fields==nil then
                    DataSource.getClassFields(DataSource.Domains[i].Images[j].Classes[k])
                  end

                  if DataSource.Domains[i].Images[j].Classes[k].Fields then
                    for l=1,#DataSource.Domains[i].Images[j].Classes[k].Fields do
                      local name=DataSource.Domains[i].Images[j].Classes[k].Fields[l].Name
                      if not caseSensitive then
                        name=name:upper()
                      end

                      if name:find(searchInput) then
                        synchronize(function()
                          if t.Terminated then return end

                          local li=frmSearch.lvResults.Items.add()
                          li.Caption=DataSource.Domains[i].Images[j].FileName
                          li.SubItems.add(DataSource.Domains[i].Images[j].Classes[k].Name)
                          li.SubItems.add(DataSource.Domains[i].Images[j].Classes[k].Fields[l].Name)

                          local e={}
                          e.DomainIndex=i
                          e.ImageIndex=j
                          e.ClassIndex=k
                          e.FieldIndex=l
                          searchresults[li.Index+1]=e
                        end)

                      end
                    end
                  end

                elseif searchtype==2 then

                  if DataSource.Domains[i].Images[j].Classes[k].Methods==nil then
                    DataSource.getClassMethods(DataSource.Domains[i].Images[j].Classes[k])
                  end

                  if DataSource.Domains[i].Images[j].Classes[k].Methods then
                    for l=1,#DataSource.Domains[i].Images[j].Classes[k].Methods do
                      local name=DataSource.Domains[i].Images[j].Classes[k].Methods[l].Name
                      if not caseSensitive then
                        name=name:upper()
                      end

                      if name:find(searchInput) then
                        synchronize(function()
                          if t.Terminated then return end

                          local li=frmSearch.lvResults.Items.add()
                          li.Caption=DataSource.Domains[i].Images[j].FileName
                          li.SubItems.add(DataSource.Domains[i].Images[j].Classes[k].Name)
                          li.SubItems.add(DataSource.Domains[i].Images[j].Classes[k].Methods[l].Name)

                          local e={}
                          e.DomainIndex=i
                          e.ImageIndex=j
                          e.ClassIndex=k
                          e.MethodIndex=l
                          searchresults[li.Index+1]=e

                        end)
                      end
                    end
                  end
                else
                  print("wtf")
                  return
                end

                if t.Terminated then return end
                if baseScanOnly and searchtype~=0 then break end

              end

              if t.Terminated then return end
              if baseScanOnly and searchtype==0 then break end
            end

            if t.Terminated then return end
            if baseScanOnly then break end
          end

          synchronize(function()

            currentScan=nil
            if frmSearch~=nil then
              frmSearch.btnScan.Caption='   '..translate('Search')..'   '
            end
          end)

        end)

      end
    end
  end
end

function SearchClassName(classname, onFound, onDone)

  if DataSource.ClassNameLookup==nil then
    DataSource.ClassNameLookup={}
  else
    local r=DataSource.ClassNameLookup[classname]
    if r then

      return nil,r
    end
  end

  return createThread(function(t)
    t.freeOnTerminate(false)
    t.Name='SearchClassName thread'
    function scan()
      local i,j,k

      if DataSource.Domains==nil then
        DataSource.getDomains()
      end

      if t.Terminated then return end

      for i=1,#DataSource.Domains do
        if t.Terminated then return end

        if DataSource.Domains[i].Images==nil then
          DataSource.getImages(DataSource.Domains[i])
        end

        if DataSource.Domains[i].Images==nil then return end

        for j=1,#DataSource.Domains[i].Images do
          if t.Terminated then return end

          if DataSource.Domains[i].Images[j].Classes==nil then
            DataSource.Domains[i].Images[j].Classes={}
            DataSource.Domains[i].Images[j].Classes.Busy=true
            DataSource.getClasses(DataSource.Domains[i].Images[j])
            DataSource.Domains[i].Images[j].Classes.Busy=nil
          end

          if t.Terminated then return end

          local found=nil
          if not DataSource.Domains[i].Images[j].ClassNameLookupDone then
            for k=1,#DataSource.Domains[i].Images[j].Classes do
              local fullname=DataSource.Domains[i].Images[j].Classes[k].FullName

              DataSource.ClassNameLookup[fullname]=DataSource.Domains[i].Images[j].Classes[k]

              if (found==nil) and (fullname==classname) then
                found=DataSource.Domains[i].Images[j].Classes[k]

                if onFound then
                  queue(function()
                    onFound(found)
                  end)

                end

              end
            end

            DataSource.Domains[i].Images[j].ClassNameLookupDone=true
          end
          if found then
            return
          end
        end
      end

    end
    scan()

    synchronize(function()
      if t.Terminated==false then
        onDone()
      end
    end)
  end)

end

