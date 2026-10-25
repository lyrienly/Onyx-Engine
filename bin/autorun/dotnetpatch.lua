
function ParseScriptTokens(script,values)

  if script==nil then
    print(debug.traceback())
    error('ParseScriptTokens: script is nil')
  end
  if values==nil then
    print(debug.traceback())
    error('ParseScriptTokens: values is nil')
  end

  return string.gsub(script,"<(.-)>",function(v)
    local r=values[v]
    if r then return r else return x end
  end)
end

function dotnetpatch_getAllReferences()

  local r={}
  local sysfile

  if monopipe then
    mono_enumImages(function(img)
      local n=mono_image_get_filename(img)
      local ln=extractFileName(n:lower())

	  table.insert(r,n)
	  if ln=='mscorlib.dll' or ln=='netstandard.dll' or ln=='system.runtime.dll' then
	    if sysfile==nil then
		  sysfile=n
		end
	  end
    end)
    return r,sysfile
  end

  local dc=getDotNetDataCollector()
  local d=dc.enumDomains()
  local i
  for i=1,#d do
    local ml=dc.enumModuleList(d[i].DomainHandle)
    local j
    for j=1,#ml do
      local ln=extractFileName(ml[j].Name):lower()

	  r[#r+1]=ml[j].Name
	  printf("%d %s", j, ml[j].Name)
	  if ln=='mscorlib.dll' or ln=='netstandard.dll' or ln=='system.runtime.dll' then
	    if sysfile==nil then
		  sysfile=ml[j].Name
		end
	  end
    end
  end

  return r,sysfile
end

function SplitDotNetName(dotnetname)
  local r=mono_splitSymbol(dotnetname)
  return r.namespace, r.classname, r.methodname
end

function findDotNetMethodAddress(name, modulename)

  local result
  local namespace, classname, methodname=SplitDotNetName(name)
  if namespace==nil then namespace='' end
  if classname==nil or classname=='' then return getAddressSafe(name) end
  if methodname==nil or methodname=='' then return getAddressSafe(name) end

  if monopipe then

    local dllmodulelower=modulename:lower()

    local assemblies=mono_enumAssemblies()
    for i=1,#assemblies do
      local img=mono_getImageFromAssembly(assemblies[i])
      local imagename=mono_image_get_filename(img):lower()
      local ln=extractFileName(imagename)

      if ln==dllmodulelower then

        local class=mono_image_findClass(img, namespace, classname)

        if class then
          local method=mono_class_findMethod(class, methodname)
          if method then
            return mono_compile_method(method)
          end

        end
        break
      end
    end

    result=getAddressSafe(monoformat)

    if result==nil then
      return nil,name..' could not be resolved'
    end

  else

    local dnformat=''
    if namespace~='' then dnformat=namespace..'.' end
    dnformat=dnformat..classname..'::'..methodname

    result=getAddressSafe(dnformat)
    if result==nil then

      result=dotnet_findDotNetMethodAddress(namespace, classname, methodname, modulename)

      if result==nil then
        return nil,name..' could not be resolved'
      end
    end
  end

  return result
end

function detourdotnet(oldmethodaddress,newmethodaddress,oldmethodcalleraddress)

  local ahe,ahd=generateAPIHookScript(string.format("%.8x",oldmethodaddress), string.format("%.8x",newmethodaddress))
  script=ahe..string.format([[
%.8x:
jmp originalcall
]],oldmethodcalleraddress)

  local aaresult,disableinfo=autoAssemble(script)
  if aaresult then
    return aaresult,disableinfo,ahd
  else
    return aaresult, disableinfo
  end
end

function InjectDotNetDetour(dllmodule, oldmethodname, newmethodname, oldmethodcaller)

  if dllmodule==nil then
    print(debug.traceback())
    print('InjectDotNetDetour: dllmodule is nil')
    error('InjectDotNetDetour: dllmodule is nil')
  end

  if monopipe then
    if mono_loadAssemblyFromFile(dllmodule)==nil then
      return false,'loading '+dllmodule+' failed'
    end

    local oldmethodaddress=getAddressSafe(oldmethodname)
    local oldmethodcalleraddress=getAddressSafe(oldmethodcaller)
    local newmethodaddress=findDotNetMethodAddress(newmethodname, extractFileName(dllmodule))

    if oldmethodcaller and newmethodaddress and oldmethodcalleraddress then
      return detourdotnet(oldmethodaddress,newmethodaddress,oldmethodcalleraddress)
    else
      error("not all addresses found")
    end

  else
    LaunchDotNetInterface()

    if dotnet_loadModule(dllmodule)==false then
      return false,'loading '..dllmodule..' failed'
    end

    local oldmethodAddress=getAddressSafe(oldmethodname)
    if oldmethodAddress==nil then

      oldmethodaddress=findDotNetMethodAddress(oldmethodname)

      if oldmethodaddress==nil then error('Failure getting '..oldmethodname) end
    end

    local newmethodaddress=findDotNetMethodAddress(newmethodname, extractFileName(dllmodule))

    local oldmethodcalleraddress=getAddressSafe(oldmethodcaller)
    if oldmethodcalleraddress==nil then

      oldmethodcalleraddress=findDotNetMethodAddress(oldmethodcaller, extractFileName(dllmodule))

      if oldmethodcalleraddress==nil then error('Failure getting '..oldmethodcalleraddress) end
    end

    if oldmethodaddress and newmethodaddress and oldmethodcalleraddress then
      return detourdotnet(oldmethodaddress,newmethodaddress,oldmethodcalleraddress)
    else
      error("not all addresses found")
    end
  end

end

