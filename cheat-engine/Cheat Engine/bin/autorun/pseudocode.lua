local function genericJumpHandler(state, alwaystaken)
  local origin=state.address
  local addressString=string.gsub(state.ldd.parameters,"qword ptr ","")
  local addressString=string.gsub(addressString,"dword ptr ","")
  local destination=getAddressSafe(addressString)
  local destination2

  if destination==nil then

    return
  end

  if not alwaystaken then
    destination2=origin+state.parsed[origin].bytesize
  end;

  state.branchOrigins[origin]={}
  state.branchOrigins[origin].destinationtaken=destination
  state.branchOrigins[origin].destinationnottaken=destination2

  if state.branchDestinations[destination]==nil then
    state.branchDestinations[destination]={}
  end

  table.insert(state.branchDestinations[destination], origin)

  if not alwaystaken then
    if state.branchDestinations[destination2]==nil then
      state.branchDestinations[destination2]={}
    end

    table.insert(state.branchDestinations[destination2], origin)
  end

  return destination
end

local function pfindNextSpot(state)

  for destination,origins in pairs(state.branchDestinations) do
    if state.parsed[destination]==nil then
      state.address=destination
      return true
    end
  end

  return false,true
end

local plookup={}
plookup['jo']=function(state)
  genericJumpHandler(state)
end

plookup['jno']=function(state)
  genericJumpHandler(state)
end

plookup['jb']=function(state)
  genericJumpHandler(state)
end

plookup['jnb']=function(state)
  genericJumpHandler(state)
end

plookup['jae']=function(state)
  genericJumpHandler(state)
end

plookup['je']=function(state)
  genericJumpHandler(state)
end

plookup['jne']=function(state)
  genericJumpHandler(state)
end

plookup['ja']=function(state)
  genericJumpHandler(state)
end

plookup['jna']=function(state)
  genericJumpHandler(state)
end

plookup['js']=function(state)
  genericJumpHandler(state)
end

plookup['jns']=function(state)
  genericJumpHandler(state)
end

plookup['jp']=function(state)
  genericJumpHandler(state)
end

plookup['jnp']=function(state)
  genericJumpHandler(state)
end

plookup['jl']=function(state)
  genericJumpHandler(state)
end

plookup['jnl']=function(state)
  genericJumpHandler(state)
end

plookup['jle']=function(state)
  genericJumpHandler(state)
end

plookup['jg']=function(state)
  genericJumpHandler(state)
end

plookup['jng']=function(state)
  genericJumpHandler(state)
end

plookup['jmp']=function(state)
  local newa
  newa=genericJumpHandler(state, true)
  if newa==nil then
    state.branchOrigins[state.address]={}
  else
    state.address=newa
    return true
  end
end

plookup['loop']=function(state)
  genericJumpHandler(state)
end

plookup['ret']=function(state)

  state.branchOrigins[state.address]={}

  return pfindNextSpot(state)
end

function parseFunction(startaddress, limit)
  local state={}

  state.branchDestinations={}
  state.branchOrigins={}

  state.parsed={}

  local currentpath={}
  currentpath.asm={}

  state.address=startaddress

  local d=createDisassembler()
  local done=false
  if limit==nil then limit=1000 end

  local statechange, shouldexit

  while (not done) and (limit>0) do
    local a=state.address

    if state.parsed[a] then

      statechange, shouldexit=pfindNextSpot(state)
      if shouldexit then break end
      if not statechange then break end

      a=state.address
    end

    local s=d.disassemble(a)

    state.parsed[a]={}
    state.parsed[a].instruction=s

    local ldd=d.getLastDisassembleData()
    table.insert(currentpath.asm, ldd)
    state.ldd=ldd

    state.parsed[a].bytesize=#ldd.bytes

    local statechange
    local f=plookup[ldd.opcode]
    if f then
      statechange,shouldexit=f(state)
    end

    if (not statechange) then
      if #ldd.bytes==0 then
        statechange,shouldexit=pfindNextSpot(state)
      else
        state.address=state.address+#ldd.bytes
      end
    end

    limit=limit-1

    if shouldexit then break end
  end

  return state
end

local function createBlocks(state)
  local blocks={}

  local sal={}
  for n in pairs(state.parsed) do
    table.insert(sal,n);
  end

  table.sort(sal)

  blocks[1]={}
  blocks[1].start=sal[1]
  blocks[1].salstartindex=1

  blocks[1].getsJumpedToBy=state.branchDestinations[sal[1]]

  for i=2,#sal do
    local address=sal[i]
    if state.branchDestinations[address] then

      blocks[#blocks].stop=sal[i-1]
      blocks[#blocks].salstopindex=i-1
      blocks[#blocks].jumpsTo=state.branchOrigins[blocks[#blocks].stop]

      if blocks[#blocks].jumpsTo==nil then
        blocks[#blocks].jumpsTo={}
        blocks[#blocks].jumpsTo.destinationtaken=address
        blocks[#blocks].jumpsTo.logicalFollow=true

      end

      blocks[#blocks+1]={}
      blocks[#blocks].start=address
      blocks[#blocks].salstartindex=i
      blocks[#blocks].getsJumpedToBy=state.branchDestinations[address]
    end

    if (i==#sal) and (state.branchOrigins[address]) then
      blocks[#blocks].jumpsTo=state.branchOrigins[address]
    end
  end

  blocks[#blocks].stop=sal[#sal]
  blocks[#blocks].salstopindex=#sal

  return blocks,sal
end

pseudocode = {}
pseudocode.parseFunction = parseFunction
pseudocode.createBlocks = createBlocks

