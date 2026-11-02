-- OnyxEngine Lua Sandbox
-- Fornece xpcall com traceback, log de erros dedicado e reset de scripts autorun

onyx = onyx or {}
onyx.sandbox = onyx.sandbox or {}

local MAX_ERRORS = 500
local errorBuffer = {}
local errorLogForm = nil
local errorLogMemo = nil
local errorLogTimer = nil
local lastRenderedCount = 0

local function timestamp()
    return os.date("%Y-%m-%d %H:%M:%S")
end

local function pushError(label, msg)
    local entry = {
        time = timestamp(),
        label = label or "unknown",
        message = tostring(msg or ""),
    }
    table.insert(errorBuffer, entry)
    while #errorBuffer > MAX_ERRORS do
        table.remove(errorBuffer, 1)
    end
    pcall(function() print(string.format("[OnyxLuaSandbox][%s] %s: %s", entry.time, entry.label, entry.message)) end)
end

local function traceback(err)
    if debug and debug.traceback then
        return debug.traceback(tostring(err), 2)
    end
    return tostring(err)
end

function onyx.sandbox.record(label, err)
    pushError(label, err)
end

function onyx.safe_call(fn, ...)
    if type(fn) ~= "function" then return false, "not a function" end
    local args = { ... }
    local n = select("#", ...)
    local ok, result = xpcall(function() return fn(table.unpack(args, 1, n)) end, traceback)
    if not ok then
        pushError("safe_call", result)
    end
    return ok, result
end

function onyx.wrap(fn, label)
    if type(fn) ~= "function" then return fn end
    local tag = label or "handler"
    return function(...)
        local args = { ... }
        local n = select("#", ...)
        local ok, result = xpcall(function() return fn(table.unpack(args, 1, n)) end, traceback)
        if not ok then
            pushError(tag, result)
            return nil
        end
        return result
    end
end

onyx.safe = onyx.safe_call
onyx.safeCall = onyx.safe_call

function onyx.safeTimer(owner, interval, handler)
    local t = createTimer(owner)
    if interval then t.Interval = interval end
    if handler then t.OnTimer = onyx.wrap(handler, "Timer.OnTimer") end
    return t
end

-- Interceptacao automatica de createTimer. Mantemos o objeto original e apenas
-- envolvemos a atribuicao de OnTimer com onyx.wrap para capturar erros.
local orig_createTimer = createTimer
local autowrapEnabled = true
onyx.sandbox.autowrap = true

local function wrapTimerAssignment(timer)
    if type(timer) ~= "userdata" and type(timer) ~= "table" then return timer end
    local realMeta = getmetatable(timer)
    if realMeta and realMeta.__onyx_wrapped then return timer end
    local proxy = {}
    local mt = {
        __onyx_wrapped = true,
        __index = function(_, key)
            local v = timer[key]
            if type(v) == "function" then
                return function(a, ...)
                    if a == proxy then
                        return v(timer, ...)
                    end
                    return v(a, ...)
                end
            end
            return v
        end,
        __newindex = function(_, key, value)
            if key == "OnTimer" and type(value) == "function" and autowrapEnabled then
                timer[key] = onyx.wrap(value, "Timer.OnTimer")
            else
                timer[key] = value
            end
        end,
    }
    setmetatable(proxy, mt)
    return proxy
end

function createTimer(owner, enabledOrSecond)
    local t = orig_createTimer(owner, enabledOrSecond)
    if not t then return t end
    local ok, wrapped = pcall(wrapTimerAssignment, t)
    if ok and wrapped then return wrapped end
    return t
end

function onyx.sandbox.setAutowrap(flag)
    autowrapEnabled = flag and true or false
    onyx.sandbox.autowrap = autowrapEnabled
end

function onyx.getErrorLog()
    local out = {}
    for i, e in ipairs(errorBuffer) do
        out[i] = string.format("[%s] %s\n%s\n", e.time, e.label, e.message)
    end
    return out
end

function onyx.clearErrorLog()
    errorBuffer = {}
    lastRenderedCount = 0
    if errorLogMemo and errorLogMemo.Lines then
        pcall(function() errorLogMemo.Lines.clear() end)
    end
end

onyx.clear_error_log = onyx.clearErrorLog

local function renderErrorLog()
    if not errorLogMemo or not errorLogMemo.Lines then return end
    if #errorBuffer == lastRenderedCount then return end
    pcall(function()
        errorLogMemo.Lines.beginUpdate()
        errorLogMemo.Lines.clear()
        if #errorBuffer == 0 then
            errorLogMemo.Lines.add("(nenhum erro Lua capturado ate o momento)")
        else
            for _, e in ipairs(errorBuffer) do
                errorLogMemo.Lines.add(string.format("[%s] %s", e.time, e.label))
                for line in tostring(e.message):gmatch("[^\r\n]+") do
                    errorLogMemo.Lines.add("  " .. line)
                end
                errorLogMemo.Lines.add("")
            end
        end
        errorLogMemo.Lines.endUpdate()
        lastRenderedCount = #errorBuffer
    end)
end

function onyx.showErrorLog()
    if errorLogForm and errorLogForm.Visible ~= nil then
        pcall(function() errorLogForm.show(); errorLogForm.BringToFront() end)
        renderErrorLog()
        return errorLogForm
    end

    local form = createForm(false)
    form.Caption = "OnyxEngine - Log de Erros Lua"
    form.Width = 760
    form.Height = 480
    form.Position = "poScreenCenter"

    local pnlTop = createPanel(form)
    pnlTop.Align = "alTop"
    pnlTop.Height = 36

    local btnClear = createButton(pnlTop)
    btnClear.Caption = "Limpar log"
    btnClear.Left = 8
    btnClear.Top = 4
    btnClear.Width = 110
    btnClear.Height = 28
    btnClear.OnClick = function()
        onyx.clearErrorLog()
        renderErrorLog()
    end

    local btnReset = createButton(pnlTop)
    btnReset.Caption = "Reiniciar autorun"
    btnReset.Left = 126
    btnReset.Top = 4
    btnReset.Width = 140
    btnReset.Height = 28
    btnReset.OnClick = function()
        onyx.resetAutorun()
    end

    local btnCopy = createButton(pnlTop)
    btnCopy.Caption = "Copiar"
    btnCopy.Left = 274
    btnCopy.Top = 4
    btnCopy.Width = 90
    btnCopy.Height = 28
    btnCopy.OnClick = function()
        if writeToClipboard and errorLogMemo and errorLogMemo.Lines then
            pcall(function() writeToClipboard(errorLogMemo.Lines.getText()) end)
        end
    end

    local btnClose = createButton(pnlTop)
    btnClose.Caption = "Fechar"
    btnClose.Left = 372
    btnClose.Top = 4
    btnClose.Width = 90
    btnClose.Height = 28
    btnClose.OnClick = function()
        pcall(function() form.hide() end)
    end

    local memo = createMemo(form)
    memo.Align = "alClient"
    memo.ScrollBars = "ssBoth"
    memo.ReadOnly = true
    memo.WordWrap = false
    memo.Font.Name = "Consolas"
    memo.Font.Size = 9

    errorLogForm = form
    errorLogMemo = memo
    lastRenderedCount = -1
    renderErrorLog()

    if not errorLogTimer then
        errorLogTimer = orig_createTimer(nil)
        errorLogTimer.Interval = 750
        errorLogTimer.OnTimer = function()
            if errorLogForm and errorLogForm.Visible then
                renderErrorLog()
            end
        end
    end

    form.show()
    return form
end

onyx.show_error_log = onyx.showErrorLog

-- Reinicializacao dos scripts autorun. CE/Lazarus nao expoe um reset real da VM,
-- entao reexecutamos cada arquivo .lua da pasta autorun sob xpcall, mantendo o
-- modulo sandbox vivo. Erros sao capturados no log.
function onyx.resetAutorun()
    pushError("reset", "reexecutando scripts autorun")
    local dir = nil
    pcall(function() dir = getAutorunPath and getAutorunPath() or (getCheatEngineDir() .. "autorun\\") end)
    if not dir or dir == "" then
        pushError("reset", "pasta autorun nao localizada")
        return false
    end
    local files = {}
    pcall(function()
        if enumFiles then
            local list = enumFiles(dir)
            if list then
                for i = 0, (list.Count or #list) - 1 do
                    local name = list[i]
                    if name and name:lower():match("%.lua$") and name:lower() ~= "onyx_lua_sandbox.lua" then
                        table.insert(files, dir .. name)
                    end
                end
            end
        end
    end)
    if #files == 0 then
        -- fallback via io.popen (dir)
        local p = io.popen('dir /b "' .. dir .. '*.lua" 2>nul')
        if p then
            for name in p:lines() do
                if name:lower() ~= "onyx_lua_sandbox.lua" then
                    table.insert(files, dir .. name)
                end
            end
            p:close()
        end
    end
    local okCount, failCount = 0, 0
    for _, path in ipairs(files) do
        local chunk, err = loadfile(path)
        if not chunk then
            failCount = failCount + 1
            pushError("reset:" .. path, err)
        else
            local ok, runErr = xpcall(chunk, traceback)
            if ok then
                okCount = okCount + 1
            else
                failCount = failCount + 1
                pushError("reset:" .. path, runErr)
            end
        end
    end
    pushError("reset", string.format("concluido: %d ok, %d falha", okCount, failCount))
    if errorLogForm and errorLogForm.Visible then renderErrorLog() end
    return failCount == 0
end

onyx.reset_lua_state = onyx.resetAutorun
onyx.reset_autorun = onyx.resetAutorun

-- Gatilho de teste para validacao end-to-end.
function onyx.triggerTestError()
    local t = createTimer(nil)
    t.Interval = 50
    t.OnTimer = function(self)
        pcall(function() self.destroy() end)
        error("erro de teste do sandbox onyx em " .. timestamp())
    end
    pushError("test", "timer de teste agendado (50ms)")
    return true
end

-- Menu de integracao
local function initializeSandboxMenu()
    if not MainForm or not MainForm.Menu then return false end
    if MainForm.miOnyxLuaSandbox then return true end

    local top = createMenuItem(MainForm)
    top.Name = "miOnyxLuaSandbox"
    top.Caption = "Lua"

    local insertIndex = MainForm.Menu.Items.Count
    for i = 0, MainForm.Menu.Items.Count - 1 do
        local mi = MainForm.Menu.Items[i]
        if mi and (mi.Name == "miOnyxMCPTopMenu" or mi.Caption == "MCP") then
            insertIndex = i + 1
            break
        end
    end
    MainForm.Menu.Items.insert(insertIndex, top)
    MainForm.miOnyxLuaSandbox = top

    local miShow = createMenuItem(top)
    miShow.Caption = "Mostrar log de erros Lua"
    miShow.OnClick = function() onyx.showErrorLog() end
    top.add(miShow)

    local miClear = createMenuItem(top)
    miClear.Caption = "Limpar log de erros Lua"
    miClear.OnClick = function()
        onyx.clearErrorLog()
        showMessage("Log de erros Lua limpo.")
    end
    top.add(miClear)

    local miReset = createMenuItem(top)
    miReset.Caption = "Reiniciar scripts autorun"
    miReset.OnClick = function()
        onyx.resetAutorun()
        showMessage("Scripts autorun reexecutados. Consulte o log para detalhes.")
    end
    top.add(miReset)

    local miSep = createMenuItem(top)
    miSep.Caption = "-"
    top.add(miSep)

    local miToggle = createMenuItem(top)
    miToggle.Caption = "Alternar envolvimento automatico de timers"
    miToggle.OnClick = function()
        onyx.sandbox.setAutowrap(not autowrapEnabled)
        showMessage("Envolvimento automatico: " .. (autowrapEnabled and "ATIVADO" or "DESATIVADO"))
    end
    top.add(miToggle)

    local miTest = createMenuItem(top)
    miTest.Caption = "Disparar erro de teste (validacao)"
    miTest.OnClick = function()
        onyx.triggerTestError()
        showMessage("Erro de teste disparado. Abra o log de erros Lua para verificar.")
    end
    top.add(miTest)

    -- menu inicializado silencioso
    return true
end

local initTimer = orig_createTimer(nil)
initTimer.Interval = 300
initTimer.OnTimer = function(t)
    if MainForm and MainForm.Menu then
        pcall(function() t.destroy() end)
        pcall(initializeSandboxMenu)
    end
end

-- carregado silencioso
