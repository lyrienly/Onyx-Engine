
local function safeLog(msg)
    pcall(function() print("[OnyxEngine MCP] " .. tostring(msg)) end)
end

function ShowMCPSettingsDialog()
    local s = getSettings("OnyxEngine_MCP")

    local curPipe = (s and s["PipeName"] and s["PipeName"] ~= "") and s["PipeName"] or "CE_MCP_Bridge_v99"
    local curPort = (s and s["TcpPort"] and s["TcpPort"] ~= "") and s["TcpPort"] or "9876"
    local curTimeout = (s and s["Timeout"] and s["Timeout"] ~= "") and s["Timeout"] or "30"
    local curAutostart = not (s and (s["Autostart"] == "0" or s["Autostart"] == "false"))
    local curAutoKernel = (s and s["AutoKernel"] == "1")
    local curAutoStrip = (s and s["AutoStripCallbacks"] == "1")
    local curAutoCloak = (s and s["AutoCloak"] == "1")
    local curBypassCoW = (s and s["BypassCoW"] == "1")

    local form = createForm(false)
    form.Caption = "OnyxEngine - Configuracoes do Servidor MCP"
    form.Width = 530
    form.Height = 520
    form.Position = "poScreenCenter"
    form.BorderStyle = "bsDialog"

    local lblTitle = createLabel(form)
    lblTitle.Caption = "Configuracao do Protocolo de Contexto de Modelo (MCP)"
    lblTitle.Font.Size = 11
    lblTitle.Font.Style = "fsBold"
    lblTitle.Left = 20
    lblTitle.Top = 15

    local lblSub = createLabel(form)
    lblSub.Caption = "Configure o named pipe, relay TCP, inicializacao automatica e poder do driver OwMemDriver."
    lblSub.Font.Size = 8
    lblSub.Left = 20
    lblSub.Top = 38

    local grpNet = createGroupBox(form)
    grpNet.Caption = " Transporte e Conexoes "
    grpNet.Left = 20
    grpNet.Top = 65
    grpNet.Width = 485
    grpNet.Height = 120

    local lblPipe = createLabel(grpNet)
    lblPipe.Caption = "Nome do Named Pipe (Local Windows):"
    lblPipe.Left = 15
    lblPipe.Top = 22

    local edtPipe = createEdit(grpNet)
    edtPipe.Text = curPipe
    edtPipe.Left = 250
    edtPipe.Top = 18
    edtPipe.Width = 215

    local lblPort = createLabel(grpNet)
    lblPort.Caption = "Porta do Relay TCP (Remoto / WSL):"
    lblPort.Left = 15
    lblPort.Top = 52

    local edtPort = createEdit(grpNet)
    edtPort.Text = curPort
    edtPort.Left = 250
    edtPort.Top = 48
    edtPort.Width = 100

    local lblTimeout = createLabel(grpNet)
    lblTimeout.Caption = "Tempo Limite da Requisicao (segundos):"
    lblTimeout.Left = 15
    lblTimeout.Top = 82

    local edtTimeout = createEdit(grpNet)
    edtTimeout.Text = curTimeout
    edtTimeout.Left = 250
    edtTimeout.Top = 78
    edtTimeout.Width = 100

    local grpKernel = createGroupBox(form)
    grpKernel.Caption = " Comportamento e Privilegios de Kernel (OwMemDriver) "
    grpKernel.Left = 20
    grpKernel.Top = 195
    grpKernel.Width = 485
    grpKernel.Height = 170

    local chkAutostart = createCheckBox(grpKernel)
    chkAutostart.Caption = "Iniciar ponte MCP automaticamente ao abrir o OnyxEngine"
    chkAutostart.Checked = curAutostart
    chkAutostart.Left = 15
    chkAutostart.Top = 20

    local chkAutoKernel = createCheckBox(grpKernel)
    chkAutoKernel.Caption = "Ativar modo de memoria fisica CR3 do OwMemDriver na inicializacao"
    chkAutoKernel.Checked = curAutoKernel
    chkAutoKernel.Left = 15
    chkAutoKernel.Top = 46

    local chkAutoStrip = createCheckBox(grpKernel)
    chkAutoStrip.Caption = "Remover callbacks de protecao de processos/threads (ObRegisterCallbacks)"
    chkAutoStrip.Checked = curAutoStrip
    chkAutoStrip.Left = 15
    chkAutoStrip.Top = 72

    local chkAutoCloak = createCheckBox(grpKernel)
    chkAutoCloak.Caption = "Ocultar driver da lista de modulos carregados e limpar tabela PiDDB"
    chkAutoCloak.Checked = curAutoCloak
    chkAutoCloak.Left = 15
    chkAutoCloak.Top = 98

    local chkBypassCoW = createCheckBox(grpKernel)
    chkBypassCoW.Caption = "Ignorar protecao de gravacao Copy-on-Write (Gravacao fisica direta)"
    chkBypassCoW.Checked = curBypassCoW
    chkBypassCoW.Left = 15
    chkBypassCoW.Top = 124

    local grpClient = createGroupBox(form)
    grpClient.Caption = " Integracao com Clientes "
    grpClient.Left = 20
    grpClient.Top = 375
    grpClient.Width = 485
    grpClient.Height = 70

    local btnCopyJson = createButton(grpClient)
    btnCopyJson.Caption = "Copiar JSON para Cursor / Claude / Antigravity"
    btnCopyJson.Left = 15
    btnCopyJson.Top = 22
    btnCopyJson.Width = 280
    btnCopyJson.Height = 32
    btnCopyJson.OnClick = function()
        local ceDir = getCheatEngineDir()
        local bridgePath = (ceDir .. "mcp\\mcp_cheatengine.py"):gsub("\\", "\\\\")
        local timeoutVal = edtTimeout.Text ~= "" and edtTimeout.Text or "30"
        local configJson = string.format([[
{
  "mcpServers": {
    "cheatengine": {
      "command": "python",
      "args": [
        "%s"
      ],
      "env": {
        "CE_MCP_TIMEOUT": "%s"
      }
    }
  }
}
]], bridgePath, timeoutVal)
        if writeToClipboard then
            writeToClipboard(configJson)
            showMessage("Configuracao do cliente MCP copiada para a area de transferencia!")
        end
    end

    local btnTestPing = createButton(grpClient)
    btnTestPing.Caption = "Testar Conexao (Ping)"
    btnTestPing.Left = 305
    btnTestPing.Top = 22
    btnTestPing.Width = 165
    btnTestPing.Height = 32
    btnTestPing.OnClick = function()
        local state = GetMCPServerState and GetMCPServerState() or (MCPServerState or {})
        if state.running then
            showMessage(string.format("Servidor MCP esta EM EXECUCAO no pipe:\\\\.\\pipe\\%s\nCliente conectado: %s",
                GetMCPPipeName and GetMCPPipeName() or edtPipe.Text,
                state.connected and "SIM" or "AGUARDANDO CONEXAO"))
        else
            showMessage("O servidor MCP esta PARADO no momento.")
        end
    end

    local btnSave = createButton(form)
    btnSave.Caption = "Salvar e Aplicar"
    btnSave.Left = 265
    btnSave.Top = 460
    btnSave.Width = 115
    btnSave.Height = 34
    btnSave.OnClick = function()
        if s then
            s["PipeName"] = edtPipe.Text
            s["TcpPort"] = edtPort.Text
            s["Timeout"] = edtTimeout.Text
            s["Autostart"] = chkAutostart.Checked and "1" or "0"
            s["AutoKernel"] = chkAutoKernel.Checked and "1" or "0"
            s["AutoStripCallbacks"] = chkAutoStrip.Checked and "1" or "0"
            s["AutoCloak"] = chkAutoCloak.Checked and "1" or "0"
            s["BypassCoW"] = chkBypassCoW.Checked and "1" or "0"
        end

        if chkAutoKernel.Checked then
            pcall(function()
                if onyx_kernelConnect then onyx_kernelConnect() end
                if dbk_initialize then dbk_initialize() end
                if dbk_usePhysicalMemoryAccess then dbk_usePhysicalMemoryAccess() end
                if dbk_useKernelmodeOpenProcess then dbk_useKernelmodeOpenProcess() end
                if dbk_useKernelmodeProcessMemoryAccess then dbk_useKernelmodeProcessMemoryAccess() end
                if dbk_useKernelmodeQueryMemoryRegions then dbk_useKernelmodeQueryMemoryRegions() end
            end)
        end
        if chkAutoStrip.Checked then
            pcall(function() if onyx_kernelStripCallbacks then onyx_kernelStripCallbacks(false) end end)
        end
        if chkAutoCloak.Checked then
            pcall(function()
                if onyx_kernelHideDriver then onyx_kernelHideDriver() end
                if onyx_kernelCleanTraces then onyx_kernelCleanTraces() end
            end)
        end
        if chkBypassCoW.Checked then
            pcall(function()
                if dbk_writesIgnoreWriteProtection then dbk_writesIgnoreWriteProtection(true) end
            end)
        end

        local state = GetMCPServerState and GetMCPServerState() or (MCPServerState or {})
        if state.running and StartMCPBridge then
            StartMCPBridge()
        end

        safeLog("Configuracoes salvas e aplicadas.")
        showMessage("Configuracoes do servidor MCP salvas e aplicadas com sucesso!")
        form.close()
    end

    local btnCancel = createButton(form)
    btnCancel.Caption = "Cancelar"
    btnCancel.Left = 390
    btnCancel.Top = 460
    btnCancel.Width = 115
    btnCancel.Height = 34
    btnCancel.OnClick = function()
        form.close()
    end

    form.showModal()
end

local function initializeMCPMenu()
    if not MainForm or not MainForm.Menu then
        return false
    end

    -- Issue #5: resolve human-readable connection state. The ground truth
    -- of liveness is last_rx (updated on every inbound frame, including
    -- heartbeats every ~5s), NOT the ephemeral `connected` boolean. CE's
    -- TPipeConnection flips `connected` to false on any transient ReadFile
    -- hiccup, the Lua worker then re-accepts the pipe within one tick and
    -- the Python relay reopens on its next heartbeat; during that brief
    -- gap, the TCP client never sees an error. Driving the label off
    -- last_rx makes those transparent cycles invisible to the user.
    --
    -- Thresholds (seconds): 12 = up to 2 missed heartbeats still counts as
    -- Connected (heartbeat interval is 5s); 45 = extended grace while we
    -- try to re-establish; beyond that we show Idle.
    local function resolveMcpStatus(state)
        if not state or not state.running then
            return "Offline", "[MCP Engine] - Offline"
        end
        local now = os.time()
        local lastRx = state.last_rx or 0
        local sinceRx = (lastRx > 0) and (now - lastRx) or math.huge

        if sinceRx <= 12 then
            return "Connected", "[MCP Engine] - Connected"
        end
        if sinceRx <= 45 then
            return "Reconnecting", "[MCP Engine] - Reconnecting..."
        end
        return "Idle", "[MCP Engine] - Aguardando conexao"
    end

    if MainForm.miMCP then
        safeLog("Menu nativo miMCP detectado ao lado do D3D.")
        pcall(function() MainForm.miMCP.Caption = "[MCP Engine] - Offline" end)
        local statusTimer = createTimer(MainForm)
        statusTimer.Interval = 1000
        statusTimer.OnTimer = function()
            pcall(function()
                local state = GetMCPServerState and GetMCPServerState() or (MCPServerState or {})
                local pipeName = GetMCPPipeName and GetMCPPipeName() or "CE_MCP_Bridge_v99"
                local _, mcpLabel = resolveMcpStatus(state)
                pcall(function() MainForm.miMCP.Caption = mcpLabel end)

                if MainForm.miMCPStatus then
                    if state.running then
                        MainForm.miMCPStatus.Caption = "Servidor: Em execucao (" .. pipeName .. ")"
                        if MainForm.miMCPStart then MainForm.miMCPStart.Enabled = false end
                        if MainForm.miMCPStop then MainForm.miMCPStop.Enabled = true end
                    else
                        MainForm.miMCPStatus.Caption = "Servidor: Parado"
                        if MainForm.miMCPStart then MainForm.miMCPStart.Enabled = true end
                        if MainForm.miMCPStop then MainForm.miMCPStop.Enabled = false end
                    end
                end

                if MainForm.miMCPClient then
                    local st, _ = resolveMcpStatus(state)
                    if st == "Connected" then
                        MainForm.miMCPClient.Caption = "Cliente: Conectado"
                    elseif st == "Reconnecting" then
                        MainForm.miMCPClient.Caption = "Cliente: Reconectando..."
                    else
                        MainForm.miMCPClient.Caption = "Cliente: Desconectado (Aguardando conexao)"
                    end
                end
            end)
        end
        return true
    end

    if MainForm.Menu.Items then
        for i = 0, MainForm.Menu.Items.Count - 1 do
            local item = MainForm.Menu.Items[i]
            if item and (item.Name == "miOnyxMCPTopMenu" or item.Name == "miMCP" or item.Caption == "MCP") then
                return true
            end
        end
    end

    local topMenu = createMenuItem(MainForm)
    topMenu.Name = "miOnyxMCPTopMenu"
    topMenu.Caption = "[MCP Engine] - Offline"

    local insertIndex = MainForm.Menu.Items.Count
    for i = 0, MainForm.Menu.Items.Count - 1 do
        local mi = MainForm.Menu.Items[i]
        if mi and (mi.Name == "mi3d" or mi.Caption == "D3D" or mi.Caption:find("D3D")) then
            insertIndex = i + 1
            break
        end
    end
    MainForm.Menu.Items.insert(insertIndex, topMenu)

    local miStatus = createMenuItem(topMenu)
    miStatus.Name = "miMCPStatus"
    miStatus.Caption = "Servidor: Inicializando..."
    miStatus.Enabled = false
    topMenu.add(miStatus)

    local miClient = createMenuItem(topMenu)
    miClient.Name = "miMCPClient"
    miClient.Caption = "Cliente: Desconectado (Aguardando conexao)"
    miClient.Enabled = false
    topMenu.add(miClient)

    local miSep1 = createMenuItem(topMenu)
    miSep1.Caption = "-"
    topMenu.add(miSep1)

    local miStart = createMenuItem(topMenu)
    miStart.Name = "miMCPStart"
    miStart.Caption = "Ligar Servidor"
    miStart.OnClick = function()
        if StartMCPBridge then
            StartMCPBridge()
            safeLog("Servidor MCP iniciado via menu.")
            showMessage("[MCP] Servidor MCP ligado com sucesso!\nEscutando requisicoes no pipe local.")
        else
            showMessage("Erro: Funcao StartMCPBridge nao encontrada.")
        end
    end
    topMenu.add(miStart)

    local miStop = createMenuItem(topMenu)
    miStop.Name = "miMCPStop"
    miStop.Caption = "Desligar Servidor"
    miStop.OnClick = function()
        if StopMCPBridge then
            StopMCPBridge()
            safeLog("Servidor MCP parado via menu.")
            showMessage("[MCP] Servidor MCP desligado.")
        else
            showMessage("Erro: Funcao StopMCPBridge nao encontrada.")
        end
    end
    topMenu.add(miStop)

    local miRestart = createMenuItem(topMenu)
    miRestart.Name = "miMCPRestart"
    miRestart.Caption = "Reiniciar Servidor"
    miRestart.OnClick = function()
        if StopMCPBridge and StartMCPBridge then
            StopMCPBridge()
            local t = createTimer(MainForm)
            t.Interval = 200
            t.OnTimer = function(timerObj)
                timerObj.destroy()
                StartMCPBridge()
                safeLog("Servidor MCP reiniciado via menu.")
                showMessage("[MCP] Servidor MCP reiniciado com sucesso!")
            end
        end
    end
    topMenu.add(miRestart)

    local miSep2 = createMenuItem(topMenu)
    miSep2.Caption = "-"
    topMenu.add(miSep2)

    local miSettings = createMenuItem(topMenu)
    miSettings.Name = "miMCPSettings"
    miSettings.Caption = "Configuracoes..."
    miSettings.OnClick = function()
        ShowMCPSettingsDialog()
    end
    topMenu.add(miSettings)

    local miSep3 = createMenuItem(topMenu)
    miSep3.Caption = "-"
    topMenu.add(miSep3)

    local miPowerMenu = createMenuItem(topMenu)
    miPowerMenu.Caption = "Poder do Kernel (OwMemDriver)"
    topMenu.add(miPowerMenu)

    local miGrantPower = createMenuItem(miPowerMenu)
    miGrantPower.Caption = "Conceder Privilegios de Kernel (Modo Fisico CR3)"
    miGrantPower.OnClick = function()
        local success = false
        pcall(function()
            if onyx_kernelConnect then onyx_kernelConnect() end
            if dbk_initialize then dbk_initialize() end
            if dbk_usePhysicalMemoryAccess then dbk_usePhysicalMemoryAccess() end
            if dbk_useKernelmodeOpenProcess then dbk_useKernelmodeOpenProcess() end
            if dbk_useKernelmodeProcessMemoryAccess then dbk_useKernelmodeProcessMemoryAccess() end
            if dbk_useKernelmodeQueryMemoryRegions then dbk_useKernelmodeQueryMemoryRegions() end
            if dbk_writesIgnoreWriteProtection then dbk_writesIgnoreWriteProtection(true) end
            if fullAccess then fullAccess() end
            success = true
        end)
        if success then
            showMessage("[OwMemDriver Ring-0 Ativo]\n\n" ..
                        "- Acesso a Memoria Fisica CR3: ATIVADO\n" ..
                        "- OpenProcess / ReadWrite de Kernel: ATIVADO\n" ..
                        "- Ignorar Protecao Copy-on-Write: ATIVADO\n" ..
                        "- Privilegios Totais do Processo (SeDebug): CONCEDIDOS\n\n" ..
                        "As ferramentas MCP agora operam com maximo poder e furtividade.")
        else
            showMessage("Falha ao inicializar privilegios do OwMemDriver. Verifique se o driver esta carregado.")
        end
    end
    miPowerMenu.add(miGrantPower)

    local miStripCallbacks = createMenuItem(miPowerMenu)
    miStripCallbacks.Caption = "Remover Callbacks de Anticheat (ObRegisterCallbacks)"
    miStripCallbacks.OnClick = function()
        local ok = false
        pcall(function()
            if onyx_kernelStripCallbacks then
                ok = (onyx_kernelStripCallbacks(false) == true)
            end
        end)
        if ok then
            showMessage("[OwMemDriver] Callbacks ObRegisterCallbacks removidos!\nFiltros de acesso a processos e threads desativados no kernel.")
        else
            showMessage("[OwMemDriver] Comando de remocao de callbacks despachado para o driver de kernel.")
        end
    end
    miPowerMenu.add(miStripCallbacks)

    local miCloakDriver = createMenuItem(miPowerMenu)
    miCloakDriver.Caption = "Ocultar Driver e Limpar Rastros (Indetectavel)"
    miCloakDriver.OnClick = function()
        pcall(function()
            if onyx_kernelHideDriver then onyx_kernelHideDriver() end
            if onyx_kernelCleanTraces then onyx_kernelCleanTraces() end
        end)
        showMessage("[OwMemDriver Ocultacao Ativa]\n\n" ..
                    "- Driver desvinculado da PsLoadedModuleList (DKOM)\n" ..
                    "- Registros da PiDDBCacheTable expurgados\n" ..
                    "- Driver invisivel para varreduras de modulos do kernel.")
    end
    miPowerMenu.add(miCloakDriver)

    local miToggleWriteProt = createMenuItem(miPowerMenu)
    miToggleWriteProt.Caption = "Ignorar Protecao de Gravacao (Gravacao Fisica Direta)"
    miToggleWriteProt.OnClick = function()
        pcall(function()
            if dbk_writesIgnoreWriteProtection then
                dbk_writesIgnoreWriteProtection(true)
                showMessage("[OwMemDriver] Ignorar protecao de gravacao ativado.\nGravacao direta em paginas fisicas em execucao.")
            end
        end)
    end
    miPowerMenu.add(miToggleWriteProt)

    local miSetProtection = createMenuItem(miPowerMenu)
    miSetProtection.Caption = "Definir Protecao do Processo Alvo (Ignorar PPL)"
    miSetProtection.OnClick = function()
        local pid = getOpenedProcessID()
        if not pid or pid == 0 then
            showMessage("Nenhum processo alvo selecionado. Conecte a um processo primeiro.")
            return
        end
        local ok = false
        pcall(function()
            if onyx_kernelSetProtection then
                ok = onyx_kernelSetProtection(pid, true)
            end
        end)
        if ok then
            showMessage(string.format("[OwMemDriver] Processo %d elevado para ProtectedProcess (PPL)!", pid))
        else
            showMessage(string.format("[OwMemDriver] Comando de protecao despachado para o PID %d.", pid))
        end
    end
    miPowerMenu.add(miSetProtection)

    local miSep4 = createMenuItem(topMenu)
    miSep4.Caption = "-"
    topMenu.add(miSep4)

    local miClearState = createMenuItem(topMenu)
    miClearState.Caption = "Limpar Estado e Breakpoints Zumbi"
    miClearState.OnClick = function()
        if cleanupZombieState then
            cleanupZombieState()
            showMessage("Breakpoints, estado zumbi e watches de DBVM expurgados.")
        end
    end
    topMenu.add(miClearState)

    local miCopyConfig = createMenuItem(topMenu)
    miCopyConfig.Caption = "Copiar JSON de Configuracao do MCP"
    miCopyConfig.OnClick = function()
        local ceDir = getCheatEngineDir()
        local bridgePath = (ceDir .. "mcp\\mcp_cheatengine.py"):gsub("\\", "\\\\")
        local configJson = string.format([[
{
  "mcpServers": {
    "cheatengine": {
      "command": "python",
      "args": [
        "%s"
      ],
      "env": {
        "CE_MCP_TIMEOUT": "30"
      }
    }
  }
}
]], bridgePath)
        if writeToClipboard then
            writeToClipboard(configJson)
            showMessage("Configuracao do servidor MCP copiada para a area de transferencia!\n\n" .. configJson)
        end
    end
    topMenu.add(miCopyConfig)

    local miAbout = createMenuItem(topMenu)
    miAbout.Caption = "Sobre a Ponte MCP"
    miAbout.OnClick = function()
        local state = GetMCPServerState and GetMCPServerState() or (MCPServerState or {})
        local pipeName = GetMCPPipeName and GetMCPPipeName() or "CE_MCP_Bridge_v99"
        local version = GetMCPVersion and GetMCPVersion() or "12.0.0"
        showMessage(string.format(
            "Ponte MCP do OnyxEngine\n" ..
            "====================================\n" ..
            "Protocolo da Ponte: miscusi-peek MCP Bridge v%s\n" ..
            "Named Pipe: \\\\.\\pipe\\%s\n" ..
            "Status do Servidor: %s\n" ..
            "Conexao do Cliente: %s\n" ..
            "Motor do Driver: OwMemDriver (Ring-0 CR3 Fisico)\n" ..
            "Localizacao: Menu Principal ao lado do D3D\n" ..
            "====================================\n" ..
            "Suporte completo a 175 ferramentas nativas de inspecao e memoria do Cheat Engine.",
            version, pipeName,
            state.running and "EM EXECUCAO" or "PARADO",
            state.connected and "CONECTADO" or "AGUARDANDO CLIENTE"
        ))
    end
    topMenu.add(miAbout)

    local statusTimer = createTimer(MainForm)
    statusTimer.Interval = 1000
    statusTimer.OnTimer = function()
        pcall(function()
            local state = GetMCPServerState and GetMCPServerState() or (MCPServerState or {})
            local pipeName = GetMCPPipeName and GetMCPPipeName() or "CE_MCP_Bridge_v99"
            local st, label = resolveMcpStatus(state)
            pcall(function() topMenu.Caption = label end)

            if state.running then
                miStatus.Caption = "Servidor: Em execucao (" .. pipeName .. ")"
                miStart.Enabled = false
                miStop.Enabled = true
            else
                miStatus.Caption = "Servidor: Parado"
                miStart.Enabled = true
                miStop.Enabled = false
            end

            if st == "Connected" then
                miClient.Caption = "Cliente: Conectado"
            elseif st == "Reconnecting" then
                miClient.Caption = "Cliente: Reconectando..."
            else
                miClient.Caption = "Cliente: Desconectado (Aguardando conexao)"
            end
        end)
    end

    safeLog("Menu MCP em portugues inicializado ao lado do D3D.")
    return true
end

local initTimer = createTimer(nil)
initTimer.Interval = 250
initTimer.OnTimer = function(t)
    if MainForm and MainForm.Menu then
        t.destroy()
        initializeMCPMenu()
    end
end

