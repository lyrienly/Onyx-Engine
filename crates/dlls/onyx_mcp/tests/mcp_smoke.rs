use onyx_mcp::server::McpServer;
use serde_json::json;

#[test]
fn test_mcp_initialize_and_tools_list() {
    let server = McpServer::new();

    // 1. Initialize Handshake
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }).to_string();

    let resp_str = server.handle_message(&init_req).expect("Should respond to initialize");
    let resp: serde_json::Value = serde_json::from_str(&resp_str).unwrap();
    assert_eq!(resp["jsonrpc"], "2.0");
    assert_eq!(resp["id"], 1);
    assert_eq!(resp["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(resp["result"]["serverInfo"]["name"], "OnyxEngine Native MCP Server");

    // 2. Tools List
    let list_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }).to_string();

    let list_resp_str = server.handle_message(&list_req).expect("Should respond to tools/list");
    let list_resp: serde_json::Value = serde_json::from_str(&list_resp_str).unwrap();
    let tools = list_resp["result"]["tools"].as_array().expect("Tools should be array");
    assert!(tools.len() >= 45);

    let names = tools.iter().map(|t| t["name"].as_str().unwrap()).collect::<Vec<_>>();
    assert!(names.contains(&"process_list"));
    assert!(names.contains(&"attach_process"));
    assert!(names.contains(&"memory_read"));
    assert!(names.contains(&"memory_write"));
    assert!(names.contains(&"disassemble"));
    assert!(names.contains(&"system_get_last_error"));
    assert!(names.contains(&"system_capabilities"));
    assert!(names.contains(&"aa_validate_script"));
    assert!(names.contains(&"aa_execute_script"));
    assert!(names.contains(&"freeze_address"));
    assert!(names.contains(&"plugin_aob_validate"));
    assert!(names.contains(&"plugin_dll_manual_map"));
    assert!(names.contains(&"kernel_connect"));
    assert!(names.contains(&"mono_detect_runtime"));
    assert!(names.contains(&"dotnet_detect_runtime"));
}

#[test]
fn test_mcp_extended_capabilities() {
    let server = McpServer::new();

    // 1. System Capabilities
    let cap_req = json!({
        "jsonrpc": "2.0",
        "id": 20,
        "method": "tools/call",
        "params": { "name": "system_capabilities" }
    }).to_string();
    let cap_resp_str = server.handle_message(&cap_req).expect("Capabilities response");
    let cap_resp: serde_json::Value = serde_json::from_str(&cap_resp_str).unwrap();
    assert!(!cap_resp["result"]["isError"].as_bool().unwrap_or(true));
    let text = cap_resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("total_modular_dlls"));

    // 2. AutoAssembler Validation
    let aa_req = json!({
        "jsonrpc": "2.0",
        "id": 21,
        "method": "tools/call",
        "params": {
            "name": "aa_validate_script",
            "arguments": {
                "script": "[ENABLE]\nalloc(newmem, 2048)\nnewmem:\nret\n[DISABLE]\ndealloc(newmem)\n"
            }
        }
    }).to_string();
    let aa_resp_str = server.handle_message(&aa_req).expect("AA response");
    let aa_resp: serde_json::Value = serde_json::from_str(&aa_resp_str).unwrap();
    assert!(!aa_resp["result"]["isError"].as_bool().unwrap_or(true));

    // 3. Instruction Assembly
    let asm_req = json!({
        "jsonrpc": "2.0",
        "id": 22,
        "method": "tools/call",
        "params": {
            "name": "assemble_instruction",
            "arguments": {
                "instruction": "nop"
            }
        }
    }).to_string();
    let asm_resp_str = server.handle_message(&asm_req).expect("Assemble response");
    let asm_resp: serde_json::Value = serde_json::from_str(&asm_resp_str).unwrap();
    assert!(!asm_resp["result"]["isError"].as_bool().unwrap_or(true));
    let asm_text = asm_resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(asm_text.contains("90"));
}

#[test]
fn test_mcp_attach_read_and_disassemble_current_process() {
    let server = McpServer::new();
    let current_pid = std::process::id();

    // 1. Attach to self
    let attach_req = json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {
            "name": "attach_process",
            "arguments": {
                "name_or_pid": current_pid.to_string()
            }
        }
    }).to_string();

    let attach_resp_str = server.handle_message(&attach_req).expect("Attach response");
    let attach_resp: serde_json::Value = serde_json::from_str(&attach_resp_str).unwrap();
    assert!(!attach_resp["result"]["isError"].as_bool().unwrap_or(true));

    // 2. Read memory of magic number
    let magic: u64 = 0xCAFE_BABE_1337_0001;
    let addr = &magic as *const u64 as usize;

    let read_req = json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/call",
        "params": {
            "name": "memory_read",
            "arguments": {
                "address": format!("0x{:X}", addr),
                "size": 8,
                "data_type": "u64"
            }
        }
    }).to_string();

    let read_resp_str = server.handle_message(&read_req).expect("Read response");
    let read_resp: serde_json::Value = serde_json::from_str(&read_resp_str).unwrap();
    assert!(!read_resp["result"]["isError"].as_bool().unwrap_or(true));
    let content_text = read_resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(content_text.contains("CAFEBABE13370001"));

    // 3. Disassemble an instruction
    let test_fn_ptr = test_mcp_initialize_and_tools_list as *const () as usize;
    let disasm_req = json!({
        "jsonrpc": "2.0",
        "id": 12,
        "method": "tools/call",
        "params": {
            "name": "disassemble",
            "arguments": {
                "address": format!("0x{:X}", test_fn_ptr),
                "count": 5
            }
        }
    }).to_string();

    let disasm_resp_str = server.handle_message(&disasm_req).expect("Disasm response");
    let disasm_resp: serde_json::Value = serde_json::from_str(&disasm_resp_str).unwrap();
    assert!(!disasm_resp["result"]["isError"].as_bool().unwrap_or(true));

    // 4. Detach
    let detach_req = json!({
        "jsonrpc": "2.0",
        "id": 13,
        "method": "tools/call",
        "params": {
            "name": "detach_process"
        }
    }).to_string();

    let detach_resp_str = server.handle_message(&detach_req).expect("Detach response");
    let detach_resp: serde_json::Value = serde_json::from_str(&detach_resp_str).unwrap();
    assert!(!detach_resp["result"]["isError"].as_bool().unwrap_or(true));
}
