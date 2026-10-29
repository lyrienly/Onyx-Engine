use onyx_aa::{analyze, parse_script, SectionKind, Statement};

fn count_sections(src: &str) -> usize {
    parse_script(src).unwrap().sections.len()
}

#[test]
fn script_vazio_e_valido() {
    let s = parse_script("").unwrap();
    assert_eq!(s.sections.len(), 0);
    assert_eq!(s.preamble.len(), 0);
}

#[test]
fn secoes_enable_e_disable() {
    let src = r#"
[ENABLE]
alloc(mem, 1024)
label(returnhere)

[DISABLE]
dealloc(mem)
"#;
    let script = parse_script(src).unwrap();
    assert_eq!(script.sections.len(), 2);
    assert_eq!(script.sections[0].kind, SectionKind::Enable);
    assert_eq!(script.sections[1].kind, SectionKind::Disable);
}

#[test]
fn alloc_com_tres_argumentos() {
    let src = r#"
[ENABLE]
alloc(mem, 0x1000, 7FF600001000)
registersymbol(mem)
"#;
    let script = parse_script(src).unwrap();
    match &script.sections[0].statements[0] {
        Statement::Alloc {
            symbol,
            size,
            near_addr,
            ..
        } => {
            assert_eq!(symbol, "mem");
            assert_eq!(*size, 0x1000);
            assert_eq!(near_addr.as_deref(), Some("7FF600001000"));
        }
        _ => panic!("esperava Alloc"),
    }
}

#[test]
fn aobscanmodule_parseado() {
    let src = r#"
[ENABLE]
aobscanmodule(injPoint, game.exe, 48 8B 05 ? ? ? ? 48 85 C0)
"#;
    let script = parse_script(src).unwrap();
    match &script.sections[0].statements[0] {
        Statement::AobScanModule {
            symbol,
            module,
            pattern,
            ..
        } => {
            assert_eq!(symbol, "injPoint");
            assert_eq!(module, "game.exe");
            assert!(pattern.contains("48 8B 05"));
        }
        _ => panic!("esperava AobScanModule"),
    }
}

#[test]
fn script_realista_x64_passa() {
    let src = r#"
// Script AA realista com assembly 64-bit
[ENABLE]
aobscanmodule(ammoCheck, game.exe, 48 83 EB 01 48 89 1F)
alloc(newmem, 0x1000, ammoCheck)
label(code)
label(return)
registersymbol(ammoCheck)

newmem:
  mov rax, 0xDEADBEEFCAFEBABE
  mov [rbx], rax
  jmp return
code:
  sub rbx, 1
  mov [rdi], rbx
  jmp return
ammoCheck:
  jmp newmem
  nop
return:

[DISABLE]
ammoCheck:
  db 48 83 EB 01 48 89 1F

unregistersymbol(ammoCheck)
dealloc(newmem)
"#;
    let script = parse_script(src).unwrap();
    assert_eq!(script.sections.len(), 2);
    analyze(&script).expect("analise semantica deve passar em script valido");
}

#[test]
fn macros_define_sao_expandidos() {
    let src = r#"
define(SPEED, 2)
[ENABLE]
alloc(mem, 0x100)
label(code)
registersymbol(mem)
code:
  mov rax, SPEED
"#;
    let script = parse_script(src).unwrap();
    // confere que a linha de assembly ja veio expandida
    let has_expanded = script.sections[0].statements.iter().any(|s| match s {
        Statement::Assembly { line, .. } => line.contains("mov rax, 2"),
        _ => false,
    });
    assert!(
        has_expanded,
        "define(SPEED, 2) deveria substituir SPEED por 2"
    );
}

#[test]
fn registradores_64bit_sao_aceitos() {
    let src = r#"
[ENABLE]
alloc(mem, 0x100)
label(code)
registersymbol(mem)
code:
  mov r8, r9
  mov r15, 0xDEADBEEFCAFEBABE
  xor r10d, r11d
"#;
    let script = parse_script(src).unwrap();
    analyze(&script).unwrap();
}

#[test]
fn assert_parseia() {
    let src = r#"
[ENABLE]
assert(game.exe+0x1234, 48 8B 05)
"#;
    let script = parse_script(src).unwrap();
    match &script.sections[0].statements[0] {
        Statement::Assert { .. } => {}
        _ => panic!("esperava Assert"),
    }
}

#[test]
fn simbolo_nao_declarado_e_erro() {
    let src = r#"
[ENABLE]
alloc(mem, 0x100)
mov rax, naoExiste
"#;
    let script = parse_script(src).unwrap();
    let err = analyze(&script).unwrap_err();
    assert!(err.msg.contains("naoExiste"), "msg: {}", err.msg);
    assert_eq!(err.span.line, 4);
}

#[test]
fn dealloc_de_simbolo_fantasma_e_erro() {
    let src = r#"
[DISABLE]
dealloc(nao_alocado)
"#;
    let script = parse_script(src).unwrap();
    let err = analyze(&script).unwrap_err();
    assert!(err.msg.contains("nao_alocado"));
}

#[test]
fn include_parseia() {
    let src = r#"
include "shared.aa"
include(biblioteca.aa)
[ENABLE]
"#;
    let script = parse_script(src).unwrap();
    assert_eq!(script.preamble.len(), 2);
    match &script.preamble[0] {
        Statement::Include { path, .. } => assert_eq!(path, "shared.aa"),
        _ => panic!("esperava Include"),
    }
}

#[test]
fn erro_de_sintaxe_reporta_linha() {
    let src = "[ENABLE]\nalloc(mem, naoNumero)\n";
    let err = parse_script(src).unwrap_err();
    assert_eq!(err.span.line, 2);
    assert!(err.msg.contains("tamanho invalido"));
}

#[test]
fn verifica_contagem_secoes_helpers() {
    assert_eq!(count_sections("[ENABLE]\n[DISABLE]\n"), 2);
}
