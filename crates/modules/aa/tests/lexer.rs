use onyx_aa::lexer::{strip_comments, tokenize_line, TokenKind};

#[test]
fn comentarios_sao_removidos() {
    let src = "alloc(mem, 1024) // comentario de fim\n{comentario de bloco}\nmov rax, rbx\n";
    let lines = strip_comments(src);
    let joined: Vec<_> = lines.iter().map(|l| l.text.trim().to_string()).collect();
    assert!(joined.iter().any(|l| l == "alloc(mem, 1024)"));
    assert!(joined.iter().any(|l| l == "mov rax, rbx"));
    assert!(!joined.iter().any(|l| l.contains("//")));
}

#[test]
fn tokens_basicos() {
    let toks = tokenize_line(1, "alloc(mem, 1024)").unwrap();
    let kinds: Vec<_> = toks.iter().map(|t| t.kind.clone()).collect();
    assert!(matches!(kinds[0], TokenKind::Ident(ref s) if s == "alloc"));
    assert!(matches!(kinds[1], TokenKind::LParen));
    assert!(matches!(kinds[2], TokenKind::Ident(ref s) if s == "mem"));
    assert!(matches!(kinds[3], TokenKind::Comma));
    assert!(matches!(kinds[4], TokenKind::Number { value: 1024, .. }));
    assert!(matches!(kinds[5], TokenKind::RParen));
}

#[test]
fn hex_e_wide_detectado() {
    let toks = tokenize_line(1, "mov rax, 0xDEADBEEFCAFEBABE").unwrap();
    let num = toks
        .iter()
        .find_map(|t| match &t.kind {
            TokenKind::Number { value, wide } => Some((*value, *wide)),
            _ => None,
        })
        .expect("precisa de numero");
    assert_eq!(num.0, 0xDEADBEEFCAFEBABE);
    assert!(num.1, "immediate deve ser marcado wide (>32b)");
}

#[test]
fn pascal_hex_dollar() {
    let toks = tokenize_line(1, "db $DEADBEEF").unwrap();
    let num = toks.iter().find_map(|t| match &t.kind {
        TokenKind::Number { value, .. } => Some(*value),
        _ => None,
    });
    assert_eq!(num, Some(0xDEADBEEF));
}

#[test]
fn string_literal() {
    let toks = tokenize_line(1, "aobscanmodule(sym, game.exe, 48 8B 05)").unwrap();
    assert!(toks.iter().any(|t| matches!(&t.kind, TokenKind::Ident(s) if s == "aobscanmodule")));
}

#[test]
fn erro_sintaxe_reporta_linha_coluna() {
    let err = tokenize_line(42, "mov rax, #inv").unwrap_err();
    assert_eq!(err.span.line, 42);
}
