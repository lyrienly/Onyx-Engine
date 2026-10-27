# Diretrizes de Contribuicao e Engenharia de Software

OnyxEngine adota um modelo de engenharia rigoroso para garantir a estabilidade de sua arquitetura hibrida (Kernel C, Rust nativo e Free Pascal/Lazarus). Todos os colaboradores devem observar estritamente as diretrizes contidas neste documento.

---

## 1. Rastreamento e Escopo via Issues

1. **Politica de Zero Codigo sem Issue:** Nenhuma alteracao, correcao ou nova funcionalidade deve ser codificada ou submetida sem uma Issue formal aberta previamente.
2. **Atribuicao de Tarefas:** Antes de iniciar a implementacao, comente na issue correspondente indicando o inicio dos trabalhos para evitar esforco redundante.
3. **Novas Propostas:** Identificou um bug ou oportunidade de melhoria? Abra uma issue detalhando o comportamento observado, a analise tecnica e o plano de resolucao antes de submeter qualquer codigo.

---

## 2. Obrigacao de Manutencao de Workflows e Builds

1. **Workflows e Integracao:** E dever de todo desenvolvedor garantir que todas as automacoes, pipelines de CI e rotinas de compilacao permaneçam plenamente operacionais.
2. **Verificacao Local Obrigatoria:** Antes de enviar commits ou abrir Pull Requests:
   * **Backend Rust:** `cargo check --workspace` e `cargo test --workspace` devem passar sem erros ou advertencias.
   * **Frontend Pascal:** A compilacao via `lazbuild` deve concluir com codigo de saida 0.
3. **Isolamento de Artefatos Binarios:** A pasta `bin/` e mantida fora do controle de versao Git (`.gitignore`). Nenhum binario compilado localmente deve ser adicionado ao repositorio. Distribuicoes executaveis sao publicadas exclusivamente atraves de releases estaveis.
4. **Criterio de Rejeicao:** PRs que quebrem fluxos de integracao, falhem na compilacao ou violem o escopo da issue serao rejeitados.

---

## 3. Topologia e Convencao de Branches

A branch `main` e protegida e contem exclusivamente codigo estavel e homologado.

1. Commits diretos na `main` sao estritamente bloqueados.
2. Cada demanda deve ser desenvolvida em uma branch dedicada a partir da `main` atualizada:
   * `feat/issue-ID-descricao` para implementacao de funcionalidades.
   * `fix/issue-ID-descricao` para correcoes de bugs.
   * `refactor/issue-ID-descricao` para reestruturacoes de codigo.
   * `docs/issue-ID-descricao` para manutencao documental.

Exemplo:
```bash
git checkout main
git pull origin main
git checkout -b fix/issue-2-driver-secureboot
```

---

## 4. Ciclo de Desenvolvimento e Submissao

1. **Desenvolvimento e Testes:** Itere no codigo e valide localmente os componentes afetados.
2. **Envio da Branch Remota:**
   ```bash
   git add <arquivos-alterados>
   git commit -m "tipo: descricao sucinta da modificacao (#ID)"
   git push origin fix/issue-2-driver-secureboot
   ```
3. **Abertura do Pull Request:**
   * Configure o destino do PR para a branch `main`.
   * Referencie a issue no corpo do PR utilizando a sintaxe de fechamento automatico (ex: `Closes #2` ou `Fixes #2`).
   * Descreva de forma objetiva o que foi alterado e como os testes foram conduzidos.

---

## 5. Revisao de Codigo e Aprovacao

* Todos os Pull Requests passam por revisao obrigatoria de codigo (Code Review) conduzida pelo mantenedor principal (**ErlonLy**).
* Ajustes arquiteturais, estaticos ou de desempenho podem ser solicitados durante a revisao.
* Apenas apos a aprovacao expressa do mantenedor e validacao de testes, o merge sera efetuado na branch `main`.
