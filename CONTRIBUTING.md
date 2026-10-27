# Diretrizes de Contribuição e Fluxo de Trabalho (Git Workflow)

Bem-vindo ao time de desenvolvimento do **OnyxEngine**. 

Para manter a estabilidade do motor em produção e evitar conflitos em uma stack híbrida complexa (Kernel C, Rust e Free Pascal/Lazarus), todos os colaboradores devem seguir estritamente o fluxo descrito abaixo.

---

## 1. Regra de Ouro: Sempre Siga as Issues

* **Nenhum código sobe sem uma Issue correspondente.**
* Antes de iniciar qualquer tarefa, verifique a aba de **Issues** no repositório.
* Caso identifique um bug ou queira sugerir uma melhoria que ainda não está documentada, **abra uma Issue primeiro** descrevendo o problema ou proposta antes de codificar.
* Marque a issue como sua ou comente que está trabalhando nela para evitar duplicação de esforço.

---

## 2. Política de Branches

A branch `main` é **protegida** e representa o código pronto e testado em produção.

1. **Nunca faça commits diretos na `main`:** Push direto para a branch `main` será bloqueado ou revertido.
2. **Crie uma branch específica para cada Issue:**
   * Padrão de nomenclatura:
     * `feat/issue-ID-descricao-curta` (para novas funcionalidades)
     * `fix/issue-ID-descricao-curta` (para correções de bugs)
     * `refactor/issue-ID-descricao-curta` (para refatorações de arquitetura)
     * `docs/issue-ID-descricao-curta` (para melhorias de documentação)
   * Exemplo: `git checkout -b fix/12-driver-secureboot-dse`

---

## 3. Passo a Passo do Fluxo de Trabalho

```text
[ Issue no GitHub ] 
        ↓
[ git checkout -b feat/xyz ] 
        ↓
[ Desenvolvimento + Testes Locais ]
        ↓
[ git push origin feat/xyz ] 
        ↓
[ Abrir Pull Request apontando para main ] 
        ↓
[ Code Review do Mantenedor (ErlonLy) ] 
        ↓
[ Aprovação e Merge para main ]
```

### Comandos Práticos:

1. **Atualize sua main local:**
   ```bash
   git checkout main
   git pull origin main
   ```

2. **Crie e alterne para sua branch de trabalho:**
   ```bash
   git checkout -b fix/issue-15-scanner-simd
   ```

3. **Desenvolva e valide localmente:**
   * Se alterou código em Rust: `cargo check --workspace` e `cargo test --workspace`
   * Se alterou código em Pascal: Compile via `lazbuild -B --build-mode=Release "cheat-engine/Cheat Engine/cheatengine.lpi"`
   * Garanta que todos os binários gerados residam em `bin/`.

4. **Envie sua branch para o repositório remoto:**
   ```bash
   git add .
   git commit -m "fix: resolve problema de alinhamento de memoria no scanner (#15)"
   git push origin fix/issue-15-scanner-simd
   ```

---

## 4. Como Abrir e Estruturar o Pull Request (PR)

1. Vá até o repositório no GitHub: `https://github.com/ErlonLy/OnyxEngine`.
2. O GitHub exibirá o botão **Compare & pull request** para sua branch recém-enviada.
3. No título do PR, use o padrão: `[Tipo]: Descrição curta (Fecha #ID)`.
   * Exemplo: `fix: resolver falha de carregamento do driver no Windows 10 (#4)`
4. Na descrição do PR, preencha:
   * **O que foi feito:** Resumo das alterações.
   * **Qual issue é resolvida:** Use palavras-chave automáticas como `Fixes #12` ou `Closes #12`.
   * **Como testar:** Passos detalhados para o mantenedor reproduzir e validar.

---

## 5. Processo de Revisão e Análise

* Todos os Pull Requests passarão por análise de código (Code Review) realizada pelo mantenedor principal (**ErlonLy**).
* Durante a revisão, podem ser solicitados ajustes de performance, formatação ou adequação de arquitetura.
* Uma vez aprovado nos testes e revisado, o PR será mergeado para a branch `main`.
