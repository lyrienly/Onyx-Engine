# Documentação Técnica Oficial do OnyxEngine

## Visão Geral

O OnyxEngine é uma plataforma modular de engenharia reversa, análise de memória em tempo de execução e inspeção dinâmica de processos x86_64 baseada em Windows. O projeto combina um ecossistema nativo de alta performance escrito em Rust (Core, Backend C-ABI, Módulos Dinâmicos, Injeções e Plugins), uma interface de usuário construída em Lazarus/Free Pascal integrada via C-ABI de baixa sobrecarga e um driver de kernel Ring-0 (`OwMemDriver.sys`) desenvolvido em C e Assembly para operações físicas de memória, controle de tabelas de paginação (CR3) e bypass de proteções a nível de sistema operacional.

Esta documentação detalha a arquitetura do sistema, o funcionamento dos subsistemas e o catálogo exaustivo de tratamento de erros com diagnósticos em Português (PT-BR).

## Estrutura da Documentação

A documentação está dividida nos seguintes módulos técnicos:

1. [Arquitetura Geral e Topologia de Binários](ARCHITECTURE.md)
   - Layout do workspace Cargo e modelo de distribuição modular em 24 bibliotecas dinâmicas (DLLs).
   - Fluxo de dados entre Frontend Pascal, Backend Rust e Ring-0 Kernel Driver.
   - Padrões de segurança operacional e isolamento de processos.

2. [Catálogo e Sistema Unificado de Erros](ERROR_SYSTEM.md)
   - Arquitetura de captura contextual (`OnyxError`), códigos padronizados (`OnyxErrorCode`) e armazenamento thread-local.
   - Especificação exaustiva de cada erro de 0 a 7099, descrevendo causa raiz, impacto operacional, diagnóstico em PT-BR e resolução recomendada.

3. [Subsistemas Técnicos e Engenharia de Módulos](SUBSYSTEMS.md)
   - Detalhamento de cada crate, módulo de injeção, hook engine e plugin do ecossistema.
   - Funcionamento de varredura multi-thread, resolução de cadeias de ponteiros, depurador VEH/PageGuard, e evasão anticheat.

4. [Compilação, Pipeline e Desdobramento (DevSecOps)](BUILD_AND_DEPLOY.md)
   - Pré-requisitos de compilação (Rust Toolchain, MSVC, WDK, Lazarus).
   - Scripts de automação de build e distribuição de artefatos.
   - Práticas de validação e testes automatizados.
