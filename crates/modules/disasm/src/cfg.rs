use crate::zydis_backend::{FlowType, Instruction};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub entry: u64,
    pub end: u64,
    pub instructions: Vec<Instruction>,
    pub successors: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    pub entry: u64,
    pub blocks: BTreeMap<u64, BasicBlock>,
}

pub fn build_cfg(instructions: &[Instruction]) -> ControlFlowGraph {
    if instructions.is_empty() {
        return ControlFlowGraph { entry: 0, blocks: BTreeMap::new() };
    }

    let entry = instructions[0].address;
    let addr_set: BTreeSet<u64> = instructions.iter().map(|i| i.address).collect();

    let mut leaders: BTreeSet<u64> = BTreeSet::new();
    leaders.insert(entry);

    for (idx, insn) in instructions.iter().enumerate() {
        match insn.flow_type {
            FlowType::ConditionalJump
            | FlowType::UnconditionalJump
            | FlowType::Call
            | FlowType::Return
            | FlowType::Int => {
                if let Some(next) = instructions.get(idx + 1) {
                    leaders.insert(next.address);
                }
                if let Some(target) = insn.branch_target {
                    if addr_set.contains(&target) {
                        leaders.insert(target);
                    }
                }
            }
            FlowType::Sequential => {}
        }
    }

    let mut blocks: BTreeMap<u64, BasicBlock> = BTreeMap::new();
    let mut current: Option<BasicBlock> = None;

    for (idx, insn) in instructions.iter().enumerate() {
        if leaders.contains(&insn.address) {
            if let Some(block) = current.take() {
                blocks.insert(block.entry, block);
            }
            current = Some(BasicBlock {
                entry: insn.address,
                end: insn.address,
                instructions: Vec::new(),
                successors: Vec::new(),
            });
        }

        if let Some(block) = current.as_mut() {
            block.instructions.push(insn.clone());
            block.end = insn.address + insn.length as u64;
        }

        let next_addr = instructions.get(idx + 1).map(|n| n.address);
        let terminator = match insn.flow_type {
            FlowType::ConditionalJump
            | FlowType::UnconditionalJump
            | FlowType::Call
            | FlowType::Return
            | FlowType::Int => true,
            FlowType::Sequential => next_addr.map_or(false, |a| leaders.contains(&a)),
        };

        if terminator {
            if let Some(block) = current.as_mut() {
                match insn.flow_type {
                    FlowType::UnconditionalJump => {
                        if let Some(t) = insn.branch_target {
                            if addr_set.contains(&t) {
                                block.successors.push(t);
                            }
                        }
                    }
                    FlowType::ConditionalJump => {
                        if let Some(t) = insn.branch_target {
                            if addr_set.contains(&t) {
                                block.successors.push(t);
                            }
                        }
                        if let Some(next) = next_addr {
                            block.successors.push(next);
                        }
                    }
                    FlowType::Call => {

                        if let Some(next) = next_addr {
                            block.successors.push(next);
                        }
                    }
                    FlowType::Return | FlowType::Int => {}
                    FlowType::Sequential => {
                        if let Some(next) = next_addr {
                            block.successors.push(next);
                        }
                    }
                }
            }
            if let Some(block) = current.take() {
                blocks.insert(block.entry, block);
            }
        }
    }

    if let Some(block) = current.take() {
        blocks.insert(block.entry, block);
    }

    ControlFlowGraph { entry, blocks }
}

pub fn cfg_to_dot(cfg: &ControlFlowGraph) -> String {
    let mut s = String::new();
    s.push_str("digraph cfg {\n");
    s.push_str("    node [shape=box, fontname=\"Consolas\"];\n");
    s.push_str(&format!("    entry -> \"bb_{:X}\";\n", cfg.entry));

    for block in cfg.blocks.values() {
        let label_body: String = block
            .instructions
            .iter()
            .map(|i| {
                let line = format!("{:X}: {} {}", i.address, i.mnemonic, i.operands);
                escape_dot(line.trim())
            })
            .collect::<Vec<_>>()
            .join("\\l");
        s.push_str(&format!(
            "    \"bb_{:X}\" [label=\"{}\\l\"];\n",
            block.entry, label_body
        ));
        for succ in &block.successors {
            s.push_str(&format!(
                "    \"bb_{:X}\" -> \"bb_{:X}\";\n",
                block.entry, succ
            ));
        }
    }

    s.push_str("}\n");
    s
}

fn escape_dot(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
