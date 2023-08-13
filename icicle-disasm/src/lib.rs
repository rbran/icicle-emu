use std::collections::HashMap;
use std::collections::HashSet;

use pcode::VarNode;
use sleigh_runtime::Decoder;
use sleigh_runtime::Lifter;
use sleigh_runtime::SleighData;

use sleigh_parse::{ast, Input, Parser};

#[derive(Debug, serde::Deserialize)]
struct Set {
    pub name: String,
    pub val: u64,
}

#[allow(unused)]
#[derive(Debug, serde::Deserialize)]
struct ProgramCounter {
    register: String,
}

#[allow(unused)]
#[derive(Debug, serde::Deserialize)]
struct ContextSet {
    pub space: String,
    #[serde(rename = "$value")]
    pub set: Vec<Set>,
}

#[allow(unused)]
#[derive(Debug, serde::Deserialize)]
struct ContextData {
    context_set: ContextSet,
    #[serde(skip)]
    tracked_set: Vec<()>,
}

/// A SLEIGH processor specification file
#[derive(Debug, serde::Deserialize)]
struct PSpec {
    #[allow(unused)]
    #[serde(skip)]
    properties: Vec<()>,
    #[allow(unused)]
    programcounter: ProgramCounter,
    context_data: ContextData,
    #[allow(unused)]
    #[serde(skip)]
    register_data: Vec<()>,
}
extern crate embeddir;

use once_cell::sync::Lazy;

const DIR: Lazy<&HashMap<&str, &[u8]>> =
    Lazy::new(|| Box::leak(Box::new(embeddir::embed!("languages"))));

pub struct Insn {
    pub string: String,
    pub inputs: HashSet<VarNode>,
    pub outputs: HashSet<VarNode>,
    pub insn: sleigh_runtime::Instruction,
    pub pcode: Vec<pcode::Instruction>,
    pub load: bool,
    pub store: bool,
}
pub struct Disassembler {
    sleigh: SleighData,
    decoder: Decoder,
    lifter: Lifter,
}

impl Disassembler {
    pub fn new() -> Self {
        struct EmbeddedInput<'a> {
            files: &'a HashMap<&'a str, &'a [u8]>,
        }
        let input = EmbeddedInput { files: &DIR };
        impl<'a> Input for EmbeddedInput<'a> {
            fn open(&mut self, name: &str) -> std::io::Result<String> {
                Ok(std::str::from_utf8(self.files[name]).unwrap().to_owned())
            }
        }
        let mut parser = Parser::new(input);
        parser.include_file("x86-64.slaspec");

        //let sleigh: SleighData = sleigh_compile::from_path("/Users/jrmuizel/src/ghidra/Ghidra/Processors/x86/data/languages/x86-64.slaspec").unwrap();
        let sleigh: SleighData = sleigh_compile::build_inner(parser, false).unwrap();

        //let ctx = &mut config.context;

        //if let Some(pspec_path) = config.processor_spec_path {
        let pspec: PSpec = serde_xml_rs::from_reader(DIR["x86-64.pspec"]).unwrap();
        //.map_err(|e| BuildError::FailedToParsePspec(e.to_string()))?;

        let mut initial_ctx = 0_u64;
        for entry in &pspec.context_data.context_set.set {
            let field = sleigh.get_context_field(&entry.name).unwrap();

            field.field.set(&mut initial_ctx, entry.val as i64);
        }
        //ctx.push(initial_ctx);
        //}
        let mut decoder = Decoder::new();
        decoder.global_context = initial_ctx;

        for r in &sleigh.named_registers {

            //dbg!(r.var, sleigh.get_str(r.name));
        }

        let mut lifter = sleigh_runtime::Lifter::new();
        Disassembler { sleigh, decoder, lifter }
    }

    pub fn decode(&mut self, base_addr: u64, bytes: &[u8]) -> Insn {
        let mut d = self;

        //d.decoder.set_inst(0, &[0x4c, 0x85, 0x7d, 0x30]);
        //decoder.set_inst(0, &[0x90]);
        //d.decoder.set_inst(0, &[0x49, 0x89, 0xe5]);
        //d.decoder.set_inst(0, &[0x55]);
        d.decoder.set_inst(base_addr, bytes);
        let insn = d.sleigh.decode(&mut d.decoder).unwrap();

        let str = d.sleigh.disasm(&insn);
        let pcode = d.lifter.lift(&d.sleigh, &insn).unwrap();
        let mut input_regs = HashSet::new();
        let mut output_regs = Vec::new();
        let mut load = false;
        let mut store = false;
        for insn in &pcode.instructions {
            match insn.op {
                pcode::Op::Load(_) => load = true,
                pcode::Op::Store(_) => store = true,
                _ => {}
            }
            //dbg!(insn);
            //dbg!(insn.inputs.first());
            match insn.inputs.first() {
                pcode::Value::Var(var) => {
                    for r in &d.sleigh.named_registers {
                        if var == r.var {
                            //println!("{}", d.sleigh.get_str(r.name));
                            //input_regs.insert(d.sleigh.get_str(r.name).to_owned());
                            input_regs.insert(var);
                        }
                    }
                }
                pcode::Value::Const(_, _) => {}
            }
            //dbg!(insn.inputs.second());
            match insn.inputs.second() {
                pcode::Value::Var(var) => {
                    for r in &d.sleigh.named_registers {
                        if var == r.var {
                            //println!("{}", d.sleigh.get_str(r.name));
                            //input_regs.insert(d.sleigh.get_str(r.name).to_owned());
                            input_regs.insert(var);
                        }
                    }
                }
                pcode::Value::Const(_, _) => {}
            }
            //dbg!(insn.output);
            for r in &d.sleigh.named_registers {
                if insn.output == r.var {
                    //println!("{}", d.sleigh.get_str(r.name));
                    //output_regs.push(d.sleigh.get_str(r.name).to_owned());
                    output_regs.push(insn.output)
                }
            }
        }

        Insn {
            string: str.unwrap(),
            inputs: input_regs.to_owned(),
            outputs: output_regs.into_iter().collect(),
            insn,
            pcode: pcode.instructions.clone(),
            load,
            store,
        }
    }
}
