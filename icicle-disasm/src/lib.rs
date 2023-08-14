use pcode::VarNode;
use sleigh_runtime::{Decoder, Lifter, SleighData};

pub struct Insn {
    pub string: String,
    pub inputs: Vec<VarNode>,
    pub outputs: Vec<VarNode>,
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
        // parse the sleigh file into this SleighData and the default context
        // for this architecture
        let (sleigh, default_context) =
            icicle_vm::build_sleigh_for("x86_64".parse().unwrap()).unwrap();

        let mut decoder = Decoder::new();
        decoder.global_context = default_context;

        //for r in &sleigh.named_registers {
        //    dbg!(r.var, sleigh.get_str(r.name));
        //}

        let lifter = sleigh_runtime::Lifter::new();
        Disassembler { sleigh, decoder, lifter }
    }

    pub fn decode(&mut self, base_addr: u64, bytes: &[u8]) -> Insn {
        //self.decoder.set_inst(0, &[0x4c, 0x85, 0x7d, 0x30]);
        //decoder.set_inst(0, &[0x90]);
        //self.decoder.set_inst(0, &[0x49, 0x89, 0xe5]);
        //self.decoder.set_inst(0, &[0x55]);
        self.decoder.set_inst(base_addr, bytes);
        let insn = self.sleigh.decode(&mut self.decoder).unwrap();

        let str = self.sleigh.disasm(&insn);
        let pcode = self.lifter.lift(&self.sleigh, &insn).unwrap();
        let mut input_regs = Vec::new();
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
                    for r in &self.sleigh.named_registers {
                        if var == r.var {
                            //println!("{}", self.sleigh.get_str(r.name));
                            //input_regs.insert(self.sleigh.get_str(r.name).to_owned());
                            input_regs.push(var);
                        }
                    }
                }
                pcode::Value::Const(_, _) => {}
            }
            //dbg!(insn.inputs.second());
            match insn.inputs.second() {
                pcode::Value::Var(var) => {
                    for r in &self.sleigh.named_registers {
                        if var == r.var {
                            //println!("{}", self.sleigh.get_str(r.name));
                            //input_regs.insert(self.sleigh.get_str(r.name).to_owned());
                            input_regs.push(var);
                        }
                    }
                }
                pcode::Value::Const(_, _) => {}
            }
            //dbg!(insn.output);
            for r in &self.sleigh.named_registers {
                if insn.output == r.var {
                    //println!("{}", self.sleigh.get_str(r.name));
                    //output_regs.push(self.sleigh.get_str(r.name).to_owned());
                    output_regs.push(insn.output)
                }
            }
        }

        Insn {
            string: str.unwrap(),
            inputs: input_regs,
            outputs: output_regs,
            insn,
            pcode: pcode.instructions.clone(),
            load,
            store,
        }
    }
}
