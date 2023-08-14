use icicle_disasm::Disassembler;



fn main() {
    let mut d = Disassembler::new();
    let mut bytes = &[0x83, 0xc0, 0x01, 0x55, 0xc3, 0xf, 0x94, 0xc2,0xf, 0xb6, 0xd2][..];
    while !bytes.is_empty() {
        let insn = d.decode(0, &bytes);
        dbg!(&insn.inputs);
        dbg!(&insn.outputs);
        dbg!(insn.string);
        dbg!(insn.insn.num_bytes());
        dbg!(insn.pcode);
        bytes = &bytes[insn.insn.num_bytes() as usize ..]
    }
}
