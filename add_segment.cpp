#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <algorithm>
#include <lief/LIEF.hpp>

static constexpr uint64_t PAGE_ALIGN = 0x1000;

uint64_t align_up(uint64_t value, uint64_t align) {
    return (value + align - 1) & ~(align - 1);
}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <elf_file>" << std::endl;
        return 1;
    }

    std::string in_dir        = "test_ELF_file/";
    std::string file_name     = argv[1];
    std::string safe_func_so  = "safe_func.so";
    std::string out_path      = "combined/" + file_name;

    auto main_bin = LIEF::ELF::Parser::parse(in_dir + file_name);
    auto hook_bin = LIEF::ELF::Parser::parse(safe_func_so);
    if (!main_bin || !hook_bin) {
        std::cerr << "ELF parse failed\n";
        return 1;
    }

    // 1) find end of existing LOAD segments in main
    uint64_t max_file_off = 0;
    uint64_t max_vaddr    = 0;
    for (auto& seg : main_bin->segments()) {
        if (seg.type() == LIEF::ELF::Segment::TYPE::LOAD) {
            max_file_off = std::max(max_file_off, seg.file_offset() + seg.physical_size());
            max_vaddr    = std::max(max_vaddr,    seg.virtual_address() + seg.virtual_size());
        }
    }
    max_file_off = align_up(max_file_off, PAGE_ALIGN);
    max_vaddr    = align_up(max_vaddr,    PAGE_ALIGN);

    // 2) merge each LOAD from hook, relocating to new region
    for (auto& seg_src : hook_bin->segments()) {
        if (seg_src.type() != LIEF::ELF::Segment::TYPE::LOAD) continue;

        // copy metadata
        LIEF::ELF::Segment new_seg = seg_src;
        // assign into free file & memory region
        new_seg.file_offset(max_file_off);
        new_seg.virtual_address(max_vaddr);
        new_seg.physical_size(seg_src.physical_size());
        new_seg.virtual_size(seg_src.virtual_size());
        new_seg.alignment(PAGE_ALIGN);
        // force R|X
        new_seg.add(LIEF::ELF::Segment::FLAGS::R);
        new_seg.add(LIEF::ELF::Segment::FLAGS::X);
        // copy content bytes
        auto span = seg_src.content();
        std::vector<uint8_t> data(span.begin(), span.end());
        new_seg.content(data);

        // add and bump offsets for next segment
        main_bin->add(new_seg);
        max_file_off += align_up(seg_src.physical_size(), PAGE_ALIGN);
        max_vaddr    += align_up(seg_src.virtual_size(), PAGE_ALIGN);
    }

    // 3) copy symtab/reloc sections as before...
    std::set<std::string> sym_secs = {".dynsym", ".dynstr", ".symtab", ".strtab"};
    for (auto& sec : hook_bin->sections()) {
        if (sym_secs.count(sec.name()) && main_bin->get_section(sec.name()) == nullptr) {
            main_bin->add(sec);
        }
    }

    std::vector<std::string> rel_secs = {".rela.plt", ".rela.dyn"};
    for (auto& sec : hook_bin->sections()) {
        if (std::find(rel_secs.begin(), rel_secs.end(), sec.name()) != rel_secs.end()
         && main_bin->get_section(sec.name()) == nullptr) {
            main_bin->add(sec);
        }
    }

    // 4) write output
    main_bin->write(out_path);
    std::cout << "Combined ELF written to " << out_path << "\n";
    std::cout << "Check readelf -l " << out_path << std::endl;
    return 0;
}
