#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cstring>
#include <lief/LIEF.hpp>

static constexpr uint64_t PAGE_ALIGN = 0x1000;

uint64_t align_up(uint64_t value, uint64_t align) {
    return (value + align - 1) & ~(align - 1);
}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <elf_file>\n";
        return 1;
    }

    std::string in_dir = "test_ELF_file/";
    std::string file_name = argv[1];
    std::string safe_func_so = "safe_func.so";
    std::string out_path = "combined/" + file_name;

    auto main_bin = LIEF::ELF::Parser::parse(in_dir + file_name);
    auto hook_bin = LIEF::ELF::Parser::parse(safe_func_so);
    
    if (!main_bin || !hook_bin) {
        std::cerr << "ELF parse failed\n";
        return 1;
    }

    std::cout << "Parsing successful\n";

    // 기존 LOAD 세그먼트 끝 위치 찾기
    uint64_t max_file_off = 0;
    uint64_t max_vaddr = 0;
    
    for (auto& seg : main_bin->segments()) {
        if (seg.type() == LIEF::ELF::Segment::TYPE::LOAD) {
            uint64_t file_end = seg.file_offset() + seg.physical_size();
            uint64_t vaddr_end = seg.virtual_address() + seg.virtual_size();
            max_file_off = std::max<uint64_t>(max_file_off, file_end);
            max_vaddr = std::max<uint64_t>(max_vaddr, vaddr_end);
            std::cout << "Existing LOAD segment: VA=0x" << std::hex << seg.virtual_address()
                      << " FileEnd=0x" << file_end
                      << " VirtEnd=0x" << vaddr_end << std::dec << "\n";
        }
    }
    
    max_file_off = align_up(max_file_off, PAGE_ALIGN);
    max_vaddr = align_up(max_vaddr, PAGE_ALIGN);

    std::cout << "New segments will start at VA: 0x" << std::hex << max_vaddr 
              << " FileOff: 0x" << max_file_off << std::dec << "\n";

    // safe_func.so의 모든 LOAD 세그먼트(코드, rodata 등)를 복사
    bool any_added = false;
    uint64_t next_file_off = max_file_off;
    uint64_t next_vaddr = max_vaddr;

    // 매핑: 원본 세그먼트 VA -> 추가된 세그먼트의 가상 주소 (base)
    std::vector<std::pair<uint64_t, LIEF::ELF::Segment>> added_segments_info;

    for (auto& seg_src : hook_bin->segments()) {
        if (seg_src.type() != LIEF::ELF::Segment::TYPE::LOAD) continue;

        // Align file_off and vaddr for each new segment
        next_file_off = align_up(next_file_off, PAGE_ALIGN);
        next_vaddr = align_up(next_vaddr, PAGE_ALIGN);

        LIEF::ELF::Segment new_seg;
        new_seg.type(LIEF::ELF::Segment::TYPE::LOAD);

        // copy flags from src
        // seg_src.flags() returns a bitset-like value; use add for each flag present
        if (seg_src.has(LIEF::ELF::Segment::FLAGS::R)) new_seg.add(LIEF::ELF::Segment::FLAGS::R);
        if (seg_src.has(LIEF::ELF::Segment::FLAGS::W)) new_seg.add(LIEF::ELF::Segment::FLAGS::W);
        if (seg_src.has(LIEF::ELF::Segment::FLAGS::X)) new_seg.add(LIEF::ELF::Segment::FLAGS::X);

        // Set addresses & sizes
        new_seg.file_offset(next_file_off);
        new_seg.virtual_address(next_vaddr);
        new_seg.physical_address(next_vaddr); // p_paddr rarely used; set to vaddr for simplicity

        uint64_t src_phys = seg_src.physical_size();
        uint64_t src_virt = seg_src.virtual_size();
        uint64_t use_vsize = (src_virt && src_virt > 0) ? src_virt : src_phys;
        new_seg.physical_size(src_phys);
        new_seg.virtual_size(use_vsize);
        new_seg.alignment(PAGE_ALIGN);

        // Copy content and pad to virtual_size (so the file will contain code/data; bss-like zeros handled)
        auto content = seg_src.content();
        std::vector<uint8_t> data;
        if (!content.empty()) {
            data.assign(content.begin(), content.end());
        }
        // pad to physical_size in file if needed
        if (data.size() < src_phys) {
            data.resize(src_phys, 0);
        }
        // ensure that data length is at most physical_size (file size)
        if (data.size() > src_phys) {
            data.resize(src_phys);
        }

        new_seg.content(data);

        // Add the new segment
        try {
            main_bin->add(new_seg);
            any_added = true;
            std::cout << "[+] Added segment from safe: orig_base=0x" << std::hex << seg_src.virtual_address()
                      << " -> added_base=0x" << next_vaddr
                      << " phys_size=0x" << src_phys
                      << " virt_size=0x" << use_vsize << std::dec << "\n";

            // store mapping info: original base -> added segment (we will search added segments by base)
            added_segments_info.emplace_back(seg_src.virtual_address(), new_seg);

            // advance file_off/vaddr for next seg
            // increment by aligned physical_size
            next_file_off += align_up(src_phys, PAGE_ALIGN);
            next_vaddr += align_up(use_vsize, PAGE_ALIGN);

        } catch (const std::exception& e) {
            std::cerr << "[!] Failed to add segment: " << e.what() << "\n";
            return 1;
        }
    }

    if (!any_added) {
        std::cerr << "No LOAD segments found in safe_func.so to add\n";
        return 1;
    }

    // ===== 심볼 복사 (주소 재계산 및 symtab/dynsym에 추가) =====
    std::cout << "\n=== Copying symbols from safe_func.so ===\n";
    uint64_t symbol_count = 0;

    // Determine hook base(s): for each source LOAD seg we noted seg_src.virtual_address
    // We'll map symbol.value() -> correct added base by finding which original seg contains it.
    for (const auto& symbol : hook_bin->symbols()) {
        const std::string& name = symbol.name();
        if (name.empty()) continue;
        // only copy symbols that look like your safe wrappers (prefix "my_")
        if (name.rfind("my_", 0) != 0) continue;

        uint64_t sym_val = symbol.value();
        // find which original segment contains this symbol
        bool placed = false;
        for (const auto& pair : added_segments_info) {
            uint64_t orig_base = pair.first;
            const LIEF::ELF::Segment& added_seg = pair.second;
            // we used src.virtual_size earlier as mapping range
            // For safety, allow symbol to be within [orig_base, orig_base + virtual_size)
            // Need to fetch corresponding source seg virtual_size from hook_bin: find seg with virtual_address == orig_base
            auto src_seg_opt = std::find_if(hook_bin->segments().begin(), hook_bin->segments().end(),
                [&](const LIEF::ELF::Segment& s){ return s.virtual_address() == orig_base; });
            if (src_seg_opt == hook_bin->segments().end()) continue;
            uint64_t src_vsize = src_seg_opt->virtual_size() ? src_seg_opt->virtual_size() : src_seg_opt->physical_size();
            uint64_t src_end = orig_base + src_vsize;
            if (sym_val >= orig_base && sym_val < src_end) {
                // new address = added_base + offset
                uint64_t offset = sym_val - orig_base;
                uint64_t new_addr = added_seg.virtual_address() + offset;

                try {
                    // Try adding to symtab
                    auto new_sym = main_bin->add_symtab_symbol(symbol);
                    new_sym.value(new_addr);

                    // Optionally ensure binding/type remain GLOBAL/FUNC
                    // new_sym.binding(symbol.binding());
                    // new_sym.type(symbol.type());

                    std::cout << "[+] Added symbol " << name << " -> 0x" << std::hex << new_addr << std::dec << "\n";
                    symbol_count++;
                    placed = true;
                } catch (const std::exception& e) {
                    std::cerr << "[!] add_symtab_symbol failed for " << name << ": " << e.what() << "\n";
                    // fallback: try add_dynamic_symbol
                    try {
                        auto new_dyn = main_bin->add_dynamic_symbol(symbol);
                        new_dyn.value(new_addr);
                        std::cout << "[+] (dyn) Added symbol " << name << " -> 0x" << std::hex << new_addr << std::dec << "\n";
                        symbol_count++;
                        placed = true;
                    } catch (const std::exception& e2) {
                        std::cerr << "[!] add_dynamic_symbol also failed for " << name << ": " << e2.what() << "\n";
                    }
                }

                break; // symbol placed
            }
        }

        if (!placed) {
            std::cerr << "[!] Could not place symbol " << name << " (value 0x" << std::hex << sym_val << std::dec << ")\n";
        }
    }

    std::cout << "Total symbols processed: " << symbol_count << "\n\n";

    // 파일 쓰기
    try {
        main_bin->write(out_path);
        std::cout << "[SUCCESS] Combined ELF written to " << out_path << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Write failed: " << e.what() << "\n";
        return 1;
    }

    // 검증 출력
    auto verify = LIEF::ELF::Parser::parse(out_path);
    if (verify) {
        std::cout << "\nVerification Results:\n";
        std::cout << "Total segments: " << verify->segments().size() << "\n";
        for (auto& seg : verify->segments()) {
            if (seg.type() == LIEF::ELF::Segment::TYPE::LOAD) {
                std::cout << "LOAD segment: VA=0x" << std::hex << seg.virtual_address()
                          << " PhysSize=0x" << seg.physical_size()
                          << " VirtSize=0x" << seg.virtual_size() << std::dec;
                if (seg.has(LIEF::ELF::Segment::FLAGS::X)) std::cout << " [EXECUTABLE]";
                if (seg.has(LIEF::ELF::Segment::FLAGS::W)) std::cout << " [WRITE]";
                std::cout << "\n";
            }
        }

        std::cout << "\nCustom symbols in output:\n";
        for (const auto& sym : verify->symbols()) {
            if (sym.name().rfind("my_", 0) == 0) {
                std::cout << "  " << sym.name() << ": 0x" << std::hex << sym.value() << std::dec << "\n";
            }
        }
    }

    std::cout << "\nNext step: Check with 'readelf -l " << out_path << "' and 'nm " << out_path << " | grep my_'\n";
    return 0;
}
