#include <iostream>
#include <string>
#include <vector>
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

    // 1) 기존 LOAD 세그먼트 끝 위치 찾기
    uint64_t max_file_off = 0;
    uint64_t max_vaddr = 0;
    
    for (auto& seg : main_bin->segments()) {
        if (seg.type() == LIEF::ELF::Segment::TYPE::LOAD) {
            max_file_off = std::max(max_file_off, seg.file_offset() + seg.physical_size());
            max_vaddr = std::max(max_vaddr, seg.virtual_address() + seg.virtual_size());
            std::cout << "Existing LOAD segment: VA=0x" << std::hex << seg.virtual_address() 
                      << " Size=0x" << seg.physical_size() << std::dec << "\n";
        }
    }
    
    max_file_off = align_up(max_file_off, PAGE_ALIGN);
    max_vaddr = align_up(max_vaddr, PAGE_ALIGN);

    std::cout << "New segment will start at VA: 0x" << std::hex << max_vaddr 
              << " FileOff: 0x" << max_file_off << std::dec << "\n";

    // 2) safe_func.so의 첫 번째 실행 세그먼트 복사 (수정된 부분)
    bool segment_added = false;
    
    for (auto& seg_src : hook_bin->segments()) {
        if (seg_src.type() != LIEF::ELF::Segment::TYPE::LOAD) continue;
        if (!seg_src.has(LIEF::ELF::Segment::FLAGS::X)) continue; // 실행 가능한 것만

        std::cout << "Found source segment: VA=0x" << std::hex << seg_src.virtual_address() 
                  << " PhysSize=0x" << seg_src.physical_size() 
                  << " VirtSize=0x" << seg_src.virtual_size() << std::dec << "\n";

        // 핵심 수정: 새 세그먼트 생성 시 크기 정보 명시적 설정
        LIEF::ELF::Segment new_seg;
        new_seg.type(LIEF::ELF::Segment::TYPE::LOAD);
        
        // 권한 설정
        new_seg.add(LIEF::ELF::Segment::FLAGS::R);
        new_seg.add(LIEF::ELF::Segment::FLAGS::X);
        
        // 위치 및 크기 설정 (명시적)
        new_seg.file_offset(max_file_off);
        new_seg.virtual_address(max_vaddr);
        new_seg.physical_address(max_vaddr);
        new_seg.physical_size(seg_src.physical_size());  // 핵심: 크기 명시적 설정
        new_seg.virtual_size(seg_src.virtual_size());    // 핵심: 크기 명시적 설정
        new_seg.alignment(PAGE_ALIGN);
        
        // 핵심 수정: 내용 복사를 명시적으로 수행
        auto content = seg_src.content();
        if (content.size() > 0) {
            std::vector<uint8_t> data(content.begin(), content.end());
            new_seg.content(data);
            std::cout << "Copied content: " << data.size() << " bytes\n";
        } else {
            std::cerr << "[!] Warning: No content to copy from source segment\n";
        }

        try {
            main_bin->add(new_seg);
            segment_added = true;
            std::cout << "Successfully added segment:\n";
            std::cout << "  VA: 0x" << std::hex << max_vaddr << std::dec << "\n";
            std::cout << "  Physical Size: " << seg_src.physical_size() << " bytes\n";
            std::cout << "  Virtual Size: " << seg_src.virtual_size() << " bytes\n";
        } catch (const std::exception& e) {
            std::cerr << "Failed to add segment: " << e.what() << "\n";
            return 1;
        }
        
        break; // 첫 번째 실행 세그먼트만 추가
    }

    if (!segment_added) {
        std::cerr << "No executable segment found in safe_func.so\n";
        return 1;
    }

    // 3) 안전한 파일 쓰기
    try {
        main_bin->write(out_path);
        std::cout << "\n[SUCCESS] Combined ELF written to " << out_path << "\n";
        
        // 4) 검증: 결과 파일 다시 파싱해서 확인
        auto verify = LIEF::ELF::Parser::parse(out_path);
        if (verify) {
            std::cout << "\nVerification Results:\n";
            std::cout << "Total segments: " << verify->segments().size() << "\n";
            
            // LOAD 세그먼트들 확인
            for (auto& seg : verify->segments()) {
                if (seg.type() == LIEF::ELF::Segment::TYPE::LOAD) {
                    std::cout << "LOAD segment: VA=0x" << std::hex << seg.virtual_address() 
                              << " PhysSize=0x" << seg.physical_size() 
                              << " VirtSize=0x" << seg.virtual_size() << std::dec;
                    if (seg.has(LIEF::ELF::Segment::FLAGS::X)) {
                        std::cout << " [EXECUTABLE]";
                    }
                    std::cout << "\n";
                }
            }
        } else {
            std::cerr << "[!] Verification failed: Cannot parse output file\n";
            return 1;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Write failed: " << e.what() << "\n";
        return 1;
    }

    std::cout << "\nNext step: Check with 'readelf -l " << out_path << "'\n";
    return 0;
}
