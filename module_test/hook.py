import lief

# 크랙미와 훅 바이너리 파싱
crackme = lief.parse("crackme.bin")
hook = lief.parse("hook")

# 훅의 첫 번째 세그먼트를 크랙미에 추가
segment_added = crackme.add(hook.segments[0])

# 훅에서 my_memcmp 함수 심볼 찾기
my_memcmp = hook.get_symbol("my_memcmp")

# my_memcmp 함수의 가상 주소 계산
my_memcmp_addr = segment_added.virtual_address + my_memcmp.value

# memcmp PLT/GOT 엔트리를 our hook으로 패치
crackme.patch_pltgot('memcmp', my_memcmp_addr)

# 수정된 바이너리 저장
crackme.write("crackme.hooked")
