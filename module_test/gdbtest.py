from pwn import *
import threading
import lief
import time

def run_program():
    p = process('safe_func')

    def auto_input():
        while True:
            try:
                data = p.recv(timeout=1)
                if data:
                    log.info(f"Received: {data.decode(errors='ignore')}")
                    # 입력 대기 상태가 맞으면 입력 자동 주입
                    p.sendline(b'AA')  # bytes 형태로 보냄
                else:
                    pass  # 출력 없으면 계속 대기
            except EOFError:
                log.info("Process EOF reached. Exiting input thread.")
                break
            except Exception as e:
                log.warning(f"Exception in auto_input: {e}")
                break

    input_thread = threading.Thread(target=auto_input, daemon=True)
    input_thread.start()

    # 프로세스와 상호 작용 유지 (프로세스 계속 유지)
    p.interactive()

def run_lief_analysis():
    # patch 작업 예시
    print("hit lief")
    binary_path = 'safe_func'   
    binary = lief.parse(binary_path)
    
    # 여기서 patch 작업을 수행
    # 예: 원하는 심볼 확인, PLT/GOT 주소 확인, 심볼 등록 등

    print("[*] lief patch 작업 완료")

if __name__ == "__main__":
    # 1) pwntools로 바이너리 실행 및 입력 자동화 작업을 별도 스레드로 실행
    prog_thread = threading.Thread(target=run_program)
    prog_thread.start()

    # 2) 프로세스가 메모리에 올라갈 시간 대기 (필요시 조절)
    time.sleep(2)

    # 3) patch 작업 실행 (메인 스레드 또는 별도 스레드로도 가능)
    run_lief_analysis()

    # 4) pwntools 프로세스 유지 및 키보드 인터랙션 가능하도록 대기
    prog_thread.join()
