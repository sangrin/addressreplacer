import os
import pymem
import time
import win32process
import ctypes
from ctypes import wintypes

EXE_PATH = r"C:\Seu\Caminho\Ragexe.exe"
IP = "172.65.x.x"
PORT = 6901

# Windows API constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD)
    ]

def find_string_in_memory(pm, target_string):
    """Encontra endereço de uma string na memória do processo"""
    kernel32 = ctypes.windll.kernel32
    handle = pm.process_handle
    
    address = 0
    while address < 0x7FFFFFFF:
        mbi = MEMORY_BASIC_INFORMATION()
        result = kernel32.VirtualQueryEx(
            handle,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi)
        )
        
        if result == 0:
            break
            
        # Verifica se os valores são válidos
        if (mbi.BaseAddress is None or mbi.RegionSize is None or 
            mbi.State != MEM_COMMIT or 
            mbi.Protect not in [PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE]):
            address = (mbi.BaseAddress or 0) + (mbi.RegionSize or 0x1000)
            continue
            
        try:
            # Lê a região em chunks
            chunk_size = 4096
            for offset in range(0, mbi.RegionSize, chunk_size):
                read_size = min(chunk_size, mbi.RegionSize - offset)
                
                buffer = ctypes.create_string_buffer(read_size)
                bytes_read = ctypes.c_size_t()
                
                if kernel32.ReadProcessMemory(
                    handle,
                    ctypes.c_void_p(mbi.BaseAddress + offset),
                    buffer,
                    read_size,
                    ctypes.byref(bytes_read)
                ):
                    data = buffer.raw[:bytes_read.value]
                    target_bytes = target_string.encode('utf-8')
                    
                    pos = data.find(target_bytes)
                    if pos != -1:
                        found_address = mbi.BaseAddress + offset + pos
                        print(f"Encontrado '{target_string}' em: 0x{found_address:08X}")
                        return found_address
                        
        except Exception:
            pass
            
        address = mbi.BaseAddress + mbi.RegionSize
    
    return None

def find_pointer_to_address(pm, target_address):
    """Encontra ponteiro que aponta para um endereço específico"""
    kernel32 = ctypes.windll.kernel32
    handle = pm.process_handle
    target_bytes = ctypes.c_uint32(target_address).value.to_bytes(4, 'little')
    
    address = 0
    while address < 0x7FFFFFFF:
        mbi = MEMORY_BASIC_INFORMATION()
        result = kernel32.VirtualQueryEx(
            handle,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi)
        )
        
        if result == 0:
            break
            
        # Verifica se os valores são válidos
        if (mbi.BaseAddress is None or mbi.RegionSize is None or 
            mbi.State != MEM_COMMIT or 
            mbi.Protect not in [PAGE_READWRITE, PAGE_EXECUTE_READWRITE]):
            address = (mbi.BaseAddress or 0) + (mbi.RegionSize or 0x1000)
            continue
            
        try:
            chunk_size = 4096
            for offset in range(0, mbi.RegionSize, chunk_size):
                read_size = min(chunk_size, mbi.RegionSize - offset)
                
                buffer = ctypes.create_string_buffer(read_size)
                bytes_read = ctypes.c_size_t()
                
                if kernel32.ReadProcessMemory(
                    handle,
                    ctypes.c_void_p(mbi.BaseAddress + offset),
                    buffer,
                    read_size,
                    ctypes.byref(bytes_read)
                ):
                    data = buffer.raw[:bytes_read.value]
                    
                    # Busca por ponteiros alinhados (4 bytes)
                    for i in range(0, len(data) - 3, 4):
                        if data[i:i+4] == target_bytes:
                            pointer_address = mbi.BaseAddress + offset + i
                            print(f"Ponteiro encontrado em: 0x{pointer_address:08X} -> 0x{target_address:08X}")
                            return pointer_address
                            
        except Exception:
            pass
            
        address = mbi.BaseAddress + mbi.RegionSize
    
    return None

def main():
    print("RAGEXE ADDRESS REPLACER")
    print("=" * 50)
    
    # 1- Abre o Rag
    print("Iniciando Ragnarok...")
    try:
        h_process, h_thread, pid, tid = win32process.CreateProcess(
            None,
            f"\"{EXE_PATH}\" 1rag1",
            None,
            None,
            False,
            0,
            None,
            os.path.dirname(EXE_PATH),
            win32process.STARTUPINFO()
        )
        
        pm = pymem.Pymem(pid)
        print(f"Processo iniciado! PID: {pid}")
        
        # Aguarda o processo carregar
        print("Aguardando processo carregar...")
        time.sleep(8)  # Aumentei para 8 segundos
        
    except Exception as e:
        print(f"Erro ao iniciar processo: {e}")
        return
    
    # Verifica se o processo ainda existe
    try:
        pm.read_bytes(pm.base_address, 4)
    except:
        print("Processo nao esta mais ativo")
        return
    
    print("\nAGUARDANDO TENTATIVA DE CONEXAO...")
    print("=" * 50)
    print()
    input("Pressione ENTER assim que começar a tentar conectar... ")
    
    # 2- Busca endereços dinamicamente DURANTE conexão
    print("\nBUSCANDO ENDERECOS DURANTE CONEXAO...")
    print("-" * 40)
     
    
    # Loop de busca - tenta encontrar as strings durante conexão
    max_search_attempts = 50  # 50 tentativas
    search_attempt = 0
    
    while search_attempt < max_search_attempts:
        print(f"Tentativa {search_attempt + 1}/{max_search_attempts}")
        
        # Busca pelas strings conhecidas (apenas hostname base)
        print("  Buscando hostname base...")
        hostname_addr = find_string_in_memory(pm, "lt-account-01.gnjoylatam.com")
        
        print("  Buscando taaddress completo...")
        taaddress_addr = find_string_in_memory(pm, "lt-account-01.gnjoylatam.com:6951")
        
        print("  Buscando domain completo...")
        domain_string_addr = find_string_in_memory(pm, "lt-account-01.gnjoylatam.com:6900")
        
        # Se encontrou algo, sai do loop
        if hostname_addr or taaddress_addr:
            print("STRINGS ENCONTRADAS!")
            break
            
        print("  Nao encontrou ainda, tentando novamente em 1 segundo...")
        time.sleep(1)
        search_attempt += 1
    
    if not hostname_addr and not taaddress_addr:
        print("Nao encontrou nenhuma string do servidor")     
        return
        
    # Usa o endereço que encontrou (prioridade: taaddress específico, depois hostname base)
    target_addr = taaddress_addr if taaddress_addr else hostname_addr
    
    if not domain_string_addr:
        print("Nao encontrou domain string, tentando usar hostname base...")
        domain_string_addr = hostname_addr
    
    # Busca ponteiro para domain apenas se encontrou a string
    domain_ptr_addr = None
    if domain_string_addr:
        print("Buscando ponteiro para domain...")
        domain_ptr_addr = find_pointer_to_address(pm, domain_string_addr)
        if not domain_ptr_addr:
            print("Nao encontrou ponteiro para domain (tentara busca direta)")
    
    print(f"\nENDERECOS ENCONTRADOS:")
    print(f"   HOSTNAME_BASE: 0x{hostname_addr:08X}" if hostname_addr else "   HOSTNAME_BASE: Nao encontrado")
    print(f"   TAADDRESS: 0x{target_addr:08X}" if target_addr else "   TAADDRESS: Nao encontrado")
    if domain_ptr_addr and domain_string_addr:
        print(f"   DOMAIN_PTR: 0x{domain_ptr_addr:08X} -> 0x{domain_string_addr:08X}")
    elif domain_string_addr:
        print(f"   DOMAIN_STRING: 0x{domain_string_addr:08X} (sem ponteiro)")
    else:
        print("   DOMAIN: Nao encontrado")
    
    # 3- Substitui endereços
    value = f"{IP}:{PORT}".encode("utf-8").ljust(33, b'\x00')
    is_taaddress_overwrited = False
    is_domain_overwrited = False
    
    print(f"\nINICIANDO SUBSTITUICOES...")
    print(f"   Alvo: {IP}:{PORT}")
    print("-" * 40)
    
    max_attempts = 100  # 1 segundo - janela muito estreita
    attempt = 0
    
    while attempt < max_attempts:
        try:
            # Verifica taaddress (usa o endereço que encontrou)
            if not is_taaddress_overwrited and target_addr:
                try:
                    current_value = pm.read_string(target_addr)
                    # Aceita qualquer string que contenha o hostname
                    if "lt-account-01.gnjoylatam.com" in current_value:
                        print(f"[taaddress] substituindo {current_value} por {IP}:{PORT}")
                        pm.write_bytes(target_addr, value, len(value))
                        is_taaddress_overwrited = True
                        print("   TAADDRESS substituido com sucesso!")
                except Exception as e:
                    if "MemoryWriteError" in str(type(e)):
                        print(f"   GameGuard bloqueou escrita no taaddress (tentativa {attempt+1})")
                        break
                    pass
            
            # Verifica domain via ponteiro
            if not is_domain_overwrited and domain_ptr_addr:
                try:
                    domain_addr = pm.read_uint(domain_ptr_addr)
                    domain = pm.read_string(domain_addr)
                    # Aceita qualquer string que contenha o hostname
                    if "lt-account-01.gnjoylatam.com" in domain:
                        print(f"[domain] substituindo {domain} por {IP}:{PORT}")
                        pm.write_bytes(domain_addr, value, len(value))
                        is_domain_overwrited = True
                        print("   DOMAIN substituido com sucesso!")
                except Exception as e:
                    if "MemoryWriteError" in str(type(e)):
                        print(f"   GameGuard bloqueou escrita no domain (tentativa {attempt+1})")
                        break
                    pass
            
            # Se não tem ponteiro, tenta substituir diretamente
            if not is_domain_overwrited and domain_string_addr and not domain_ptr_addr:
                try:
                    domain = pm.read_string(domain_string_addr)
                    if "lt-account-01.gnjoylatam.com" in domain:
                        print(f"[domain-direct] substituindo {domain} por {IP}:{PORT}")
                        pm.write_bytes(domain_string_addr, value, len(value))
                        is_domain_overwrited = True
                        print("   DOMAIN-DIRECT substituido com sucesso!")
                except Exception as e:
                    if "MemoryWriteError" in str(type(e)):
                        print(f"   GameGuard bloqueou escrita no domain-direct (tentativa {attempt+1})")
                        break
                    pass                           
        except pymem.pymem.exception.MemoryWriteError as e:
            print(f"GameGuard bloqueou todas as escritas na memoria (tentativa {attempt+1})")
            print("A janela de tempo para substituicao foi perdida")
            break
        except Exception:
            pass
            
        time.sleep(0.01)
        attempt += 1
    
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperacao cancelada pelo usuario")
    except Exception as e:
        print(f"Erro: {e}")
