import idc
import idaapi
import idautils
import base64
from Crypto.Cipher import ARC4, AES

banner = """
----------------------------------------------------------------
IDA Universal String Decryptor Template
----------------------------------------------------------------
A modular framework to automate string decryption in IDA Pro.
Supports: RC4, XOR, AES.
----------------------------------------------------------------
"""

# ==============================================================
# CONFIGURATION
# ==============================================================
TARGET_FUNC   = "REPLACE_WITH_FUNC_NAME_OR_ADDRESS"
CRYPTO_KEY    = b"REPLACE_WITH_YOUR_KEY"
ALGO          = "RC4"  # Options: "RC4", "XOR", "AES"
SCAN_DEPTH    = 15
# ==============================================================

def decryption_logic(raw_data):
    """
    MODULAR DECRYPTION LOGIC
    Edit this section to switch between different algorithms.
    """
    try:
        # 1. Pre-processing: Most malware strings are Base64 encoded
        data = base64.b64decode(raw_data.strip())
        
        # 2. Decryption Selection
        if ALGO == "RC4":
            cipher = ARC4.new(CRYPTO_KEY)
            decrypted = cipher.decrypt(data)
            
        elif ALGO == "XOR":
            # Simple XOR logic
            decrypted = bytes([b ^ CRYPTO_KEY[i % len(CRYPTO_KEY)] for i, b in enumerate(data)])
            
        elif ALGO == "AES":
            # Example for AES-CBC (adjust IV as needed)
            iv = b"\x00" * 16 
            cipher = AES.new(CRYPTO_KEY, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(data)
            
        else:
            return None

        # 3. Cleanup and Validation
        result = decrypted.decode('utf-8', errors='ignore').strip('\x00').strip()
        return result if (result and result.isprintable()) else None
        
    except:
        return None

def get_string_from_addr(addr):
    if addr == idc.BADADDR: return None
    content = idc.get_strlit_contents(addr)
    if content: return content
    raw = idc.get_bytes(addr, 256)
    if raw:
        end = raw.find(b'\x00')
        return raw[:end] if end > 0 else None
    return None

def resolve_target_ea(target):
    if isinstance(target, int): return target
    ea = idc.get_name_ea_simple(target)
    if ea != idc.BADADDR: return ea
    for name_ea, name in idautils.Names():
        if target in name: return name_ea
    return idc.BADADDR

def main():
    print(banner)
    target_ea = resolve_target_ea(TARGET_FUNC)
    
    if target_ea == idc.BADADDR or "REPLACE" in str(TARGET_FUNC):
        print("[!] Configuration required. Edit the script to set TARGET_FUNC and KEY.")
        return

    print(f"[-] Target: {hex(target_ea)}. Scanning Xrefs...")

    count = 0
    for xref in idautils.XrefsTo(target_ea):
        call_site = xref.frm
        if "Decrypted:" in (idc.get_cmt(call_site, 0) or ""): continue

        found = False
        curr_insn = call_site
        for _ in range(SCAN_DEPTH):
            curr_insn = idc.prev_head(curr_insn)
            if curr_insn == idc.BADADDR: break

            for op_idx in range(2):
                if idc.get_operand_type(curr_insn, op_idx) in [idc.o_mem, idc.o_imm, idc.o_near, idc.o_displ]:
                    val = idc.get_operand_value(curr_insn, op_idx)
                    raw_str = get_string_from_addr(val)

                    if raw_str and len(raw_str) > 4:
                        plaintext = decryption_logic(raw_str)
                        if plaintext:
                            comment = f"Decrypted: {plaintext}"
                            idc.set_cmt(call_site, comment, 0)
                            idc.set_cmt(call_site, comment, 1)
                            print(f"[+] {hex(call_site)} -> {plaintext}")
                            idc.set_color(call_site, idc.CIC_ITEM, 0xE0F0E0)
                            found = True
                            count += 1
                            break
            if found: break

    print(f"[-] Done. Decrypted {count} strings.")
    idaapi.refresh_idaview_anyway()

if __name__ == "__main__":
    main()
