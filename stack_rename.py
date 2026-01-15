import idc
import idaapi
import idautils
import re

# ----------------------------------------------------------------
# Banner 定義
# ----------------------------------------------------------------
banner = """
----------------------------------------------------------------
IDA Stack String Function Renamer
----------------------------------------------------------------
This script detects stack-based strings inside functions and uses
them to rename API wrapper functions automatically.

Example pattern handled by this script:

    strcpy(buf, "memcpy");
    func = GetProcAddress(hModule, buf);
    return func(a1, a2, a3);

Instead of leaving the function as sub_xxxx, the script recovers
the stack string ("memcpy") and renames the function accordingly,
making static analysis faster and more readable.
----------------------------------------------------------------
"""

def get_stack_string_from_func(func_ea):
    stack_chars = {}
    
    for head in idautils.FuncItems(func_ea):
        if not idc.print_insn_mnem(head).startswith("mov"):
            continue
            
        # Check if op0 is Stack Displacement and op1 is Immediate
        if idc.get_operand_type(head, 0) == idc.o_displ and idc.get_operand_type(head, 1) == idc.o_imm:
            char_val = idc.get_operand_value(head, 1)
            
            # ASCII filter
            if 0x20 <= char_val <= 0x7E:
                stack_offset = idc.get_operand_value(head, 0)
                stack_chars[stack_offset] = chr(char_val)

    if not stack_chars:
        return None

    sorted_offsets = sorted(stack_chars.keys())
    potential_names = []
    current_string = ""
    last_offset = -999999

    for offset in sorted_offsets:
        char = stack_chars[offset]
        
        if offset == last_offset + 1:
            current_string += char
        else:
            if len(current_string) > 3:
                potential_names.append(current_string)
            current_string = char
            
        last_offset = offset

    if len(current_string) > 3:
        potential_names.append(current_string)

    if potential_names:
        return max(potential_names, key=len)
    return None

def solve_all_stack_strings():
    print(banner)
    print("[-] Scanning for Stack Strings...")
    
    count = 0
    for func_ea in idautils.Functions():
        func = idaapi.get_func(func_ea)
        if not func or (func.end_ea - func.start_ea < 10):
            continue
            
        try:
            target_string = get_stack_string_from_func(func_ea)
            
            if target_string:
                clean_name = re.sub(r'[^a-zA-Z0-9_]', '', target_string)
                
                if len(clean_name) < 3:
                    continue

                # 命名規則: string_0
                base_name = f"{clean_name}_0"
                
                if idc.set_name(func_ea, base_name, idc.SN_NOWARN):
                    print(f"[+] {hex(func_ea)} -> {base_name}")
                    idc.set_color(func_ea, idc.CIC_FUNC, 0xE0F0E0)
                    count += 1
                else:
                    # 只有衝突時才加上位址後綴
                    retry_name = f"{base_name}_{hex(func_ea)[2:]}"
                    if idc.set_name(func_ea, retry_name, idc.SN_NOWARN):
                        print(f"[+] {hex(func_ea)} -> {retry_name} (Conflict resolved)")
                        idc.set_color(func_ea, idc.CIC_FUNC, 0xE0F0E0)
                        count += 1
                        
        except Exception as e:
            print(f"[!] Error at {hex(func_ea)}: {e}")

    print(f"[-] Done. Renamed {count} functions.")
    idaapi.refresh_idaview_anyway()

if __name__ == "__main__":
    solve_all_stack_strings()
