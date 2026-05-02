# cs2_sig_dumper.py
#
# Писал и тестил на IDA 9.2 Pro + Windows 11.
# На 9.0-9.1 должно работать без изменений.
# Если у тебя 8.x или младше - могут быть мелкие проблемы с API.
#

import hashlib
import json
import os
import re
import time
import traceback

import ida_auto
import ida_bytes
import ida_funcs
import ida_gdl
import ida_idaapi
import ida_loader
import ida_segment
import ida_ua
import idaapi
import idautils
import idc


def env_flag(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.lower() in ("1", "true", "yes", "on")


ONLY_NAMED = True
MIN_SIG_LEN = 6
MAX_SIG_LEN = 200
MAX_FUNCTION_BYTES = 2048
MAX_PATTERN_START_OFFSET = 512
MIN_FIXED_BYTES = 4
LIMIT = 0

OUTPUT_JSON = True
OUTPUT_CPP = not env_flag("CS2SIG_NO_CPP", False)
OUTPUT_REPORT = not env_flag("CS2SIG_NO_REPORT", False)
OUTPUT_MANIFEST = not env_flag("CS2SIG_NO_MANIFEST", False)
OUTPUT_DIR = os.environ.get("CS2SIG_OUTPUT_DIR", "")
ALLOW_INTERIOR_PATTERNS = True
PROBE_LENGTHS = (6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 160, 200)
EXTEND_UNIQUE_PATTERNS = True
PREFERRED_MIN_SIG_LEN = 12
PREFERRED_MIN_FIXED_BYTES = 8
MAX_STABLE_SIG_LEN = 48
FILTER_PRESET = os.environ.get("CS2SIG_FILTER_PRESET", "balanced").lower()
if FILTER_PRESET not in ("balanced", "clean", "broad"):
    FILTER_PRESET = "balanced"
EMIT_RUNTIME_SIGNATURES = env_flag("CS2SIG_INCLUDE_RUNTIME", FILTER_PRESET == "broad")
EMIT_THUNK_SIGNATURES = env_flag("CS2SIG_INCLUDE_THUNKS", FILTER_PRESET == "broad")
EMIT_LIBRARY_SIGNATURES = env_flag("CS2SIG_INCLUDE_LIBRARY", FILTER_PRESET != "clean")
MIGRATION_MODE = env_flag("CS2SIG_MIGRATION_MODE", False)
OLD_SIGNATURES_JSON = os.environ.get("CS2SIG_OLD_SIGNATURES_JSON", "")
OLD_MANIFEST_JSON = os.environ.get("CS2SIG_OLD_MANIFEST_JSON", "")
MIGRATION_MIN_CONFIDENCE = 0.75
MIGRATION_RVA_WINDOW = 0x6000
MAX_FEATURE_STRINGS = 24
MAX_FEATURE_CONSTANTS = 32
MAX_FEATURE_CALLS = 24

AUTO_NAME_PREFIXES = (
    "sub_",
    "j_",
    "nullsub",
    "unknown",
)

INCLUDE_NAME_PREFIXES = ()
EXCLUDE_NAME_PREFIXES = ()
RUNTIME_NAME_PREFIXES = (
    "__AdjustPointer",
    "__alloca",
    "__C_specific_handler",
    "__free_lconv",
    "__lc_",
    "__remainder_",
    "__security_",
    "__scrt_",
    "__std_",
    "__crt_",
    "__GSHandler",
    "__CxxFrameHandler",
    "_CxxThrowException",
    "_purecall",
    "_invalid_parameter",
    "_guard_",
    "_RTC_",
    "_initp_",
    "_initterm",
    "_Init_thread",
    "_local_stdio_",
    "_set_fpsr",
    "_str",
    "_Mtx",
    "_Cnd",
    "_Thrd",
    "_Once",
    "_CallSettingFrame",
    "_CallMemberFunction",
    "_cexit",
    "_clrfp",
    "_ctrlfp",
    "_errcode",
    "_fclrf",
    "_fd",
    "_get_",
    "_Getcoll",
    "_isatty",
    "_is",
    "_raise_",
    "_set_",
    "_setjmp",
    "_statfp",
    "_validdrive",
    "_wsetlocale",
    "_heap_",
    "_return",
)
RUNTIME_NAME_EXACT = (
    "_IsNonwritableInCurrentImage",
    "atexit",
    "cosf",
    "fegetenv",
    "memcpy",
    "memcpy_s",
    "memmove",
    "memset",
    "strcmp",
    "strlen",
    "malloc",
    "free",
)
MODULE_NAME_EXACT = (
    "CreateInterface",
    "DllEntryPoint",
    "ExtractModuleMetadata",
    "GetResourceManifestCount",
    "GetResourceManifests",
    "GsDriverEntry",
    "InstallSchemaBindings",
)
MODULE_NAME_PREFIXES = (
    "TlsCallback",
)
RUNTIME_NAME_SUBSTRINGS = (
    "@std@@",
    "std::",
    "@Concurrency",
    "Concurrency::",
    "_RefCounter",
    "__ExceptionPtr",
    "_DeleteExceptionPtr",
    "_GetThrowImageBase",
    "GetImageBase",
    "__GetUnwind",
    "__uncaught_exception",
    "_s_FuncInfo",
    "_DISPATCHER_CONTEXT",
    "localeinfo",
    "__lc_time_data",
    "security_cookie",
    "dynamic initializer",
    "dynamic atexit destructor",
    "`RTTI",
    "RTTI ",
    "type_info",
)
LIBRARY_NAME_PREFIXES = (
    "antlr3",
    "generic_expr",
)
LIBRARY_NAME_EXACT = ()
LIBRARY_NAME_SUBSTRINGS = (
    "DName",
    "UnDecorator",
    "pcharNode",
    "charNode",
)
PROGRESS_EVERY = 200

SEARCH_FLAGS = (
    ida_bytes.BIN_SEARCH_FORWARD
    | getattr(ida_bytes, "BIN_SEARCH_NOBREAK", 0)
    | getattr(ida_bytes, "BIN_SEARCH_NOSHOW", 0)
)


def log(message):
    print(f"[cs2sig] {message}")


def get_input_path():
    input_path = idc.get_input_file_path()
    if input_path:
        return input_path

    input_path = ida_loader.get_path(ida_loader.PATH_TYPE_CMD)
    if input_path:
        return input_path

    return idc.get_idb_path()


def get_module_name():
    input_path = get_input_path()
    filename = os.path.basename(input_path) if input_path else "unknown_module"
    module_name, _ = os.path.splitext(filename)
    return module_name or "unknown_module"


def get_output_dir():
    if OUTPUT_DIR:
        return os.path.abspath(OUTPUT_DIR)

    idb_path = idc.get_idb_path()
    if idb_path:
        idb_dir = os.path.dirname(idb_path)
        if idb_dir:
            return idb_dir

    input_path = get_input_path()
    if input_path:
        input_dir = os.path.dirname(input_path)
        if input_dir:
            return input_dir

    return os.getcwd()


def get_ida_version():
    try:
        return idaapi.get_kernel_version()
    except Exception:
        return "unknown"


def get_input_file_hash():
    input_path = get_input_path()
    if not input_path or not os.path.isfile(input_path):
        return None

    sha256 = hashlib.sha256()
    with open(input_path, "rb") as input_file:
        for chunk in iter(lambda: input_file.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def demangle_name(function_name):
    if not function_name or not function_name.startswith("?"):
        return function_name

    try:
        demangle_flags = idc.get_inf_attr(idc.INF_SHORT_DN)
        demangled = idc.demangle_name(function_name, demangle_flags)
        return demangled or function_name
    except Exception:
        return function_name


def compact_display_name(function_name):
    demangled = demangle_name(function_name)
    if demangled == function_name:
        return function_name

    head = demangled.split("(", 1)[0].strip()
    head = re.sub(r"^(public|protected|private):\s+", "", head)

    head = re.sub(
        r"\b(public|protected|private|virtual|static|class|struct|enum|union|"
        r"const|volatile|__cdecl|__stdcall|__fastcall|__thiscall|__ptr64)\b",
        " ",
        head,
    )
    head = re.sub(r"\s+", " ", head).strip()

    if "operator" in head:
        operator_index = head.find("operator")
        owner_prefix = head[:operator_index].strip().split(" ")
        owner = owner_prefix[-1] if owner_prefix else ""
        operator_name = head[operator_index:].strip()
        return f"{owner}::{operator_name}" if owner and "::" in owner else operator_name

    for token in reversed(head.split(" ")):
        candidate = token.strip("*&")
        if candidate:
            return candidate

    return demangled


def is_runtime_name(function_name, display_name):
    raw_base = re.sub(r"_\d+$", "", function_name or "")
    display_base = re.sub(r"_\d+$", "", display_name or "")

    if raw_base in RUNTIME_NAME_EXACT or display_base in RUNTIME_NAME_EXACT:
        return True

    if function_name.startswith(RUNTIME_NAME_PREFIXES) or display_name.startswith(RUNTIME_NAME_PREFIXES):
        return True

    combined = f"{function_name} {display_name}"
    return any(marker in combined for marker in RUNTIME_NAME_SUBSTRINGS)


def is_module_name(function_name, display_name):
    raw_base = re.sub(r"_\d+$", "", function_name or "")
    display_base = re.sub(r"_\d+$", "", display_name or "")

    if raw_base in MODULE_NAME_EXACT or display_base in MODULE_NAME_EXACT:
        return True

    return function_name.startswith(MODULE_NAME_PREFIXES) or display_name.startswith(MODULE_NAME_PREFIXES)


def is_library_name(function_name, display_name):
    raw_base = re.sub(r"_\d+$", "", function_name or "")
    display_base = re.sub(r"_\d+$", "", display_name or "")

    if raw_base in LIBRARY_NAME_EXACT or display_base in LIBRARY_NAME_EXACT:
        return True

    if function_name.startswith(LIBRARY_NAME_PREFIXES) or display_name.startswith(LIBRARY_NAME_PREFIXES):
        return True

    combined = f"{function_name} {display_name}"
    return any(marker in combined for marker in LIBRARY_NAME_SUBSTRINGS)


def get_function_category(function_ea, function_name, display_name):
    function = ida_funcs.get_func(function_ea)
    thunk_flag = getattr(ida_funcs, "FUNC_THUNK", 0)
    function_flags = getattr(function, "flags", 0) if function is not None else 0
    if thunk_flag and (function_flags & thunk_flag):
        return "thunk"

    if function_name.startswith(AUTO_NAME_PREFIXES):
        return "auto"

    if is_runtime_name(function_name, display_name):
        return "runtime"

    if is_module_name(function_name, display_name):
        return "module"

    if is_library_name(function_name, display_name):
        return "library"

    return "game"


def make_function_info(function_ea, function_name):
    display_name = compact_display_name(function_name)
    return {
        "ea": function_ea,
        "name": function_name,
        "display_name": display_name,
        "category": get_function_category(function_ea, function_name, display_name),
    }


def stable_hash_text(value):
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:16]


def try_read_string(ea):
    try:
        raw = idc.get_strlit_contents(ea, -1, 0)
    except Exception:
        raw = None

    if raw is None:
        try:
            raw = idc.get_strlit_contents(ea)
        except Exception:
            raw = None

    if raw is None:
        return None

    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            return None
    else:
        text = str(raw)

    text = text.strip("\x00\r\n\t ")
    if len(text) < 4:
        return None
    return text[:160]


def collect_code_refs_from_item(ea):
    refs = []
    try:
        refs.extend(idautils.CodeRefsFrom(ea, False))
    except Exception:
        pass
    return refs


def collect_data_refs_from_item(ea):
    refs = []
    try:
        refs.extend(idautils.DataRefsFrom(ea))
    except Exception:
        pass
    return refs


def add_limited_unique(target, value, limit):
    if value in target:
        return
    if len(target) >= limit:
        return
    target.append(value)


def get_basic_block_count(function):
    if function is None:
        return 0
    try:
        return sum(1 for _ in ida_gdl.FlowChart(function))
    except Exception:
        return 0


def collect_function_features(function_ea, image_base):
    function = ida_funcs.get_func(function_ea)
    if function is None:
        return {
            "rva": hex(function_ea - image_base),
            "size": 0,
            "basic_blocks": 0,
            "strings": [],
            "constants": [],
            "calls": [],
            "mnemonic_hash": "",
            "mnemonic_prefix": [],
            "xref_to_count": 0,
        }

    strings = []
    constants = []
    calls = []
    mnemonics = []

    for item_ea in idautils.FuncItems(function.start_ea):
        mnemonic = idc.print_insn_mnem(item_ea) or ""
        if mnemonic:
            mnemonics.append(mnemonic)

        instruction = ida_ua.insn_t()
        if ida_ua.decode_insn(instruction, item_ea) > 0:
            for operand_index in range(8):
                operand = instruction.ops[operand_index]
                if operand.type == ida_ua.o_void:
                    break
                if operand.type == ida_ua.o_imm:
                    value = int(operand.value)
                    if value > 0x1000:
                        add_limited_unique(constants, hex(value), MAX_FEATURE_CONSTANTS)
                elif operand.type in (ida_ua.o_mem, ida_ua.o_displ):
                    value = int(operand.addr)
                    if value > 0x1000:
                        add_limited_unique(constants, hex(value), MAX_FEATURE_CONSTANTS)

        for data_ref in collect_data_refs_from_item(item_ea):
            text = try_read_string(data_ref)
            if text:
                add_limited_unique(strings, text, MAX_FEATURE_STRINGS)

        for code_ref in collect_code_refs_from_item(item_ea):
            target_function = ida_funcs.get_func(code_ref)
            if target_function is None:
                continue
            target_name = idc.get_func_name(target_function.start_ea)
            if target_name:
                add_limited_unique(calls, compact_display_name(target_name), MAX_FEATURE_CALLS)

    try:
        xref_to_count = sum(1 for _ in idautils.CodeRefsTo(function.start_ea, False))
    except Exception:
        xref_to_count = 0

    mnemonic_prefix = mnemonics[:48]
    mnemonic_text = " ".join(mnemonics[:160])
    return {
        "rva": hex(function.start_ea - image_base),
        "size": int(function.end_ea - function.start_ea),
        "basic_blocks": get_basic_block_count(function),
        "strings": strings,
        "constants": constants,
        "calls": calls,
        "mnemonic_hash": stable_hash_text(mnemonic_text) if mnemonic_text else "",
        "mnemonic_prefix": mnemonic_prefix,
        "xref_to_count": xref_to_count,
    }


def enrich_function_info(function_info, image_base):
    if "features" not in function_info:
        function_info["features"] = collect_function_features(function_info["ea"], image_base)
    return function_info


def should_include_function(function_name, category):
    if not function_name:
        return False

    if ONLY_NAMED and function_name.startswith(AUTO_NAME_PREFIXES):
        return False

    if category == "runtime" and not EMIT_RUNTIME_SIGNATURES:
        return False

    if category == "thunk" and not EMIT_THUNK_SIGNATURES:
        return False

    if category == "library" and not EMIT_LIBRARY_SIGNATURES:
        return False

    if INCLUDE_NAME_PREFIXES and not function_name.startswith(INCLUDE_NAME_PREFIXES):
        return False

    if EXCLUDE_NAME_PREFIXES and function_name.startswith(EXCLUDE_NAME_PREFIXES):
        return False

    return True


def collect_target_functions():
    targets = []

    for function_ea in idautils.Functions():
        function_name = idc.get_func_name(function_ea)
        function_info = make_function_info(function_ea, function_name)
        if should_include_function(function_name, function_info["category"]):
            targets.append(function_info)

    targets.sort(key=lambda item: item["ea"])
    return targets


def get_code_segments():
    code_segments = []

    for segment_start in idautils.Segments():
        segment = ida_segment.getseg(segment_start)
        if segment and segment.type == ida_segment.SEG_CODE:
            code_segments.append((segment.start_ea, segment.end_ea))

    code_segments.sort(key=lambda item: item[0])
    return code_segments


def wildcard_mask_range(mask, start, length):
    end = min(start + length, len(mask))
    for index in range(start, end):
        mask[index] = False


def get_operand_wildcard_size(op, instruction_size):
    remaining_operand_bytes = max(0, instruction_size - op.offb)
    if op.type == ida_ua.o_imm and op.value > 0xFFFFFFFF:
        return min(8, remaining_operand_bytes)
    return min(4, remaining_operand_bytes)


def should_wildcard_operand(op):
    if op.type in (ida_ua.o_near, ida_ua.o_far):
        return True

    if op.type == ida_ua.o_mem:
        return True

    if op.type == ida_ua.o_imm:
        return op.value > 0x1000 and ida_bytes.is_mapped(op.value)

    if op.type == ida_ua.o_displ:
        return bool(op.addr and ida_bytes.is_mapped(op.addr))

    return False


def get_instruction_mask(ea):
    instruction = ida_ua.insn_t()
    instruction_size = ida_ua.decode_insn(instruction, ea)
    if instruction_size <= 0:
        return None, None

    raw_bytes = ida_bytes.get_bytes(ea, instruction_size)
    if raw_bytes is None:
        return None, None

    mask = [True] * instruction_size

    for operand_index in range(8):
        operand = instruction.ops[operand_index]
        if operand.type == ida_ua.o_void:
            break

        if not should_wildcard_operand(operand):
            continue

        if operand.offb <= 0:
            continue

        wildcard_size = get_operand_wildcard_size(operand, instruction_size)
        wildcard_mask_range(mask, operand.offb, wildcard_size)

    return bytes(raw_bytes), mask


def make_pattern(function_ea, max_bytes=MAX_FUNCTION_BYTES):
    function = ida_funcs.get_func(function_ea)
    if function is None:
        return [], [], []

    pattern_bytes = []
    pattern_mask = []
    instruction_offsets = []
    ea = function.start_ea

    while ea < function.end_ea and len(pattern_bytes) < max_bytes:
        raw_bytes, instruction_mask = get_instruction_mask(ea)
        if raw_bytes is None:
            break

        instruction_offsets.append(len(pattern_bytes))
        for byte_index, byte_value in enumerate(raw_bytes):
            pattern_bytes.append(byte_value)
            pattern_mask.append(instruction_mask[byte_index])

        ea += len(raw_bytes)

    return pattern_bytes, pattern_mask, instruction_offsets


def pattern_to_ida(pattern_bytes, pattern_mask, length, start=0):
    parts = []
    for index in range(start, start + length):
        parts.append(f"{pattern_bytes[index]:02X}" if pattern_mask[index] else "?")
    return " ".join(parts)


def pattern_to_code(pattern_bytes, pattern_mask, length, start=0):
    signature_bytes = ""
    signature_mask = ""

    for index in range(start, start + length):
        if pattern_mask[index]:
            signature_bytes += f"\\x{pattern_bytes[index]:02X}"
            signature_mask += "x"
        else:
            signature_bytes += "\\x00"
            signature_mask += "?"

    return signature_bytes, signature_mask


def pattern_to_code_style(pattern_bytes, pattern_mask, length, start=0):
    signature_bytes = ""
    for index in range(start, start + length):
        signature_bytes += f"\\x{pattern_bytes[index]:02X}" if pattern_mask[index] else "\\x2A"
    return signature_bytes


def is_required_category(category):
    return category in ("game", "module")


def compile_binary_pattern(pattern_text, ea=0):
    try:
        if hasattr(ida_bytes.compiled_binpat_vec_t, "parse"):
            return ida_bytes.compiled_binpat_vec_t.parse(ea, pattern_text, 16)

        compiled_pattern = ida_bytes.compiled_binpat_vec_t()
        if not ida_bytes.parse_binpat_str(compiled_pattern, ea, pattern_text, 16):
            return None
        return compiled_pattern
    except Exception as exc:
        log(f"failed to compile pattern '{pattern_text}': {exc}")
        return None


def count_matches_in_segment(compiled_pattern, segment_start, segment_end, max_count):
    match_count = 0
    search_ea = segment_start

    while search_ea < segment_end and match_count < max_count:
        search_result = ida_bytes.bin_search(
            search_ea,
            segment_end,
            compiled_pattern,
            SEARCH_FLAGS,
        )

        if isinstance(search_result, tuple):
            match_ea = search_result[0]
        else:
            match_ea = search_result

        if match_ea == ida_idaapi.BADADDR:
            break

        match_count += 1
        search_ea = match_ea + 1

    return match_count


def count_matches(pattern_text, code_segments, max_count=2):
    compiled_pattern = compile_binary_pattern(pattern_text)
    if compiled_pattern is None:
        return max_count

    total_matches = 0
    for segment_start, segment_end in code_segments:
        total_matches += count_matches_in_segment(
            compiled_pattern,
            segment_start,
            segment_end,
            max_count - total_matches,
        )

        if total_matches >= max_count:
            break

    return total_matches


def count_fixed_bytes(pattern_mask, start, length):
    return sum(1 for index in range(start, start + length) if pattern_mask[index])


def align_length_to_instruction_boundary(start, length, instruction_offsets, total_length, max_length):
    target = start + length
    if target >= total_length or target in instruction_offsets:
        return min(length, max_length)

    for instruction_offset in instruction_offsets:
        if instruction_offset > target:
            aligned_length = instruction_offset - start
            if aligned_length <= max_length:
                return aligned_length
            break

    return min(length, max_length)


def extend_unique_length(pattern_mask, instruction_offsets, start, unique_length):
    if not EXTEND_UNIQUE_PATTERNS or unique_length <= 0:
        return unique_length

    max_length = min(
        MAX_SIG_LEN,
        MAX_STABLE_SIG_LEN,
        len(pattern_mask) - start,
    )
    if unique_length >= max_length:
        return unique_length

    length = unique_length
    while length < max_length:
        fixed_bytes = count_fixed_bytes(pattern_mask, start, length)
        ends_with_wildcard = not pattern_mask[start + length - 1]
        has_enough_context = (
            length >= PREFERRED_MIN_SIG_LEN
            and fixed_bytes >= PREFERRED_MIN_FIXED_BYTES
            and not ends_with_wildcard
        )
        if has_enough_context:
            break
        length += 1

    return align_length_to_instruction_boundary(
        start,
        length,
        instruction_offsets,
        len(pattern_mask),
        max_length,
    )


def get_probe_lengths(max_candidate_length):
    lengths = set()
    for length in PROBE_LENGTHS:
        if MIN_SIG_LEN <= length <= max_candidate_length:
            lengths.add(length)

    lengths.add(MIN_SIG_LEN)
    lengths.add(max_candidate_length)
    return sorted(lengths)


def find_min_unique_length_at_offset(pattern_bytes, pattern_mask, code_segments, start):
    total_length = len(pattern_bytes)
    remaining_length = total_length - start
    max_candidate_length = min(remaining_length, MAX_SIG_LEN)
    last_failed_length = MIN_SIG_LEN - 1

    if max_candidate_length < MIN_SIG_LEN:
        return 0

    for length in get_probe_lengths(max_candidate_length):
        if count_fixed_bytes(pattern_mask, start, length) < MIN_FIXED_BYTES:
            last_failed_length = length
            continue

        pattern_text = pattern_to_ida(pattern_bytes, pattern_mask, length, start)
        if count_matches(pattern_text, code_segments) == 1:
            shrink_start = max(MIN_SIG_LEN, last_failed_length + 1)
            for shorter_length in range(shrink_start, length):
                if count_fixed_bytes(pattern_mask, start, shorter_length) < MIN_FIXED_BYTES:
                    continue

                shorter_pattern = pattern_to_ida(pattern_bytes, pattern_mask, shorter_length, start)
                if count_matches(shorter_pattern, code_segments) == 1:
                    return shorter_length
            return length

        last_failed_length = length

    return 0


def collect_candidate_starts(instruction_offsets, total_length):
    max_start = min(MAX_PATTERN_START_OFFSET, total_length - MIN_SIG_LEN)
    candidate_starts = []
    seen = set()

    for offset in instruction_offsets:
        if offset > max_start:
            break
        if offset not in seen:
            candidate_starts.append(offset)
            seen.add(offset)

    return candidate_starts


def find_unique_window(pattern_bytes, pattern_mask, instruction_offsets, code_segments):
    for start in collect_candidate_starts(instruction_offsets, len(pattern_bytes)):
        if start > 0 and not ALLOW_INTERIOR_PATTERNS:
            break

        unique_length = find_min_unique_length_at_offset(
            pattern_bytes,
            pattern_mask,
            code_segments,
            start,
        )
        if unique_length:
            return start, unique_length

    return 0, 0


def evaluate_signature_quality(pattern_mask, start, length, minimal_unique_length, category):
    fixed_bytes = count_fixed_bytes(pattern_mask, start, length)
    wildcard_count = length - fixed_bytes
    wildcard_ratio = wildcard_count / length if length else 1.0
    score = 100
    notes = []

    if category in ("runtime", "thunk", "auto"):
        score -= 10
        notes.append(f"{category}_symbol")

    if minimal_unique_length < PREFERRED_MIN_SIG_LEN:
        score -= 8
        notes.append("short_unique_core")

    if length < PREFERRED_MIN_SIG_LEN:
        score -= 18
        notes.append("short_pattern")

    if fixed_bytes < PREFERRED_MIN_FIXED_BYTES:
        score -= 24
        notes.append("low_fixed_bytes")

    if wildcard_ratio > 0.45:
        score -= 18
        notes.append("wildcard_heavy")
    elif wildcard_ratio > 0.30:
        score -= 8
        notes.append("many_wildcards")

    if start > 0:
        score -= 3
        notes.append("interior_anchor")

    if length > 96:
        score -= 5
        notes.append("long_pattern")

    score = max(0, min(100, score))
    if score >= 80:
        quality = "good"
    elif score >= 60:
        quality = "ok"
    else:
        quality = "fragile"

    return {
        "quality": quality,
        "quality_score": score,
        "fixed_bytes": fixed_bytes,
        "wildcards": wildcard_count,
        "wildcard_ratio": round(wildcard_ratio, 3),
        "quality_notes": notes,
    }


def sanitize_cpp_identifier(function_name, used_identifiers):
    identifier = function_name.replace("::", "__")
    identifier = identifier.replace("<", "_").replace(">", "_")
    identifier = identifier.replace(",", "_").replace(" ", "_").replace("*", "ptr")
    identifier = "".join(character if character.isalnum() or character == "_" else "_" for character in identifier)

    if not identifier or identifier[0].isdigit():
        identifier = f"sig_{identifier}"

    base_identifier = identifier
    suffix = 2
    while identifier in used_identifiers:
        identifier = f"{base_identifier}_{suffix}"
        suffix += 1

    used_identifiers.add(identifier)
    return identifier


def write_json_output(output_dir, module_name, metadata, signatures):
    output = {"_metadata": metadata}
    output.update(signatures)

    json_path = os.path.join(output_dir, f"{module_name}_signatures.json")
    with open(json_path, "w", encoding="utf-8") as output_file:
        json.dump(output, output_file, indent=2, ensure_ascii=False)

    log(f"JSON -> {json_path}")
    return json_path


def write_cpp_output(output_dir, module_name, signatures):
    hpp_path = os.path.join(output_dir, f"{module_name}_signatures.hpp")
    used_identifiers = set()

    with open(hpp_path, "w", encoding="utf-8") as output_file:
        output_file.write("#pragma once\n")
        output_file.write(f"namespace {module_name}_sigs {{\n\n")

        for function_name, signature in sorted(signatures.items()):
            display_name = signature.get("display_name", function_name)
            cpp_name = sanitize_cpp_identifier(display_name, used_identifiers)
            output_file.write(f"    constexpr auto {cpp_name} = \"{signature['pattern']}\";\n\n")

        output_file.write("}\n")

    log(f"C++ -> {hpp_path}")
    return hpp_path


def count_by(items, key):
    counts = {}
    for item in items:
        value = item.get(key, "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def make_report(module_name, metadata, target_functions, signatures, failure_samples):
    generated_entries = list(signatures.values())
    report = {
        "module": module_name,
        "timestamp": metadata["timestamp"],
        "summary": {
            "selected_functions": len(target_functions),
            "generated": len(signatures),
            "failed": metadata["failed"],
            "success_rate": round(len(signatures) / len(target_functions), 3) if target_functions else 0.0,
        },
        "selected_categories": count_by(target_functions, "category"),
        "generated_categories": count_by(generated_entries, "category"),
        "generated_importance": count_by(generated_entries, "importance"),
        "quality": count_by(generated_entries, "quality"),
        "failures": metadata["failures"],
        "failure_samples": failure_samples,
        "notes": [
            "JSON keys remain raw IDA names for scanner compatibility.",
            "display_name/cpp_name/category/quality are helper metadata for humans.",
            "fragile signatures are still emitted, but should not be treated as long-term anchors.",
        ],
    }
    return report


def write_report_output(output_dir, module_name, report):
    report_path = os.path.join(output_dir, f"{module_name}_signature_report.json")
    with open(report_path, "w", encoding="utf-8") as output_file:
        json.dump(report, output_file, indent=2, ensure_ascii=False)

    log(f"Report -> {report_path}")
    return report_path


def make_manifest(module_name, metadata, target_functions, signatures, image_base):
    signatures_by_raw_name = {
        signature.get("raw_name", key): signature
        for key, signature in signatures.items()
    }

    manifest_functions = []
    for function_info in target_functions:
        enrich_function_info(function_info, image_base)
        signature = signatures_by_raw_name.get(function_info["name"])
        entry = {
            "raw_name": function_info["name"],
            "display_name": function_info["display_name"],
            "category": function_info["category"],
            "rva": hex(function_info["ea"] - image_base),
            "features": function_info["features"],
            "signature": None,
        }
        if signature:
            entry["signature"] = {
                "pattern": signature["pattern"],
                "rva": signature["rva"],
                "pattern_rva": signature["pattern_rva"],
                "pattern_offset": signature["pattern_offset"],
                "address_offset": signature["address_offset"],
                "length": signature["length"],
                "quality": signature.get("quality", "unknown"),
                "quality_score": signature.get("quality_score", 0),
                "fixed_bytes": signature.get("fixed_bytes", 0),
                "wildcard_ratio": signature.get("wildcard_ratio", 0),
            }
        manifest_functions.append(entry)

    return {
        "metadata": metadata,
        "module": module_name,
        "functions": manifest_functions,
    }


def write_manifest_output(output_dir, module_name, manifest):
    manifest_path = os.path.join(output_dir, f"{module_name}_signature_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as output_file:
        json.dump(manifest, output_file, indent=2, ensure_ascii=False)

    log(f"Manifest -> {manifest_path}")
    return manifest_path


def parse_int(value, default=0):
    if value is None:
        return default
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 0)
    except Exception:
        return default


def load_json_file(path):
    if not path or not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as input_file:
        return json.load(input_file)


def load_old_signature_entries(path):
    data = load_json_file(path)
    if not isinstance(data, dict):
        return {}

    signatures = {}
    for key, value in data.items():
        if key.startswith("_") or not isinstance(value, dict):
            continue
        pattern = value.get("pattern")
        if not pattern:
            continue
        signatures[key] = value
    return signatures


def load_old_manifest_functions(path):
    data = load_json_file(path)
    if not isinstance(data, dict):
        return {}

    functions = data.get("functions", [])
    if not isinstance(functions, list):
        return {}

    by_name = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        raw_name = function.get("raw_name")
        display_name = function.get("display_name")
        if raw_name:
            by_name[raw_name] = function
        if display_name:
            by_name.setdefault(display_name, function)
    return by_name


def find_unique_pattern_match(pattern_text, code_segments):
    compiled_pattern = compile_binary_pattern(pattern_text)
    if compiled_pattern is None:
        return None, "compile_failed"

    found_ea = None
    match_count = 0
    for segment_start, segment_end in code_segments:
        search_ea = segment_start
        while search_ea < segment_end and match_count < 2:
            search_result = ida_bytes.bin_search(
                search_ea,
                segment_end,
                compiled_pattern,
                SEARCH_FLAGS,
            )
            match_ea = search_result[0] if isinstance(search_result, tuple) else search_result
            if match_ea == ida_idaapi.BADADDR:
                break
            found_ea = match_ea
            match_count += 1
            search_ea = match_ea + 1

        if match_count >= 2:
            return None, "ambiguous"

    if match_count == 1:
        return found_ea, "exact"
    return None, "not_found"


def get_function_info_for_ea(ea, image_base):
    function = ida_funcs.get_func(ea)
    function_ea = function.start_ea if function is not None else ea
    function_name = idc.get_func_name(function_ea) or f"sub_{function_ea:x}"
    function_info = make_function_info(function_ea, function_name)
    enrich_function_info(function_info, image_base)
    return function_info


def jaccard_score(left, right):
    left_set = set(left or [])
    right_set = set(right or [])
    if not left_set and not right_set:
        return 0.0
    if not left_set or not right_set:
        return 0.0
    return len(left_set & right_set) / len(left_set | right_set)


def size_similarity(left_size, right_size):
    left_size = int(left_size or 0)
    right_size = int(right_size or 0)
    if left_size <= 0 or right_size <= 0:
        return 0.0
    return 1.0 - (abs(left_size - right_size) / max(left_size, right_size))


def rva_similarity(old_rva, new_rva):
    distance = abs(old_rva - new_rva)
    if distance > MIGRATION_RVA_WINDOW:
        return 0.0
    return 1.0 - (distance / MIGRATION_RVA_WINDOW)


def compute_migration_confidence(old_function, new_function_info, image_base):
    old_features = old_function.get("features", {}) if isinstance(old_function, dict) else {}
    new_features = enrich_function_info(new_function_info, image_base).get("features", {})

    score = 0.0
    reasons = []

    old_raw_name = old_function.get("raw_name", "") if isinstance(old_function, dict) else ""
    old_display_name = old_function.get("display_name", "") if isinstance(old_function, dict) else ""
    if old_raw_name and old_raw_name == new_function_info["name"]:
        score += 0.30
        reasons.append("raw_name")
    elif old_display_name and old_display_name == new_function_info["display_name"]:
        score += 0.24
        reasons.append("display_name")

    strings = jaccard_score(old_features.get("strings", []), new_features.get("strings", []))
    constants = jaccard_score(old_features.get("constants", []), new_features.get("constants", []))
    calls = jaccard_score(old_features.get("calls", []), new_features.get("calls", []))
    score += strings * 0.25
    score += constants * 0.14
    score += calls * 0.14
    if strings >= 0.4:
        reasons.append("strings")
    if constants >= 0.35:
        reasons.append("constants")
    if calls >= 0.35:
        reasons.append("calls")

    size_score = size_similarity(old_features.get("size", 0), new_features.get("size", 0))
    score += size_score * 0.10
    if size_score >= 0.75:
        reasons.append("size")

    old_blocks = int(old_features.get("basic_blocks", 0) or 0)
    new_blocks = int(new_features.get("basic_blocks", 0) or 0)
    if old_blocks > 0 and new_blocks > 0:
        block_score = 1.0 - (abs(old_blocks - new_blocks) / max(old_blocks, new_blocks))
        score += block_score * 0.06
        if block_score >= 0.75:
            reasons.append("basic_blocks")

    old_rva = parse_int(old_function.get("rva") if isinstance(old_function, dict) else None)
    new_rva = new_function_info["ea"] - image_base
    rva_score = rva_similarity(old_rva, new_rva) if old_rva else 0.0
    score += rva_score * 0.12
    if rva_score >= 0.70:
        reasons.append("near_rva")

    if old_features.get("mnemonic_hash") and old_features.get("mnemonic_hash") == new_features.get("mnemonic_hash"):
        score += 0.14
        reasons.append("mnemonic_hash")

    return min(score, 0.97), reasons


def find_best_fuzzy_match(old_function, target_functions, image_base, used_function_eas):
    best = None
    best_score = 0.0
    best_reasons = []

    for function_info in target_functions:
        if function_info["ea"] in used_function_eas:
            continue
        score, reasons = compute_migration_confidence(old_function, function_info, image_base)
        if score > best_score:
            best = function_info
            best_score = score
            best_reasons = reasons

    return best, best_score, best_reasons


def migration_status_from_confidence(confidence):
    if confidence >= 0.95:
        return "exact"
    if confidence >= 0.85:
        return "fuzzy_strong"
    if confidence >= MIGRATION_MIN_CONFIDENCE:
        return "fuzzy_ok"
    return "failed"


def write_migrated_signatures(output_dir, module_name, metadata, signatures):
    output = {"_metadata": metadata}
    output.update(signatures)

    path = os.path.join(output_dir, f"{module_name}_migrated_signatures.json")
    with open(path, "w", encoding="utf-8") as output_file:
        json.dump(output, output_file, indent=2, ensure_ascii=False)

    log(f"Migrated JSON -> {path}")
    return path


def write_migration_report(output_dir, module_name, report):
    path = os.path.join(output_dir, f"{module_name}_migration_report.json")
    with open(path, "w", encoding="utf-8") as output_file:
        json.dump(report, output_file, indent=2, ensure_ascii=False)

    log(f"Migration report -> {path}")
    return path


def run_migration(module_name, image_base, output_dir, code_segments, target_functions):
    if not MIGRATION_MODE:
        return {}, None

    old_signatures = load_old_signature_entries(OLD_SIGNATURES_JSON)
    old_manifest = load_old_manifest_functions(OLD_MANIFEST_JSON)
    if not old_signatures:
        log("Migration mode: no old signatures loaded. Set OLD_SIGNATURES_JSON or CS2SIG_OLD_SIGNATURES_JSON.")
        return {}, None

    log(f"Migration mode: loaded {len(old_signatures)} old signature(s)")
    migrated = {}
    report_entries = []
    used_function_eas = set()

    for old_key, old_signature in old_signatures.items():
        old_function = old_manifest.get(old_key) or old_manifest.get(old_signature.get("display_name", ""))
        matched_info = None
        confidence = 0.0
        reasons = []
        method = "failed"
        failure = ""

        match_ea, exact_status = find_unique_pattern_match(old_signature.get("pattern", ""), code_segments)
        if match_ea is not None:
            matched_info = get_function_info_for_ea(match_ea, image_base)
            confidence = 0.98
            reasons = ["old_pattern_exact"]
            method = "exact"
        elif old_function:
            matched_info, confidence, reasons = find_best_fuzzy_match(
                old_function,
                target_functions,
                image_base,
                used_function_eas,
            )
            method = migration_status_from_confidence(confidence)
            if method == "failed":
                failure = f"best confidence {confidence:.2f} below threshold"
        else:
            failure = f"old pattern {exact_status}; no manifest metadata"

        generated_signature = None
        if matched_info is not None and confidence >= MIGRATION_MIN_CONFIDENCE:
            signature, failure_reason = build_signature_entry(
                matched_info,
                module_name,
                image_base,
                code_segments,
            )
            if signature:
                migrated_key = old_key
                if migrated_key in migrated:
                    migrated_key = f"{old_key}_{matched_info['ea']:x}"
                migrated[migrated_key] = signature
                used_function_eas.add(matched_info["ea"])
                generated_signature = {
                    "rva": signature["rva"],
                    "quality": signature.get("quality", "unknown"),
                    "quality_score": signature.get("quality_score", 0),
                }
            else:
                method = "failed"
                failure = failure_reason or "new signature generation failed"

        report_entries.append({
            "name": old_key,
            "method": method,
            "confidence": round(confidence, 3),
            "reasons": reasons,
            "old_rva": old_signature.get("rva"),
            "new_raw_name": matched_info["name"] if matched_info else None,
            "new_display_name": matched_info["display_name"] if matched_info else None,
            "new_rva": hex(matched_info["ea"] - image_base) if matched_info else None,
            "signature": generated_signature,
            "failure": failure,
        })

    metadata = {
        "generator": "cs2_sig_dumper.py",
        "mode": "migration",
        "module": module_name,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "old_signatures_json": OLD_SIGNATURES_JSON,
        "old_manifest_json": OLD_MANIFEST_JSON,
        "min_confidence": MIGRATION_MIN_CONFIDENCE,
        "old_count": len(old_signatures),
        "migrated_count": len(migrated),
    }
    write_migrated_signatures(output_dir, module_name, metadata, migrated)

    report = {
        "metadata": metadata,
        "summary": count_by(report_entries, "method"),
        "entries": report_entries,
    }
    write_migration_report(output_dir, module_name, report)
    return migrated, report


def build_signature_entry(function_info, module_name, image_base, code_segments):
    function_ea = function_info["ea"]
    pattern_bytes, pattern_mask, instruction_offsets = make_pattern(function_ea)
    if not pattern_bytes:
        return None, "decode_failed"

    pattern_offset, minimal_unique_length = find_unique_window(
        pattern_bytes,
        pattern_mask,
        instruction_offsets,
        code_segments,
    )
    if minimal_unique_length == 0:
        return None, "not_unique"

    unique_length = extend_unique_length(
        pattern_mask,
        instruction_offsets,
        pattern_offset,
        minimal_unique_length,
    )
    signature_pattern = pattern_to_ida(pattern_bytes, pattern_mask, unique_length, pattern_offset)
    signature_bytes, signature_mask = pattern_to_code(pattern_bytes, pattern_mask, unique_length, pattern_offset)
    code_style_pattern = pattern_to_code_style(pattern_bytes, pattern_mask, unique_length, pattern_offset)
    quality = evaluate_signature_quality(
        pattern_mask,
        pattern_offset,
        unique_length,
        minimal_unique_length,
        function_info["category"],
    )

    signature = {
        "pattern": signature_pattern,
        "ida_pattern": signature_pattern,
        "code_style_pattern": code_style_pattern,
        "bytes": signature_bytes,
        "mask": signature_mask,
        "module": module_name,
        "raw_name": function_info["name"],
        "display_name": function_info["display_name"],
        "category": function_info["category"],
        "importance": "required" if is_required_category(function_info["category"]) else "optional",
        "required": is_required_category(function_info["category"]),
        "status": "generated",
        "source": "ida_plugin",
        "source_project": "cs2sign",
        "source_count": 1,
        "rva": hex(function_ea - image_base),
        "pattern_rva": hex(function_ea + pattern_offset - image_base),
        "pattern_offset": pattern_offset,
        "address_offset": -pattern_offset,
        "length": unique_length,
        "minimal_unique_length": minimal_unique_length,
    }
    signature.update(quality)
    signature["confidence"] = signature.get("quality_score", 0)

    return signature, None


def make_metadata(module_name, image_base, target_count, signatures, failures, elapsed_seconds):
    metadata = {
        "generator": "cs2_sig_dumper.py",
        "ida_version": get_ida_version(),
        "module": module_name,
        "image_base": hex(image_base),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_functions": target_count,
        "signatures_generated": len(signatures),
        "failed": sum(failures.values()),
        "failures": failures,
        "elapsed_seconds": round(elapsed_seconds, 2),
        "config": {
            "only_named": ONLY_NAMED,
            "min_signature_length": MIN_SIG_LEN,
            "max_signature_length": MAX_SIG_LEN,
            "max_function_bytes": MAX_FUNCTION_BYTES,
            "max_pattern_start_offset": MAX_PATTERN_START_OFFSET,
            "min_fixed_bytes": MIN_FIXED_BYTES,
            "allow_interior_patterns": ALLOW_INTERIOR_PATTERNS,
            "extend_unique_patterns": EXTEND_UNIQUE_PATTERNS,
            "preferred_min_signature_length": PREFERRED_MIN_SIG_LEN,
            "preferred_min_fixed_bytes": PREFERRED_MIN_FIXED_BYTES,
            "max_stable_signature_length": MAX_STABLE_SIG_LEN,
            "filter_preset": FILTER_PRESET,
            "emit_runtime_signatures": EMIT_RUNTIME_SIGNATURES,
            "emit_thunk_signatures": EMIT_THUNK_SIGNATURES,
            "emit_library_signatures": EMIT_LIBRARY_SIGNATURES,
            "output_report": OUTPUT_REPORT,
            "output_manifest": OUTPUT_MANIFEST,
            "migration_mode": MIGRATION_MODE,
            "migration_min_confidence": MIGRATION_MIN_CONFIDENCE,
            "migration_rva_window": MIGRATION_RVA_WINDOW,
            "limit": LIMIT,
        },
    }

    file_hash = get_input_file_hash()
    if file_hash:
        metadata["sha256"] = file_hash

    return metadata


def dump_signatures():
    ida_auto.auto_wait()

    started_at = time.time()
    module_name = get_module_name()
    image_base = idaapi.get_imagebase()
    output_dir = get_output_dir()

    code_segments = get_code_segments()
    if not code_segments:
        log("No code segments found. Is auto-analysis complete?")
        return {}

    log(f"Module: {module_name}")
    log(f"Code segments: {len(code_segments)}")
    log(f"Output directory: {output_dir}")

    target_functions = collect_target_functions()
    target_count = len(target_functions)
    log(f"Named functions selected: {target_count}")

    if target_count == 0:
        log("No named functions selected. Set ONLY_NAMED = False to include sub_* names.")
        return {}

    signatures = {}
    failures = {
        "decode_failed": 0,
        "not_unique": 0,
        "duplicate_name": 0,
    }
    failure_samples = {
        "decode_failed": [],
        "not_unique": [],
    }

    for index, function_info in enumerate(target_functions):
        if LIMIT and len(signatures) >= LIMIT:
            break

        if index % PROGRESS_EVERY == 0:
            elapsed = time.time() - started_at
            log(f"{index}/{target_count} processed, {len(signatures)} signatures, {sum(failures.values())} failed [{elapsed:.1f}s]")

        function_ea = function_info["ea"]
        function_name = function_info["name"]
        result_key = function_name
        if result_key in signatures:
            result_key = f"{function_name}_{function_ea:x}"
            failures["duplicate_name"] += 1

        signature, failure_reason = build_signature_entry(
            function_info,
            module_name,
            image_base,
            code_segments,
        )

        if failure_reason:
            failures[failure_reason] += 1
            samples = failure_samples.get(failure_reason)
            if samples is not None and len(samples) < 25:
                samples.append({
                    "name": function_name,
                    "display_name": function_info["display_name"],
                    "category": function_info["category"],
                    "rva": hex(function_ea - image_base),
                })
            continue

        signatures[result_key] = signature

    elapsed_seconds = time.time() - started_at
    metadata = make_metadata(
        module_name,
        image_base,
        target_count,
        signatures,
        failures,
        elapsed_seconds,
    )

    if OUTPUT_JSON:
        write_json_output(output_dir, module_name, metadata, signatures)

    if OUTPUT_CPP:
        write_cpp_output(output_dir, module_name, signatures)

    if OUTPUT_REPORT:
        report = make_report(
            module_name,
            metadata,
            target_functions,
            signatures,
            failure_samples,
        )
        write_report_output(output_dir, module_name, report)

    if OUTPUT_MANIFEST:
        manifest = make_manifest(module_name, metadata, target_functions, signatures, image_base)
        write_manifest_output(output_dir, module_name, manifest)

    if MIGRATION_MODE:
        run_migration(module_name, image_base, output_dir, code_segments, target_functions)

    log(
        "Done: "
        f"{len(signatures)} generated, "
        f"{sum(failures.values())} failed "
        f"{failures} "
        f"[{elapsed_seconds:.1f}s]"
    )

    return signatures


PLUGIN_NAME = "CS2 Signature Dumper"
PLUGIN_HOTKEY = "Ctrl-Shift-S"
PLUGIN_COMMENT = "Dump unique byte signatures for named functions"
PLUGIN_HELP = "Generates IDA-style and C-style byte signatures for named functions"
PLUGIN_WANTED_NAME = PLUGIN_NAME


class cs2_sig_dumper_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_WANTED_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        print("=" * 60)
        print(f"  {PLUGIN_NAME}")
        print("=" * 60)
        try:
            dump_signatures()
        except Exception:
            log("Unhandled error while dumping signatures:")
            traceback.print_exc()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return cs2_sig_dumper_t()


if __name__ == "__main__":
    print("=" * 60)
    print(f"  {PLUGIN_NAME} (script mode)")
    print("=" * 60)
    if env_flag("CS2SIG_HEADLESS", False):
        try:
            result = dump_signatures()
            exit_code = 0 if result else 1
        except Exception:
            traceback.print_exc()
            exit_code = 1
        idc.qexit(exit_code)
    else:
        dump_signatures()
