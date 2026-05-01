import json
import os
import time
import traceback

import ida_auto
import ida_bytes
import ida_funcs
import ida_segment
import ida_ua
import idaapi
import idautils
import idc


BADADDR = idaapi.BADADDR
IMAGE_BASE = idaapi.get_imagebase()
MODULE_NAME = os.path.splitext(os.path.basename(idc.get_input_file_path()))[0]
OUTPUT_DIR = os.path.dirname(os.path.abspath(idc.get_input_file_path()))

try:
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
except NameError:
    SCRIPT_DIR = OUTPUT_DIR

REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))


MAX_PATTERN_BYTES = 256
PROBE_LENGTHS = (8, 12, 16, 20, 24, 32, 40, 48, 64, 80, 96, 128, 160, 200, 256)
MIN_FIXED_BYTES = 5
DEFAULT_MAX_REFS = 96
DEFAULT_MAX_CANDIDATES = 3

SEARCH_FLAGS = (
    ida_bytes.BIN_SEARCH_FORWARD
    | getattr(ida_bytes, "BIN_SEARCH_NOBREAK", 0)
    | getattr(ida_bytes, "BIN_SEARCH_NOSHOW", 0)
)


def log(message):
    print("[offset_signer] " + message)


def parse_int(value, field):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value.strip(), 0)
    raise ValueError(field + " must be an integer or string")


def hex_rva(ea):
    return hex(ea - IMAGE_BASE)


def clean_name(value):
    return str(value).strip()


def normalize_module(value):
    name = str(value).strip().lower()
    if name.endswith(".dll"):
        name = os.path.splitext(name)[0]
    if name.startswith("lib") and name.endswith(".so"):
        name = name[3:-3]
    return name


def normalize_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).lower() for item in value]
    return [str(value).lower()]


def load_json(path):
    with open(path, "r", encoding="utf-8-sig") as file:
        return json.load(file)


def find_config_path():
    candidates = (
        os.path.join(OUTPUT_DIR, MODULE_NAME + "_offset_targets.json"),
        os.path.join(OUTPUT_DIR, "offset_targets.json"),
        os.path.join(SCRIPT_DIR, MODULE_NAME + "_offset_targets.json"),
        os.path.join(SCRIPT_DIR, "offset_targets.json"),
        os.path.join(REPO_ROOT, "tools", "targets", MODULE_NAME + "_offset_targets.json"),
        os.path.join(REPO_ROOT, "tools", "targets", "offset_targets.json"),
    )
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def normalize_targets(data):
    if isinstance(data, list):
        raw_targets = data
    elif isinstance(data, dict) and isinstance(data.get("targets"), list):
        raw_targets = data["targets"]
    elif isinstance(data, dict) and isinstance(data.get("targets"), dict):
        raw_targets = []
        for name, value in data["targets"].items():
            if isinstance(value, dict):
                target = dict(value)
            else:
                target = {"rva": value}
            target["name"] = name
            raw_targets.append(target)
    elif isinstance(data, dict):
        raw_targets = []
        for name, value in data.items():
            if name.startswith("_"):
                continue
            if isinstance(value, dict):
                target = dict(value)
            else:
                target = {"rva": value}
            target["name"] = name
            raw_targets.append(target)
    else:
        raise ValueError("unsupported target config")

    targets = []
    for target in raw_targets:
        if not isinstance(target, dict):
            continue
        name = clean_name(target.get("name", ""))
        if not name:
            continue
        normalized = dict(target)
        normalized["name"] = name
        normalized["type"] = clean_name(
            normalized.get("type")
            or normalized.get("kind")
            or infer_target_type(normalized)
        ).lower()
        targets.append(normalized)
    return targets


def target_module_matches(target):
    module = clean_name(target.get("module", ""))
    if not module:
        return True
    return normalize_module(module) == normalize_module(MODULE_NAME)


def infer_target_type(target):
    if "offset" in target or "field_offset" in target:
        return "field_offset"
    if "target_rva" in target or "global_rva" in target:
        return "global_rva"
    return "direct_rva"


def get_code_segments():
    segments = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg and seg.type == ida_segment.SEG_CODE:
            segments.append((seg.start_ea, seg.end_ea))
    return segments


def iter_code_heads(start_ea=None, end_ea=None):
    for seg_start, seg_end in get_code_segments():
        first = max(seg_start, start_ea) if start_ea is not None else seg_start
        last = min(seg_end, end_ea) if end_ea is not None else seg_end
        if first >= last:
            continue
        for ea in idautils.Heads(first, last):
            if ida_bytes.is_code(ida_bytes.get_flags(ea)):
                yield ea


def decode_insn(ea):
    insn = ida_ua.insn_t()
    size = ida_ua.decode_insn(insn, ea)
    if size <= 0:
        return None
    return insn


def should_wildcard(op):
    if op.type in (ida_ua.o_near, ida_ua.o_far, ida_ua.o_mem):
        return True
    if op.type == ida_ua.o_imm:
        return op.value > 0x1000 and ida_bytes.is_mapped(op.value)
    if op.type == ida_ua.o_displ:
        return bool(op.addr and ida_bytes.is_mapped(op.addr))
    return False


def insn_mask(ea):
    insn = decode_insn(ea)
    if insn is None:
        return None, None
    raw = ida_bytes.get_bytes(ea, insn.size)
    if not raw:
        return None, None
    mask = [True] * insn.size
    for index in range(8):
        op = insn.ops[index]
        if op.type == ida_ua.o_void:
            break
        if not should_wildcard(op) or op.offb <= 0:
            continue
        remaining = max(0, insn.size - op.offb)
        width = min(8 if op.type == ida_ua.o_imm and op.value > 0xFFFFFFFF else 4, remaining)
        for byte_index in range(op.offb, op.offb + width):
            if byte_index < insn.size:
                mask[byte_index] = False
    return bytes(raw), mask


def build_raw_pattern(start_ea, max_bytes=MAX_PATTERN_BYTES):
    pattern_bytes = []
    pattern_mask = []
    boundaries = set()
    ea = start_ea
    while len(pattern_bytes) < max_bytes:
        boundaries.add(len(pattern_bytes))
        raw, mask = insn_mask(ea)
        if raw is None:
            break
        pattern_bytes.extend(raw)
        pattern_mask.extend(mask)
        ea += len(raw)
    return pattern_bytes, pattern_mask, boundaries


def to_ida_pattern(pattern_bytes, pattern_mask, length):
    tokens = []
    for index in range(min(length, len(pattern_bytes))):
        tokens.append("{:02X}".format(pattern_bytes[index]) if pattern_mask[index] else "?")
    return " ".join(tokens)


def to_code_mask(pattern_bytes, pattern_mask, length):
    sig_bytes = []
    sig_mask = []
    for index in range(min(length, len(pattern_bytes))):
        if pattern_mask[index]:
            sig_bytes.append("\\x{:02X}".format(pattern_bytes[index]))
            sig_mask.append("x")
        else:
            sig_bytes.append("\\x00")
            sig_mask.append("?")
    return "".join(sig_bytes), "".join(sig_mask)


def compile_binary_pattern(pattern_text, ea=0):
    try:
        if hasattr(ida_bytes.compiled_binpat_vec_t, "parse"):
            return ida_bytes.compiled_binpat_vec_t.parse(ea, pattern_text, 16)
        compiled = ida_bytes.compiled_binpat_vec_t()
        if not ida_bytes.parse_binpat_str(compiled, ea, pattern_text, 16):
            return None
        return compiled
    except Exception as exc:
        log("compile failed: {}".format(exc))
        return None


def count_matches(ida_pattern, max_count=2):
    compiled = compile_binary_pattern(ida_pattern)
    if compiled is None:
        return max_count

    total = 0
    for seg_start, seg_end in get_code_segments():
        ea = seg_start
        while ea < seg_end and total < max_count:
            try:
                result = ida_bytes.bin_search(ea, seg_end, compiled, SEARCH_FLAGS)
                found = result[0] if isinstance(result, tuple) else result
            except Exception as exc:
                log("bin_search failed: {}".format(exc))
                return max_count
            if found == BADADDR or found >= seg_end:
                break
            total += 1
            ea = found + 1
    return total


def make_unique_pattern(start_ea):
    pattern_bytes, pattern_mask, boundaries = build_raw_pattern(start_ea)
    if not pattern_bytes:
        return None

    for probe in PROBE_LENGTHS:
        length = min(probe, len(pattern_bytes))
        while length not in boundaries and length < len(pattern_bytes):
            length += 1
        if length > len(pattern_bytes):
            break
        fixed = sum(1 for index in range(length) if pattern_mask[index])
        if fixed < MIN_FIXED_BYTES:
            continue
        ida_pattern = to_ida_pattern(pattern_bytes, pattern_mask, length)
        if count_matches(ida_pattern) == 1:
            code_bytes, code_mask = to_code_mask(pattern_bytes, pattern_mask, length)
            return ida_pattern, code_bytes, code_mask, length
    return None


def operand_width(insn, op):
    if op.offb <= 0:
        return 0
    remaining = max(0, insn.size - op.offb)
    if op.type in (ida_ua.o_near, ida_ua.o_far, ida_ua.o_mem, ida_ua.o_displ):
        return min(4, remaining)
    if op.type == ida_ua.o_imm:
        return min(8 if op.value > 0xFFFFFFFF else 4, remaining)
    return min(4, remaining)


def function_name(ea):
    func = ida_funcs.get_func(ea)
    if not func:
        return ""
    return idc.get_func_name(func.start_ea) or ""


def function_start(ea):
    func = ida_funcs.get_func(ea)
    return func.start_ea if func else ea


def target_string(target, key, default=""):
    value = target.get(key, default)
    return default if value is None else str(value)


def target_result_type(target, resolver_type):
    configured = target_string(target, "result_type", "")
    if configured:
        return configured
    if resolver_type == "instruction_displacement":
        return "field_offset"
    if resolver_type == "direct_match":
        return "function_address"
    return "absolute_address"


def target_int(target, *keys):
    for key in keys:
        if key in target and target[key] not in (None, ""):
            return parse_int(target[key], key)
    raise ValueError("missing " + " or ".join(keys))


def target_max_refs(target):
    return int(target.get("max_refs", DEFAULT_MAX_REFS))


def target_max_candidates(target):
    return int(target.get("max_candidates", DEFAULT_MAX_CANDIDATES))


def target_range(target):
    start = None
    end = None
    if target.get("start_rva") not in (None, ""):
        start = IMAGE_BASE + parse_int(target["start_rva"], "start_rva")
    if target.get("end_rva") not in (None, ""):
        end = IMAGE_BASE + parse_int(target["end_rva"], "end_rva")
    return start, end


def target_matches_filters(target, ea):
    mnemonics = normalize_list(target.get("mnemonic"))
    if mnemonics and idc.print_insn_mnem(ea).lower() not in mnemonics:
        return False

    contains = target.get("function_contains")
    if contains:
        if str(contains).lower() not in function_name(ea).lower():
            return False

    near_rva = target.get("near_rva")
    if near_rva not in (None, ""):
        near_ea = IMAGE_BASE + parse_int(near_rva, "near_rva")
        window = parse_int(target.get("near_window", 0x400), "near_window")
        if abs(ea - near_ea) > window:
            return False

    return True


def matching_operands(ea, target_ea=None, offset=None):
    insn = decode_insn(ea)
    if insn is None:
        return []

    matches = []
    for index in range(8):
        op = insn.ops[index]
        if op.type == ida_ua.o_void:
            break

        if target_ea is not None:
            if op.type in (ida_ua.o_mem, ida_ua.o_displ, ida_ua.o_near, ida_ua.o_far) and op.addr == target_ea:
                matches.append((insn, index, op))
            elif op.type == ida_ua.o_imm and op.value == target_ea:
                matches.append((insn, index, op))

        if offset is not None:
            if op.type == ida_ua.o_displ and op.addr == offset:
                matches.append((insn, index, op))
            elif op.type == ida_ua.o_imm and op.value == offset:
                matches.append((insn, index, op))

    return matches


def refs_to_global(target_ea, target):
    refs = []
    seen = set()

    for xref in idautils.XrefsTo(target_ea, 0):
        ea = xref.frm
        if ea in seen or not ida_bytes.is_code(ida_bytes.get_flags(ea)):
            continue
        if not target_matches_filters(target, ea):
            continue
        matches = matching_operands(ea, target_ea=target_ea)
        if not matches:
            continue
        seen.add(ea)
        refs.append((ea, matches[0]))
        if len(refs) >= target_max_refs(target):
            return refs

    if refs:
        return refs

    start, end = target_range(target)
    for ea in iter_code_heads(start, end):
        if ea in seen or not target_matches_filters(target, ea):
            continue
        matches = matching_operands(ea, target_ea=target_ea)
        if not matches:
            continue
        seen.add(ea)
        refs.append((ea, matches[0]))
        if len(refs) >= target_max_refs(target):
            break

    return refs


def refs_to_field_offset(offset, target):
    refs = []
    start, end = target_range(target)
    for ea in iter_code_heads(start, end):
        if not target_matches_filters(target, ea):
            continue
        matches = matching_operands(ea, offset=offset)
        if not matches:
            continue
        refs.append((ea, matches[0]))
        if len(refs) >= target_max_refs(target):
            break
    return refs


def quality_from_mask(length, fixed, wildcards):
    if length <= 0:
        return "bad", 0
    wildcard_ratio = wildcards / float(length)
    score = 100
    score -= int(wildcard_ratio * 35)
    if length > 64:
        score -= int((length - 64) / 8)
    if fixed < 8:
        score -= 12
    score = max(0, min(100, score))
    if score >= 90:
        return "excellent", score
    if score >= 75:
        return "good", score
    if score >= 60:
        return "ok", score
    return "fragile", score


def make_entry(name, target, match_ea, match_data, resolver_type):
    pattern = make_unique_pattern(match_ea)
    if pattern is None:
        return None

    ida_pattern, code_bytes, code_mask, length = pattern
    insn, op_index, op = match_data if match_data else (decode_insn(match_ea), -1, None)
    if insn is None:
        return None

    fixed = sum(1 for char in code_mask if char == "x")
    wildcards = sum(1 for char in code_mask if char == "?")
    quality, score = quality_from_mask(length, fixed, wildcards)
    func_ea = function_start(match_ea)
    result_type = target_result_type(target, resolver_type)

    entry = {
        "pattern": ida_pattern,
        "bytes": code_bytes,
        "mask": code_mask,
        "module": target_string(target, "module", MODULE_NAME),
        "raw_name": name,
        "display_name": name,
        "category": target_string(target, "category", "game"),
        "result_type": result_type,
        "importance": target_string(target, "importance", "required"),
        "required": bool(target.get("required", True)),
        "status": "generated",
        "source": "cs2_offset_signer",
        "source_project": "cs2sign",
        "rva": hex_rva(func_ea),
        "pattern_rva": hex_rva(match_ea),
        "pattern_offset": match_ea - func_ea,
        "address_offset": 0,
        "length": length,
        "description": target_string(target, "description", ""),
        "confidence": score,
        "quality": quality,
        "quality_score": score,
        "fixed_bytes": fixed,
        "wildcards": wildcards,
        "xref": {
            "rva": hex_rva(match_ea),
            "function_rva": hex_rva(func_ea),
            "function": function_name(match_ea),
            "mnemonic": idc.print_insn_mnem(match_ea),
        },
    }

    if resolver_type == "rip_relative":
        width = operand_width(insn, op)
        entry["resolver"] = {
            "type": "rip_relative",
            "result_type": result_type,
            "instruction_offset": 0,
            "instruction_size": insn.size,
            "operand_index": op_index,
            "operand_offset": op.offb,
            "operand_size": width,
            "add": insn.size,
            "target_rva": target_string(target, "rva", target_string(target, "target_rva", "")),
            "formula": "match + instruction_size + disp",
        }
    elif resolver_type == "instruction_displacement":
        width = operand_width(insn, op)
        entry["resolver"] = {
            "type": "instruction_displacement",
            "result_type": result_type,
            "instruction_offset": 0,
            "instruction_size": insn.size,
            "operand_index": op_index,
            "operand_offset": op.offb,
            "operand_size": width,
            "expected": hex(target_int(target, "offset", "field_offset")),
            "formula": "read displacement at match + operand_offset",
        }
    else:
        entry["resolver"] = {
            "type": "direct_match",
            "result_type": result_type,
            "target_rva": target_string(target, "rva", ""),
            "formula": "match",
        }

    return entry


def candidate_rank(entry):
    return (
        int(entry.get("quality_score", 0)),
        -int(entry.get("length", 9999)),
        -int(entry.get("wildcards", 9999)),
    )


def select_entries(name, target, refs, resolver_type):
    candidates = []
    for match_ea, match_data in refs:
        entry = make_entry(name, target, match_ea, match_data, resolver_type)
        if entry is None:
            continue
        candidates.append(entry)

    candidates.sort(key=candidate_rank, reverse=True)
    max_candidates = max(1, target_max_candidates(target))
    return candidates[:max_candidates]


def process_direct_rva(target):
    name = target["name"]
    rva = target_int(target, "rva")
    ea = IMAGE_BASE + rva
    if not ida_bytes.is_mapped(ea):
        raise ValueError("{} maps outside the database".format(hex(rva)))
    entry = make_entry(name, target, ea, None, "direct_match")
    return [entry] if entry else []


def process_global_rva(target):
    rva = target_int(target, "rva", "target_rva", "global_rva")
    target_ea = IMAGE_BASE + rva
    if not ida_bytes.is_mapped(target_ea):
        raise ValueError("{} maps outside the database".format(hex(rva)))
    refs = refs_to_global(target_ea, target)
    return select_entries(target["name"], target, refs, "rip_relative")


def process_field_offset(target):
    offset = target_int(target, "offset", "field_offset")
    refs = refs_to_field_offset(offset, target)
    return select_entries(target["name"], target, refs, "instruction_displacement")


def process_target(target):
    kind = target["type"]
    if kind in ("direct", "direct_rva", "function", "function_rva"):
        return process_direct_rva(target)
    if kind in ("global", "global_rva", "rip", "rip_relative"):
        return process_global_rva(target)
    if kind in ("field", "field_offset", "member", "member_offset", "displacement"):
        return process_field_offset(target)
    raise ValueError("unknown target type: " + kind)


def output_name(name, index, total):
    if total <= 1:
        return name
    return "{}_{}".format(name, index + 1)


def run():
    ida_auto.auto_wait()

    config_path = find_config_path()
    if not config_path:
        log("No offset target config found.")
        log("Expected one of: {}_offset_targets.json or offset_targets.json".format(MODULE_NAME))
        return None

    targets = [target for target in normalize_targets(load_json(config_path)) if target_module_matches(target)]
    log("module: {}".format(MODULE_NAME))
    log("base: {}".format(hex(IMAGE_BASE)))
    log("config: {}".format(config_path))
    log("targets: {}".format(len(targets)))

    started = time.time()
    results = {}
    failures = {}

    for target in targets:
        name = target["name"]
        try:
            entries = process_target(target)
            if not entries:
                failures[name] = "no unique candidate"
                log("FAIL  {} ({})".format(name, failures[name]))
                continue
            for index, entry in enumerate(entries):
                key = output_name(name, index, len(entries))
                results[key] = entry
            log("OK    {} ({} candidate{})".format(name, len(entries), "" if len(entries) == 1 else "s"))
        except Exception as exc:
            failures[name] = str(exc)
            log("FAIL  {} ({})".format(name, exc))
            traceback.print_exc()

    elapsed = round(time.time() - started, 2)
    output = {
        "_metadata": {
            "generator": "cs2_offset_signer.py",
            "ida_version": str(idaapi.IDA_SDK_VERSION),
            "module": MODULE_NAME,
            "image_base": hex(IMAGE_BASE),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "config": os.path.basename(config_path),
            "targets": len(targets),
            "signatures_generated": len(results),
            "failed": len(failures),
            "failures": failures,
            "elapsed_seconds": elapsed,
        }
    }
    output.update(results)

    out_path = os.path.join(OUTPUT_DIR, MODULE_NAME + "_offset_signatures.json")
    with open(out_path, "w", encoding="utf-8") as file:
        json.dump(output, file, indent=2, ensure_ascii=False)

    log("done: {} generated, {} failed, {}s".format(len(results), len(failures), elapsed))
    log("written: " + out_path)
    return out_path


run()
