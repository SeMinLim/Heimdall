"""Snort rule parser for Heimdall prefilter compilation."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from ruleset_compiler.ir import (
    LiteralPattern,
    MatchContext,
    Rule,
    RuleSource,
    RulesetIR,
)


ACTIONS = (
    "alert",
    "drop",
    "block",
    "sdrop",
    "reject",
    "pass",
    "log",
    "rewrite",
    "activate",
    "dynamic",
)

RULE_START_RE = re.compile(rf"^\s*({'|'.join(ACTIONS)})\b")
CONTENT_RE = re.compile(r'^content\s*:\s*(!?)\s*"((?:\\.|[^"\\])*)"\s*(.*)$', re.DOTALL)
RAW_SO_RULE_RE = re.compile(
    r'R"\[Snort_SO_Rule\]\((.*?)\)\[Snort_SO_Rule\]"', re.DOTALL
)

STICKY_BUFFERS = {
    "payload",
    "pkt_data",
    "raw_data",
    "file_data",
    "js_data",
    "vba_data",
    "base64_data",
    "http_uri",
    "http_raw_uri",
    "http_header",
    "http_raw_header",
    "http_client_body",
    "http_raw_body",
    "http_cookie",
    "http_raw_cookie",
    "http_method",
    "http_param",
    "http_stat_code",
    "http_stat_msg",
    "http_version",
    "http_request_line",
    "http_raw_request",
    "http_raw_status",
    "http_user_agent",
    "http_host",
    "http_raw_host",
    "http_true_ip",
    "http2_header",
    "http2_data",
    "dns_query",
    "sip_header",
    "sip_body",
    "smtp_data",
}

CONTENT_MODIFIER_KEYS = {
    "nocase",
    "fast_pattern",
    "offset",
    "depth",
    "distance",
    "within",
    "startswith",
    "endswith",
    "width",
    "rawbytes",
}

ABSOLUTE_POSITION_KEYS = ("offset", "depth", "startswith", "endswith")
RELATIVE_POSITION_KEYS = ("distance", "within")
POSITION_KEYS = ABSOLUTE_POSITION_KEYS + RELATIVE_POSITION_KEYS
BYTE_OP_PREFIXES = ("byte_test", "byte_jump", "byte_extract", "byte_math")


def empty_str_dict() -> dict[str, str]:
    return {}


def empty_str_list() -> list[str]:
    return []


@dataclass(frozen=True, slots=True)
class SnortRuleId:
    source: str
    file: str
    line: int
    gid: str
    sid: str
    rev: str

    @property
    def native_id(self) -> str:
        if self.sid:
            gid = self.gid or "1"
            rev = f":{self.rev}" if self.rev else ""
            return f"{gid}:{self.sid}{rev}"
        return f"{self.file}:{self.line}"


@dataclass(frozen=True, slots=True)
class SnortRuleRecord:
    rule_id: SnortRuleId
    action: str
    proto: str
    services: tuple[str, ...]
    msg: str
    has_pcre: bool
    has_regex: bool
    has_flowbits: bool
    has_byte_ops: bool
    has_so_eval: bool


@dataclass(frozen=True, slots=True)
class SnortContentRecord:
    rule_id: SnortRuleId
    source: str
    file: str
    line: int
    content_index: int
    action: str
    proto: str
    services: tuple[str, ...]
    buffer: str
    raw_text: str
    pattern: bytes
    negated: bool
    nocase: bool
    fast_pattern: bool
    modifiers: dict[str, str] = field(default_factory=empty_str_dict)
    has_pcre: bool = False
    has_regex: bool = False
    has_flowbits: bool = False
    has_byte_ops: bool = False
    has_so_eval: bool = False

    @property
    def position_signature(self) -> tuple[tuple[str, str], ...]:
        return tuple(
            (key, self.modifiers.get(key, ""))
            for key in POSITION_KEYS
            if key in self.modifiers
        )


@dataclass(frozen=True, slots=True)
class SnortAnchorSelection:
    content: SnortContentRecord
    anchor: bytes
    anchor_offset: int
    anchor_n: int
    selection: str
    rarity: int


@dataclass(slots=True)
class SnortParseStats:
    skipped_lines: int = 0
    invalid_rules: int = 0
    invalid_contents: int = 0
    warnings: list[str] = field(default_factory=empty_str_list)


def parse_snort_rules(
    input_path: Path,
    *,
    include_so_source: bool = True,
    include_so_stubs: bool = True,
    include_builtins: bool = True,
    include_negated: bool = False,
    anchor_n: int = 8,
) -> RulesetIR:
    if anchor_n <= 0:
        raise ValueError("anchor_n must be positive")

    stats = SnortParseStats()
    ir = RulesetIR()
    source_ids: dict[tuple[str, str], int] = {}
    context_ids: dict[tuple[str, str], int] = {}
    parsed_rules: list[tuple[int, SnortRuleRecord, list[SnortContentRecord]]] = []

    for path, source, parser_kind in _collect_inputs(
        input_path,
        include_so_source=include_so_source,
        include_so_stubs=include_so_stubs,
        include_builtins=include_builtins,
    ):
        source_id = _source_id(ir, source_ids, source, path)
        iterator = (
            _iter_so_source_rules(path, stats)
            if parser_kind == "so_source"
            else _iter_rule_statements(path, source, stats)
        )

        for statement, statement_source, line in iterator:
            rule, contents = parse_snort_rule_statement(
                statement,
                source=statement_source,
                file_path=path,
                line=line,
                stats=stats,
            )
            if rule is None:
                continue

            parsed_rules.append((source_id, rule, contents))

    _emit_rule_prefilter_anchors(
        ir,
        parsed_rules=parsed_rules,
        context_ids=context_ids,
        anchor_n=anchor_n,
        include_negated=include_negated,
    )

    return ir


def parse_snort_statements(
    statements: Iterable[str],
    *,
    source_uri: str = "<statements>",
    source: str = "rules",
    include_negated: bool = False,
    anchor_n: int = 8,
) -> RulesetIR:
    if anchor_n <= 0:
        raise ValueError("anchor_n must be positive")

    stats = SnortParseStats()
    ir = RulesetIR()
    source_path = Path(source_uri)
    source_id = _source_id(ir, {}, source, source_path)
    context_ids: dict[tuple[str, str], int] = {}
    parsed_rules: list[tuple[int, SnortRuleRecord, list[SnortContentRecord]]] = []

    for line, statement in enumerate(statements, start=1):
        rule, contents = parse_snort_rule_statement(
            statement,
            source=source,
            file_path=source_path,
            line=line,
            stats=stats,
        )
        if rule is None:
            continue
        parsed_rules.append((source_id, rule, contents))

    _emit_rule_prefilter_anchors(
        ir,
        parsed_rules=parsed_rules,
        context_ids=context_ids,
        anchor_n=anchor_n,
        include_negated=include_negated,
    )

    return ir


def parse_snort_rule_statement(
    statement: str,
    *,
    source: str,
    file_path: Path,
    line: int,
    stats: SnortParseStats | None = None,
) -> tuple[SnortRuleRecord | None, list[SnortContentRecord]]:
    stats = stats or SnortParseStats()
    text = statement.strip()
    if not text or not RULE_START_RE.match(text):
        stats.invalid_rules += 1
        return None, []

    open_paren = text.find("(")
    close_paren = text.rfind(")")
    if open_paren == -1 or close_paren == -1 or open_paren >= close_paren:
        stats.invalid_rules += 1
        stats.warnings.append(f"could not find rule body at {file_path}:{line}")
        return None, []

    header_parts = text[:open_paren].strip().split()
    action = header_parts[0].lower() if header_parts else "unknown"
    proto = header_parts[1].lower() if len(header_parts) > 1 else "builtin"
    body = text[open_paren + 1 : close_paren]
    tokens = tokenize_body(body)

    option_values: dict[str, list[str]] = defaultdict(list)
    for token in tokens:
        key, value = option_key_value(token)
        if key:
            option_values[key].append(value)

    gid = option_values.get("gid", ["1"])[-1].strip()
    sid = option_values.get("sid", [""])[-1].strip()
    rev = option_values.get("rev", [""])[-1].strip()
    msg = option_values.get("msg", [""])[-1].strip().strip('"')
    services = tuple(
        service.strip().lower()
        for value in option_values.get("service", [])
        for service in value.split(",")
        if service.strip()
    )

    keys = {leading_key(token) for token in tokens}
    has_pcre = "pcre" in keys
    has_regex = "regex" in keys
    has_flowbits = "flowbits" in keys
    has_byte_ops = any(key.startswith(BYTE_OP_PREFIXES) for key in keys)
    has_so_eval = any(token.strip().lower().startswith("so:eval") for token in tokens)

    rule_id = SnortRuleId(
        source=source,
        file=str(file_path),
        line=line,
        gid=gid,
        sid=sid,
        rev=rev,
    )
    rule = SnortRuleRecord(
        rule_id=rule_id,
        action=action,
        proto=proto,
        services=services,
        msg=msg,
        has_pcre=has_pcre,
        has_regex=has_regex,
        has_flowbits=has_flowbits,
        has_byte_ops=has_byte_ops,
        has_so_eval=has_so_eval,
    )

    records: list[SnortContentRecord] = []
    current_buffer = "payload"
    content_index = 0

    for index, token in enumerate(tokens):
        key = leading_key(token)
        content_match = CONTENT_RE.match(token)
        if content_match:
            content_index += 1
            negated = bool(content_match.group(1))
            raw_content = content_match.group(2)
            modifier_tokens = split_inline_options(content_match.group(3))

            for next_token in tokens[index + 1 :]:
                next_key = leading_key(next_token)
                if next_key == "content" or next_key in STICKY_BUFFERS:
                    break
                if next_key in CONTENT_MODIFIER_KEYS:
                    modifier_tokens.append(next_token)

            modifiers: dict[str, str] = {}
            for modifier in modifier_tokens:
                mod_key, mod_value = option_key_value(modifier)
                if mod_key:
                    modifiers[mod_key] = mod_value

            try:
                pattern = normalize_content(raw_content)
            except ValueError as error:
                stats.invalid_contents += 1
                stats.warnings.append(f"{error} at {file_path}:{line}")
                continue

            records.append(
                SnortContentRecord(
                    rule_id=rule_id,
                    source=source,
                    file=str(file_path),
                    line=line,
                    content_index=content_index,
                    action=action,
                    proto=proto,
                    services=services,
                    buffer=current_buffer,
                    raw_text=raw_content,
                    pattern=pattern,
                    negated=negated,
                    nocase="nocase" in modifiers,
                    fast_pattern="fast_pattern" in modifiers,
                    modifiers=modifiers,
                    has_pcre=has_pcre,
                    has_regex=has_regex,
                    has_flowbits=has_flowbits,
                    has_byte_ops=has_byte_ops,
                    has_so_eval=has_so_eval,
                )
            )
            continue

        if key in STICKY_BUFFERS:
            current_buffer = key

    return rule, records


def tokenize_body(body: str) -> list[str]:
    tokens: list[str] = []
    buffer: list[str] = []
    in_quote = False
    index = 0
    while index < len(body):
        char = body[index]
        if in_quote:
            if char == "\\" and index + 1 < len(body):
                buffer.append(char)
                buffer.append(body[index + 1])
                index += 2
                continue
            if char == '"':
                in_quote = False
            buffer.append(char)
        else:
            if char == '"':
                in_quote = True
                buffer.append(char)
            elif char == ";":
                token = "".join(buffer).strip()
                if token:
                    tokens.append(token)
                buffer = []
            else:
                buffer.append(char)
        index += 1

    token = "".join(buffer).strip()
    if token:
        tokens.append(token)
    return tokens


def normalize_content(text: str) -> bytes:
    data = bytearray()
    index = 0
    while index < len(text):
        char = text[index]
        if char == "|":
            end = text.find("|", index + 1)
            if end == -1:
                data.extend(text[index:].encode("latin-1", errors="replace"))
                break
            data.extend(parse_hex_block(text[index + 1 : end].strip()))
            index = end + 1
        elif char == "\\" and index + 1 < len(text):
            data.extend(text[index + 1].encode("latin-1", errors="replace"))
            index += 2
        else:
            data.extend(char.encode("latin-1", errors="replace"))
            index += 1
    return bytes(data)


def ascii_lower_bytes(data: bytes) -> bytes:
    return bytes(byte + 32 if 0x41 <= byte <= 0x5A else byte for byte in data)


def anchor_windows(
    record: SnortContentRecord, anchor_n: int, *, include_negated: bool = False
) -> Iterable[tuple[int, bytes, tuple[bytes, bool]]]:
    if (record.negated and not include_negated) or len(record.pattern) < anchor_n:
        return
    for offset in range(0, len(record.pattern) - anchor_n + 1):
        raw_anchor = record.pattern[offset : offset + anchor_n]
        canonical = ascii_lower_bytes(raw_anchor) if record.nocase else raw_anchor
        yield offset, raw_anchor, (canonical, record.nocase)


def build_anchor_frequency(
    contents: Sequence[SnortContentRecord],
    anchor_n: int,
    *,
    include_negated: bool = False,
) -> Counter[tuple[bytes, bool]]:
    frequency: Counter[tuple[bytes, bool]] = Counter()
    for record in contents:
        for _, _, key in anchor_windows(
            record, anchor_n, include_negated=include_negated
        ):
            frequency[key] += 1
    return frequency


def select_rule_anchor(
    rule_contents: Sequence[SnortContentRecord],
    anchor_n: int,
    frequency: Counter[tuple[bytes, bool]],
    *,
    include_negated: bool = False,
) -> tuple[SnortAnchorSelection | None, str]:
    positive = [
        record for record in rule_contents if include_negated or not record.negated
    ]
    if not positive:
        return None, "no_positive_content"

    candidates: list[
        tuple[
            tuple[int, int, int, int, int],
            SnortContentRecord,
            int,
            bytes,
            tuple[bytes, bool],
            str,
        ]
    ] = []
    for record in positive:
        for offset, raw_anchor, key in anchor_windows(
            record, anchor_n, include_negated=include_negated
        ):
            selection = "fast_pattern" if record.fast_pattern else "content"
            score = (
                0 if record.fast_pattern else 1,
                frequency[key],
                -len(record.pattern),
                record.content_index,
                offset,
            )
            candidates.append((score, record, offset, raw_anchor, key, selection))

    if not candidates:
        return None, "positive_content_shorter_than_anchor"

    _, record, offset, raw_anchor, key, selection = min(
        candidates, key=lambda item: item[0]
    )
    return (
        SnortAnchorSelection(
            content=record,
            anchor=raw_anchor,
            anchor_offset=offset,
            anchor_n=anchor_n,
            selection=selection,
            rarity=frequency[key],
        ),
        "anchored",
    )


def parse_hex_block(text: str) -> bytes:
    data = bytearray()
    for token in text.split():
        chunks = (
            [token]
            if len(token) <= 2
            else [token[i : i + 2] for i in range(0, len(token), 2)]
        )
        for chunk in chunks:
            if len(chunk) != 2 or not re.fullmatch(r"[0-9A-Fa-f]{2}", chunk):
                raise ValueError(f"invalid hex byte '{chunk}' in |{text}|")
            data.append(int(chunk, 16))
    return bytes(data)


def leading_key(token: str) -> str:
    match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)", token)
    return match.group(1).lower() if match else ""


def option_key_value(option: str) -> tuple[str, str]:
    text = option.strip().strip(",").strip()
    if not text:
        return "", ""
    if ":" in text:
        key, value = text.split(":", 1)
        return key.strip().lower(), value.strip()
    parts = text.split(None, 1)
    key = parts[0].strip().lower()
    value = parts[1].strip() if len(parts) > 1 else ""
    return key, value


def split_inline_options(tail: str) -> list[str]:
    tail = tail.strip()
    if tail.startswith(","):
        tail = tail[1:]
    if not tail:
        return []
    return [part.strip() for part in tail.split(",") if part.strip()]


def paren_delta_outside_quotes(line: str) -> tuple[int, bool]:
    in_quote = False
    escaped = False
    delta = 0
    saw_open = False
    for char in line:
        if in_quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_quote = False
        else:
            if char == '"':
                in_quote = True
            elif char == "(":
                delta += 1
                saw_open = True
            elif char == ")":
                delta -= 1
    return delta, saw_open


def _iter_rule_statements(
    path: Path, source: str, stats: SnortParseStats
) -> Iterable[tuple[str, str, int]]:
    pending: list[str] = []
    start_line = 0
    balance = 0
    saw_open = False

    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.rstrip("\n")
            stripped = line.strip()

            if not pending:
                if (
                    not stripped
                    or stripped.startswith("#")
                    or stripped.startswith("include ")
                ):
                    continue
                if not RULE_START_RE.match(stripped):
                    stats.skipped_lines += 1
                    continue
                pending = [line]
                start_line = line_number
                balance, saw_open = paren_delta_outside_quotes(line)
            else:
                pending.append(line)
                delta, line_saw_open = paren_delta_outside_quotes(line)
                balance += delta
                saw_open = saw_open or line_saw_open

            if pending and saw_open and balance <= 0:
                yield "\n".join(pending), source, start_line
                pending = []
                start_line = 0
                balance = 0
                saw_open = False

    if pending:
        stats.invalid_rules += 1
        stats.warnings.append(f"unterminated rule at {path}:{start_line}")


def _iter_so_source_rules(
    path: Path, stats: SnortParseStats
) -> Iterable[tuple[str, str, int]]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    for match in RAW_SO_RULE_RE.finditer(text):
        rule_text = match.group(1).strip()
        line_number = text.count("\n", 0, match.start(1)) + 1
        if rule_text:
            yield rule_text, "so_source", line_number
    if "Snort_SO_Rule" in text and not RAW_SO_RULE_RE.search(text):
        stats.warnings.append(f"found SO marker but no parseable raw rule in {path}")


def _collect_inputs(
    root: Path,
    *,
    include_so_source: bool,
    include_so_stubs: bool,
    include_builtins: bool,
) -> list[tuple[Path, str, str]]:
    inputs: list[tuple[Path, str, str]] = []
    if root.is_file():
        return [(root, "rules", "rules_file")]

    if (root / "rules").is_dir():
        for path in sorted((root / "rules").glob("*.rules")):
            inputs.append((path, "rules", "rules_file"))
    else:
        for path in sorted(root.glob("*.rules")):
            inputs.append((path, "rules", "rules_file"))

    if include_so_stubs and (root / "so_rules").is_dir():
        for path in sorted((root / "so_rules").glob("*.rules")):
            inputs.append((path, "so_stub", "rules_file"))
    if include_builtins and (root / "builtins").is_dir():
        for path in sorted((root / "builtins").glob("*.rules")):
            inputs.append((path, "builtins", "rules_file"))
    if include_so_source and (root / "so_rules" / "src").is_dir():
        for path in sorted((root / "so_rules" / "src").rglob("*.cc")):
            inputs.append((path, "so_source", "so_source"))
    return inputs


def _source_id(
    ir: RulesetIR, source_ids: dict[tuple[str, str], int], source: str, path: Path
) -> int:
    key = (source, str(path))
    if key not in source_ids:
        source_id = ir.next_source_id()
        source_ids[key] = source_id
        ir.sources.append(
            RuleSource(
                source_id=source_id,
                source_type="snort_rules",
                uri=str(path),
                native_engine="snort",
                metadata={"source": source},
            )
        )
    return source_ids[key]


def _emit_rule_prefilter_anchors(
    ir: RulesetIR,
    *,
    parsed_rules: Sequence[tuple[int, SnortRuleRecord, list[SnortContentRecord]]],
    context_ids: dict[tuple[str, str], int],
    anchor_n: int,
    include_negated: bool,
) -> None:
    all_contents = [content for _, _, contents in parsed_rules for content in contents]
    frequency = build_anchor_frequency(
        all_contents,
        anchor_n,
        include_negated=include_negated,
    )

    for source_id, rule, contents in parsed_rules:
        selection, reason = select_rule_anchor(
            contents,
            anchor_n,
            frequency,
            include_negated=include_negated,
        )
        rule_uid = ir.next_rule_uid()
        ir.rules.append(
            _to_ir_rule(
                rule_uid,
                source_id,
                rule,
                contents,
                prefilter_anchor_reason=reason,
            )
        )
        if selection is None:
            continue

        content = selection.content
        context_id = _context_id(ir, context_ids, content.proto, content.buffer)
        ir.patterns.append(
            _to_literal_pattern(
                pattern_uid=ir.next_pattern_uid(),
                rule_uid=rule_uid,
                context_id=context_id,
                selection=selection,
            )
        )


def _context_id(
    ir: RulesetIR, context_ids: dict[tuple[str, str], int], proto: str, buffer: str
) -> int:
    key = (proto or "any", buffer or "payload")
    if key not in context_ids:
        context_id = ir.next_context_id()
        context_ids[key] = context_id
        ir.contexts.append(
            MatchContext(
                context_id=context_id,
                protocol=key[0],
                buffer_kind=key[1],
                normalization="snort",
                direction="either",
                stream_scope="packet",
            )
        )
    return context_ids[key]


def _to_ir_rule(
    rule_uid: int,
    source_id: int,
    rule: SnortRuleRecord,
    contents: Sequence[SnortContentRecord],
    *,
    prefilter_anchor_reason: str,
) -> Rule:
    return Rule(
        rule_uid=rule_uid,
        source_id=source_id,
        native_id=rule.rule_id.native_id,
        native_engine="snort",
        action=rule.action,
        message=rule.msg or None,
        source_line=rule.rule_id.line,
        metadata={
            "source": rule.rule_id.source,
            "file": rule.rule_id.file,
            "gid": rule.rule_id.gid,
            "sid": rule.rule_id.sid,
            "rev": rule.rule_id.rev,
            "protocol": rule.proto,
            "services": list(rule.services),
            "content_count": len(contents),
            "positive_content_count": sum(
                1 for content in contents if not content.negated
            ),
            "negated_content_count": sum(1 for content in contents if content.negated),
            "prefilter_anchor_reason": prefilter_anchor_reason,
            "has_pcre": rule.has_pcre,
            "has_regex": rule.has_regex,
            "has_flowbits": rule.has_flowbits,
            "has_byte_ops": rule.has_byte_ops,
            "has_so_eval": rule.has_so_eval,
        },
    )


def _to_literal_pattern(
    *,
    pattern_uid: int,
    rule_uid: int,
    context_id: int,
    selection: SnortAnchorSelection,
) -> LiteralPattern:
    content = selection.content
    return LiteralPattern(
        pattern_uid=pattern_uid,
        rule_uid=rule_uid,
        context_id=context_id,
        data=selection.anchor,
        nocase=content.nocase,
        offset=_parse_int(content.modifiers.get("offset")),
        depth=_parse_int(content.modifiers.get("depth")),
        pattern_type="SNORT_RULE_ANCHOR",
        source_line=content.line,
        metadata={
            "source": content.source,
            "file": content.file,
            "content_index": content.content_index,
            "buffer": content.buffer,
            "raw_text": content.raw_text,
            "negated": content.negated,
            "fast_pattern": content.fast_pattern,
            "origin_length": len(content.pattern),
            "origin_pattern_hex": content.pattern.hex(),
            "anchor_n": selection.anchor_n,
            "anchor_offset": selection.anchor_offset,
            "anchor_selection": selection.selection,
            "anchor_rarity": selection.rarity,
            "modifiers": dict(content.modifiers),
            "position_signature": list(content.position_signature),
            "services": list(content.services),
            "has_pcre": content.has_pcre,
            "has_regex": content.has_regex,
            "has_flowbits": content.has_flowbits,
            "has_byte_ops": content.has_byte_ops,
            "has_so_eval": content.has_so_eval,
        },
    )


def _parse_int(value: str | None) -> int | None:
    if value is None or not str(value).strip():
        return None
    try:
        return int(str(value).strip(), 0)
    except ValueError:
        return None


__all__ = [
    "SnortAnchorSelection",
    "SnortContentRecord",
    "SnortParseStats",
    "SnortRuleId",
    "SnortRuleRecord",
    "anchor_windows",
    "ascii_lower_bytes",
    "build_anchor_frequency",
    "normalize_content",
    "parse_hex_block",
    "parse_snort_rule_statement",
    "parse_snort_rules",
    "parse_snort_statements",
    "select_rule_anchor",
    "tokenize_body",
]
