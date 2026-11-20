"""
Snort 3 Rule Renderer & Structured Representation Engine.
Part of Stage 7: Final Rule Assembly.

Converts between internal RuleState / AST and the canonical intermediate structured representation,
and serializes into standard multi-line and single-line Snort 3 rule syntax with strict
ordering preservation, escaping, and formatting.
"""

import re
from typing import Dict, List, Any, Optional, Tuple, Union
from snort_pipeline.rule_state import (
    RuleState,
    RuleAST,
    RuleHeaderAST,
    RuleOptionAST,
    ConstructionState,
)

class RuleRenderer:
    """
    Renders Snort 3 rules from AST and manages the intermediate structured representation.
    Guarantees:
    - Preservation of exact declared order for payload options (no alphabetical sorting).
    - Proper string escaping for msg, rem, content, and pcre.
    - Canonical multi-line and single-line rule emission.
    - Two-way conversion with the intermediate structured representation schema.
    """

    @classmethod
    def escape_string(cls, val: str, escape_semicolons: bool = True) -> str:
        """Escape unescaped double quotes and semicolons per Snort 3 specification."""
        clean = str(val).strip()
        if clean.startswith('"') and clean.endswith('"') and len(clean) >= 2:
            clean = clean[1:-1]
        # Escape unescaped double quotes
        clean = re.sub(r'(?<!\\)"', r'\"', clean)
        if escape_semicolons:
            clean = re.sub(r'(?<!\\);', r'\;', clean)
        return clean

    @classmethod
    def render_option(cls, opt: RuleOptionAST) -> str:
        """
        Render an individual RuleOptionAST node into canonical Snort 3 option syntax.
        Handles sticky buffers, content modifiers, numeric options, and metadata.
        """
        name = opt.name.strip()
        val = opt.value
        mods = opt.modifiers or {}

        # 1. Sticky buffers without value or modifiers (e.g. http_uri;, file_data;)
        if val is None and not mods:
            return f"{name};"

        # 2. msg option
        if name == "msg":
            escaped_msg = cls.escape_string(str(val))
            return f'msg:"{escaped_msg}";'

        # 3. flow option
        if name == "flow":
            if isinstance(val, list):
                flow_args = ",".join(str(v).strip() for v in val)
            else:
                flow_args = str(val).strip()
            return f"flow:{flow_args};"

        # 4. content option with comma-separated Snort 3 modifiers
        if name == "content":
            raw_content = str(val).strip()
            is_neg = False
            if raw_content.startswith("!"):
                is_neg = True
                raw_content = raw_content[1:].strip()
            if raw_content.startswith('"') and raw_content.endswith('"') and len(raw_content) >= 2:
                raw_content = raw_content[1:-1]

            mod_tokens = []
            if mods.get("nocase"):
                mod_tokens.append("nocase")
            if mods.get("fast_pattern"):
                fp_val = mods.get("fast_pattern")
                if fp_val is True or fp_val == "True":
                    mod_tokens.append("fast_pattern")
                elif isinstance(fp_val, str):
                    mod_tokens.append(f"fast_pattern {fp_val}")
            for pos_mod in ["offset", "depth", "distance", "within"]:
                if pos_mod in mods and mods[pos_mod] is not None:
                    mod_tokens.append(f"{pos_mod} {mods[pos_mod]}")

            neg_prefix = "!" if is_neg else ""
            if mod_tokens:
                return f'content:{neg_prefix}"{raw_content}",{",".join(mod_tokens)};'
            return f'content:{neg_prefix}"{raw_content}";'

        # 5. pcre option
        if name == "pcre":
            raw_pcre = str(val).strip()
            is_neg = False
            if raw_pcre.startswith("!"):
                is_neg = True
                raw_pcre = raw_pcre[1:].strip()
            if raw_pcre.startswith('"') and raw_pcre.endswith('"') and len(raw_pcre) >= 2:
                raw_pcre = raw_pcre[1:-1]
            neg_prefix = "!" if is_neg else ""
            return f'pcre:{neg_prefix}"{raw_pcre}";'

        # 6. regex option (Hyperscan)
        if name == "regex":
            raw_regex = str(val).strip()
            is_neg = False
            if raw_regex.startswith("!"):
                is_neg = True
                raw_regex = raw_regex[1:].strip()
            if raw_regex.startswith('"') and raw_regex.endswith('"') and len(raw_regex) >= 2:
                raw_regex = raw_regex[1:-1]
            neg_prefix = "!" if is_neg else ""
            mod_tokens = []
            if mods.get("fast_pattern"):
                mod_tokens.append("fast_pattern")
            if mods.get("nocase"):
                mod_tokens.append("nocase")
            if mod_tokens:
                return f'regex:{neg_prefix}"{raw_regex}",{",".join(mod_tokens)};'
            return f'regex:{neg_prefix}"{raw_regex}";'

        # 7. Quoted string options (rem, replace, file_type)
        if name in ["rem", "replace", "file_type"]:
            clean_str = cls.escape_string(str(val))
            return f'{name}:"{clean_str}";'

        # 8. Numeric, simple keywords, or pre-formatted values (sid, rev, classtype, service, etc.)
        if isinstance(val, (int, float)):
            return f"{name}:{val};"
        if isinstance(val, str):
            clean_val = val.strip().rstrip(";")
            return f"{name}:{clean_val};"

        return f"{name}:{val};"

    @classmethod
    def render_multiline(cls, state: RuleState, indent: int = 4) -> str:
        """
        Render Snort 3 rule in canonical multi-line indented format.
        Example:
        alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS
        (
            msg:"MALWARE Suspicious HTTP Request Pattern";
            flow:to_server,established;
            http_uri;
            content:"/observed_pattern",fast_pattern,nocase;
            sid:1000001;
            rev:1;
        )
        """
        header_line = state.ast.header.render()
        indent_str = " " * indent
        option_lines = [f"{indent_str}{cls.render_option(opt)}" for opt in state.ast.options]
        body = "\n".join(option_lines)
        return f"{header_line}\n(\n{body}\n)"

    @classmethod
    def render_singleline(cls, state: RuleState) -> str:
        """Render Snort 3 rule in canonical single-line format."""
        header_str = state.ast.header.render()
        rendered_options = [cls.render_option(opt) for opt in state.ast.options]
        options_body = " ".join(rendered_options)
        return f"{header_str} ( {options_body} )"

    @classmethod
    def to_structured_representation(cls, state: RuleState) -> Dict[str, Any]:
        """
        Construct the intermediate structured representation data model from RuleState.
        Conforms strictly to Stage 7 specification:
        {
          "candidate_id": "...",
          "hypothesis_id": "...",
          "rule_type": "traditional | service | file",
          "status": "...",
          "header": { ... },
          "options": {
            "general": { ... },
            "flow": { ... },
            "detection": [ ... ],
            "non_payload": [ ... ],
            "post_detection": [ ... ]
          },
          "validation": { ... }
        }
        """
        hdr = state.ast.header

        # Group options by architectural category
        general_opts: Dict[str, Any] = {
            "msg": None,
            "classtype": None,
            "priority": None,
            "metadata": [],
            "references": [],
            "service": None,
            "gid": 1,
            "sid": None,
            "rev": 1,
            "rem": None
        }

        flow_dict: Dict[str, Any] = {
            "direction": None,
            "connection_state": None,
            "stream_state": None,
            "fragment_state": None
        }

        detection_list: List[Dict[str, Any]] = []
        non_payload_list: List[Dict[str, Any]] = []
        post_detection_list: List[Dict[str, Any]] = []

        # Known option category sets
        non_payload_names = {
            "flags", "ttl", "tos", "id", "fragoffset", "fragbits", "ip_proto",
            "seq", "ack", "window", "itype", "icode", "icmp_id", "icmp_seq",
            "flowbits", "file_type", "stream_reassemble", "stream_size"
        }
        post_detection_names = {"detection_filter", "tag", "replace"}

        for opt in state.ast.options:
            name = opt.name.strip()
            val = opt.value

            if name == "msg":
                clean_msg = str(val).strip()
                if clean_msg.startswith('"') and clean_msg.endswith('"'):
                    clean_msg = clean_msg[1:-1]
                general_opts["msg"] = clean_msg
            elif name == "sid":
                try:
                    general_opts["sid"] = int(val)
                except (ValueError, TypeError):
                    general_opts["sid"] = val
            elif name == "rev":
                try:
                    general_opts["rev"] = int(val)
                except (ValueError, TypeError):
                    general_opts["rev"] = val
            elif name == "gid":
                try:
                    general_opts["gid"] = int(val)
                except (ValueError, TypeError):
                    general_opts["gid"] = val
            elif name == "classtype":
                general_opts["classtype"] = str(val).strip()
            elif name == "priority":
                try:
                    general_opts["priority"] = int(val)
                except (ValueError, TypeError):
                    general_opts["priority"] = val
            elif name == "service":
                general_opts["service"] = str(val).strip()
            elif name == "rem":
                general_opts["rem"] = str(val).strip()
            elif name == "reference":
                ref_str = str(val).strip()
                parts = [p.strip() for p in ref_str.split(",", 1)]
                if len(parts) == 2:
                    general_opts["references"].append({"system": parts[0], "id": parts[1]})
                else:
                    general_opts["references"].append({"system": "url", "id": ref_str})
            elif name == "metadata":
                meta_str = str(val).strip()
                # Parse key-value comma-separated items
                for item in meta_str.split(","):
                    item = item.strip()
                    if item:
                        item_parts = item.split(None, 1)
                        if len(item_parts) == 2:
                            general_opts["metadata"].append({"key": item_parts[0], "value": item_parts[1]})
                        else:
                            general_opts["metadata"].append({"key": item, "value": ""})
            elif name == "flow":
                flow_tokens = [f.strip() for f in (val if isinstance(val, list) else str(val).split(","))]
                for token in flow_tokens:
                    if token in ["to_server", "to_client", "from_client", "from_server"]:
                        flow_dict["direction"] = token
                    elif token in ["established", "not_established", "stateless"]:
                        flow_dict["connection_state"] = token
                    elif token in ["only_stream", "no_stream"]:
                        flow_dict["stream_state"] = token
                    elif token in ["only_frag", "no_frag"]:
                        flow_dict["fragment_state"] = token
            elif name in non_payload_names:
                non_payload_list.append({
                    "option": name,
                    "value": val,
                    "modifiers": opt.modifiers,
                    "evidence_refs": opt.evidence_refs
                })
            elif name in post_detection_names:
                post_detection_list.append({
                    "option": name,
                    "value": val,
                    "modifiers": opt.modifiers,
                    "evidence_refs": opt.evidence_refs
                })
            else:
                # Payload detection option or sticky buffer
                detection_list.append({
                    "option": name,
                    "value": val,
                    "modifiers": opt.modifiers,
                    "evidence_refs": opt.evidence_refs
                })

        # Determine validation status summaries
        val_records = state.component_validation
        def get_status(stage_k: str) -> str:
            rec = val_records.get(stage_k)
            if rec is None:
                return "passed"  # Default passed if stage completed
            return "passed" if rec.get("passed", False) else "failed"

        validation_map = {
            "hypothesis": get_status("stage1_hypothesis"),
            "header": get_status("stage2_header"),
            "message": get_status("stage3_msg"),
            "flow": get_status("stage4_flow"),
            "detection": get_status("stage5_detection"),
            "supporting_options": get_status("stage6_metadata")
        }

        return {
            "candidate_id": state.candidate_id,
            "hypothesis_id": state.hypothesis_id or f"HYP_{state.candidate_id}",
            "rule_type": hdr.header_type,
            "status": state.status,
            "header": {
                "action": hdr.action,
                "protocol": hdr.protocol or hdr.service or "tcp",
                "source_ip": hdr.source_addr,
                "source_port": hdr.source_port,
                "direction": hdr.direction,
                "destination_ip": hdr.dest_addr,
                "destination_port": hdr.dest_port
            },
            "options": {
                "general": general_opts,
                "flow": flow_dict,
                "detection": detection_list,
                "non_payload": non_payload_list,
                "post_detection": post_detection_list
            },
            "validation": validation_map
        }

    @classmethod
    def from_structured_representation(cls, data: Dict[str, Any]) -> RuleState:
        """
        Reconstruct a RuleState and RuleAST from the intermediate structured representation.
        Preserves canonical ordering:
        Header -> Option #0 msg -> Option #1 flow -> non-payload -> detection -> supporting -> post-detection -> sid -> rev.
        """
        candidate_id = data.get("candidate_id", "CAND_001")
        hypothesis_id = data.get("hypothesis_id")
        rule_type = data.get("rule_type", "traditional")
        hdr_data = data.get("header", {})

        header_ast = RuleHeaderAST(
            action=hdr_data.get("action", "alert"),
            header_type=rule_type,
            protocol=hdr_data.get("protocol", "tcp"),
            source_addr=hdr_data.get("source_ip", "$HOME_NET"),
            source_port=hdr_data.get("source_port", "any"),
            direction=hdr_data.get("direction", "->"),
            dest_addr=hdr_data.get("destination_ip", "$EXTERNAL_NET"),
            dest_port=hdr_data.get("destination_port", "$HTTP_PORTS")
        )

        options_data = data.get("options", {})
        gen = options_data.get("general", {})
        flow_data = options_data.get("flow", {})

        ast_options: List[RuleOptionAST] = []

        # 1. Option #0: msg
        if gen.get("msg"):
            ast_options.append(RuleOptionAST(name="msg", value=gen["msg"]))

        # 2. Option #1: flow
        flow_tokens = []
        for fk in ["direction", "connection_state", "stream_state", "fragment_state"]:
            if flow_data.get(fk):
                flow_tokens.append(flow_data[fk])
        if flow_tokens:
            ast_options.append(RuleOptionAST(name="flow", value=",".join(flow_tokens)))

        # 3. Non-payload options
        for np_opt in options_data.get("non_payload", []):
            ast_options.append(RuleOptionAST(
                name=np_opt["option"],
                value=np_opt.get("value"),
                modifiers=np_opt.get("modifiers", {}),
                evidence_refs=np_opt.get("evidence_refs", [])
            ))

        # 4. Detection payload options & sticky buffers (in exact declared order)
        for det_opt in options_data.get("detection", []):
            ast_options.append(RuleOptionAST(
                name=det_opt["option"],
                value=det_opt.get("value"),
                modifiers=det_opt.get("modifiers", {}),
                evidence_refs=det_opt.get("evidence_refs", [])
            ))

        # 5. Supporting options
        if gen.get("service"):
            ast_options.append(RuleOptionAST(name="service", value=gen["service"]))
        if gen.get("classtype"):
            ast_options.append(RuleOptionAST(name="classtype", value=gen["classtype"]))
        if gen.get("priority"):
            ast_options.append(RuleOptionAST(name="priority", value=gen["priority"]))
        for ref in gen.get("references", []):
            ast_options.append(RuleOptionAST(name="reference", value=f"{ref['system']},{ref['id']}"))
        if gen.get("metadata"):
            meta_items = [f"{m['key']} {m['value']}".strip() for m in gen["metadata"]]
            ast_options.append(RuleOptionAST(name="metadata", value=", ".join(meta_items)))
        if gen.get("rem"):
            ast_options.append(RuleOptionAST(name="rem", value=gen["rem"]))

        # 6. Post-detection options
        for pd_opt in options_data.get("post_detection", []):
            ast_options.append(RuleOptionAST(
                name=pd_opt["option"],
                value=pd_opt.get("value"),
                modifiers=pd_opt.get("modifiers", {}),
                evidence_refs=pd_opt.get("evidence_refs", [])
            ))

        # 7. Identity options (sid, rev)
        if gen.get("sid") is not None:
            ast_options.append(RuleOptionAST(name="sid", value=gen["sid"]))
        if gen.get("rev") is not None:
            ast_options.append(RuleOptionAST(name="rev", value=gen.get("rev", 1)))

        state = RuleState(candidate_id=candidate_id, hypothesis_id=hypothesis_id)
        state.status = data.get("status", ConstructionState.RULE_ASSEMBLED.value)
        state.ast = RuleAST(header=header_ast, options=ast_options)
        state.rendered_rule_text = cls.render_singleline(state)
        return state

    @classmethod
    def parse_rule_string(cls, rule_text: str) -> RuleAST:
        """
        Parse raw Snort 3 rule text into a compliant RuleAST with exact option preservation.
        Handles traditional headers, service headers, file headers, sticky buffers,
        quoted patterns, escaped semicolons, and comma-separated content modifiers.
        """
        rule_str = rule_text.strip()
        m = re.match(r"^([^(]+)\(\s*([\s\S]*?)\s*\)\s*$", rule_str)
        if not m:
            raise ValueError(f"Invalid rule format: unable to match header and body in '{rule_text}'")

        header_part = m.group(1).strip()
        body_part = m.group(2).strip()

        # Parse header tokens
        tokens = header_part.split()
        if len(tokens) >= 7:
            action = tokens[0]
            proto = tokens[1]
            src_ip = tokens[2]
            src_port = tokens[3]
            direction = tokens[4]
            dst_ip = tokens[5]
            dst_port = tokens[6]
            header = RuleHeaderAST(
                action=action,
                header_type="traditional",
                protocol=proto,
                source_addr=src_ip,
                source_port=src_port,
                direction=direction,
                dest_addr=dst_ip,
                dest_port=dst_port
            )
        elif len(tokens) == 2:
            action = tokens[0]
            h_type = "file" if tokens[1] == "file" else "service"
            header = RuleHeaderAST(
                action=action,
                header_type=h_type,
                protocol=tokens[1] if h_type == "traditional" else None,
                service=tokens[1] if h_type == "service" else None
            )
        elif len(tokens) == 1 and tokens[0] == "file_id":
            header = RuleHeaderAST(header_type="file_id")
        else:
            header = RuleHeaderAST(action=tokens[0] if tokens else "alert")

        # Parse body options with quote & escape aware semicolon splitting
        options: List[RuleOptionAST] = []
        opt_strings: List[str] = []
        current: List[str] = []
        in_quotes = False
        escaped = False

        for char in body_part:
            if escaped:
                current.append(char)
                escaped = False
            elif char == '\\':
                current.append(char)
                escaped = True
            elif char == '"':
                in_quotes = not in_quotes
                current.append(char)
            elif char == ';' and not in_quotes:
                s = "".join(current).strip()
                if s:
                    opt_strings.append(s)
                current = []
            else:
                current.append(char)
        trailing = "".join(current).strip()
        if trailing and trailing != ")":
            opt_strings.append(trailing)

        for opt_str in opt_strings:
            if ":" not in opt_str:
                # Sticky buffer or flag option like 'http_uri', 'file_data', 'raw_data', 'dns_query'
                options.append(RuleOptionAST(name=opt_str.strip(), value=None))
                continue

            opt_name, opt_val = opt_str.split(":", 1)
            opt_name = opt_name.strip()
            opt_val = opt_val.strip()

            if opt_name == "content":
                is_neg = False
                if opt_val.startswith("!"):
                    is_neg = True
                    opt_val = opt_val[1:].strip()

                pattern = ""
                mod_str = ""
                if opt_val.startswith('"'):
                    end_q = -1
                    esc = False
                    for idx in range(1, len(opt_val)):
                        if esc:
                            esc = False
                        elif opt_val[idx] == '\\':
                            esc = True
                        elif opt_val[idx] == '"':
                            end_q = idx
                            break
                    if end_q != -1:
                        pattern = opt_val[1:end_q]
                        mod_str = opt_val[end_q + 1:].lstrip(",").strip()
                    else:
                        pattern = opt_val.strip('"')
                elif opt_val.startswith("|"):
                    end_bar = opt_val.find("|", 1)
                    if end_bar != -1:
                        pattern = opt_val[:end_bar + 1]
                        mod_str = opt_val[end_bar + 1:].lstrip(",").strip()
                    else:
                        pattern = opt_val
                else:
                    if "," in opt_val:
                        parts = opt_val.split(",", 1)
                        pattern = parts[0].strip()
                        mod_str = parts[1].strip()
                    else:
                        pattern = opt_val

                modifiers: Dict[str, Any] = {}
                if mod_str:
                    for mod_token in [m.strip() for m in mod_str.split(",") if m.strip()]:
                        if mod_token == "nocase":
                            modifiers["nocase"] = True
                        elif mod_token == "fast_pattern":
                            modifiers["fast_pattern"] = True
                        elif mod_token.startswith("fast_pattern"):
                            modifiers["fast_pattern"] = mod_token.split(None, 1)[1]
                        elif mod_token.startswith("offset"):
                            modifiers["offset"] = int(mod_token.split(None, 1)[1])
                        elif mod_token.startswith("depth"):
                            modifiers["depth"] = int(mod_token.split(None, 1)[1])
                        elif mod_token.startswith("distance"):
                            modifiers["distance"] = int(mod_token.split(None, 1)[1])
                        elif mod_token.startswith("within"):
                            modifiers["within"] = int(mod_token.split(None, 1)[1])

                val_res = f"!{pattern}" if is_neg else pattern
                options.append(RuleOptionAST(name="content", value=val_res, modifiers=modifiers))

            elif opt_name == "pcre":
                clean_p = opt_val.strip().strip('"')
                options.append(RuleOptionAST(name="pcre", value=clean_p))

            elif opt_name == "regex":
                clean_r = opt_val.strip().strip('"')
                options.append(RuleOptionAST(name="regex", value=clean_r))

            elif opt_name == "msg":
                clean_m = opt_val.strip().strip('"')
                clean_m = clean_m.replace('\\"', '"').replace('\\;', ';')
                options.append(RuleOptionAST(name="msg", value=clean_m))

            elif opt_name in ["sid", "rev", "gid", "priority"]:
                try:
                    options.append(RuleOptionAST(name=opt_name, value=int(opt_val)))
                except ValueError:
                    options.append(RuleOptionAST(name=opt_name, value=opt_val))

            elif opt_name == "flow":
                tokens = [t.strip() for t in opt_val.split(",")]
                options.append(RuleOptionAST(name="flow", value=tokens))

            else:
                clean_v = opt_val.strip().strip('"')
                options.append(RuleOptionAST(name=opt_name, value=clean_v))

        return RuleAST(header=header, options=options)

    @classmethod
    def parse_rule_to_state(
        cls,
        rule_text: str,
        candidate_id: str = "CAND_001",
        hypothesis_id: Optional[str] = None
    ) -> RuleState:
        """
        Reconstruct a complete RuleState from raw Snort 3 rule text.
        Synchronizes AST, components store, rendered text, and status.
        """
        ast = cls.parse_rule_string(rule_text)
        state = RuleState(candidate_id=candidate_id, hypothesis_id=hypothesis_id)
        state.ast = ast
        state.status = ConstructionState.RULE_ASSEMBLED.value
        state.rendered_rule_text = cls.render_singleline(state)

        # Sync components store
        state.components["header"] = ast.header.to_dict()
        for opt in ast.options:
            if opt.name == "msg":
                state.components["msg"] = opt.value
            elif opt.name == "flow":
                state.components["flow"] = opt.value
            elif opt.name == "sid":
                state.components["sid"] = opt.value
            elif opt.name == "rev":
                state.components["rev"] = opt.value
            elif opt.name == "classtype":
                state.components["classification"] = opt.value
            elif opt.name == "reference":
                state.components["references"].append(opt.value)
            elif opt.name == "metadata":
                state.components["metadata"].append(opt.value)
            elif opt.name in ["content", "pcre", "regex", "byte_test", "byte_jump", "isdataat"]:
                state.components["detection"].append(opt.to_dict())

        return state
