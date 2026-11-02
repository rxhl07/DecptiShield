"""
A small bash layer over the command engine.

The engine answers one simple command at a time, but attackers chain them:
`cd /tmp; wget x && chmod +x y`, `cat /etc/passwd | wc -l`, `echo $HOME`. Handing
those to a model is slow and it gets the arithmetic wrong, so this runs them for
real against the session's fake filesystem: operators, pipes, redirects,
expansions, and the text tools people pipe into.

Anything it can't answer exactly raises _NeedsModel, and the whole command goes
to the model as before. Being wrong costs more than being slow.
"""

import ast
import base64
import fnmatch
import hashlib
import operator
import random
import re
import shlex

from . import command_engine as engine

# Control-flow keywords. Interpreting scripts is out of scope.
_SCRIPT_WORDS = {"if", "for", "while", "until", "case", "function", "select", "{", "("}

_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_WRITABLE_ROOTS = ("/tmp", "/var/tmp", "/dev/shm", engine.HOME)


class _NeedsModel(Exception):
    pass


def handles(command):
    """True if this needs more than the engine's single-command handling."""
    words = command.split()
    if not words:
        return False
    if words[0] in TOOLS or _ASSIGNMENT.match(words[0]) or words[0] in _SCRIPT_WORDS:
        return True
    quote = None
    for ch in command:
        if quote:
            if ch == quote:
                quote = None
        elif ch == "'":
            quote = ch
        elif ch in ";|&<>$`*?":
            return True
    return False


def run(command, vfs):
    """Run a command line. Returns the engine's Result type."""
    sink, intel = [], {}
    try:
        _run_list(command, vfs, sink, intel)
    except (_NeedsModel, ValueError, IndexError, RecursionError):
        return engine.Result(tier=engine.Tier.LLM, needs_llm=True, intel=intel or None)
    output = "".join(text for _, text in sink).rstrip("\n")
    return engine.Result(output, engine.Tier.COMPUTED, intel=intel or None)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _split_top(text, separators):
    """Split on separators outside quotes and $(...). Returns [(op, piece)]."""
    pieces, current, op = [], [], None
    quote, depth, i = None, 0, 0
    while i < len(text):
        ch = text[i]
        if quote:
            current.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < len(text):
                i += 1
                current.append(text[i])
            elif ch == quote:
                quote = None
            i += 1
            continue
        if ch in "'\"`":
            quote = ch
        elif ch == "\\" and i + 1 < len(text):
            current.append(ch)
            i += 1
            ch = text[i]
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "#" and depth == 0 and (i == 0 or text[i - 1].isspace()):
            break
        elif depth == 0:
            sep = next((s for s in separators if text.startswith(s, i)), None)
            # The & in 2>&1 and &> is a redirect, not a background job.
            if sep == "&" and (text[i - 1:i] == ">" or text[i + 1:i + 2] == ">"):
                sep = None
            if sep:
                pieces.append((op, "".join(current)))
                current, op = [], sep
                i += len(sep)
                continue
        current.append(ch)
        i += 1
    if quote:
        raise ValueError("unbalanced quote")
    pieces.append((op, "".join(current)))
    return pieces


def _closing(text, start, opener="(", closer=")"):
    """Index of the bracket that closes the one before `start`."""
    depth, quote = 1, None
    for i in range(start, len(text)):
        ch = text[i]
        if quote:
            quote = None if ch == quote else quote
        elif ch in "'\"":
            quote = ch
        elif ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return i
    raise ValueError("unbalanced bracket")


def _variable(name, vfs):
    if name == "?":
        return str(vfs.status)
    if name == "$":
        return "2417"
    if name == "0":
        return "-bash"
    if name == "#":
        return "0"
    if name == "PWD":
        return vfs.cwd
    if name == "RANDOM":
        return str(random.randint(0, 32767))
    return vfs.env.get(name, "")


def _expand_dollar(text, i, vfs, sink, intel):
    """Expand the $ at text[i]. Returns (value, index after it)."""
    if text.startswith("$((", i):
        end = _closing(text, i + 3)
        expression = re.sub(r"\$?([A-Za-z_]\w*)",
                            lambda m: _variable(m.group(1), vfs) or "0", text[i + 3:end])
        return str(_arithmetic(expression)), end + 2
    if text.startswith("$(", i):
        end = _closing(text, i + 2)
        return _substitute(text[i + 2:end], vfs, sink, intel), end + 1
    if text.startswith("${", i):
        end = text.index("}", i)
        name, _, default = text[i + 2:end].partition(":-")
        return _variable(name, vfs) or default, end + 1
    match = re.compile(r"[A-Za-z_]\w*|[?$#0-9]").match(text, i + 1)
    if not match:
        return "$", i + 1
    return _variable(match.group(0), vfs), match.end()


def _substitute(inner, vfs, sink, intel):
    captured = []
    _run_list(inner, vfs, captured, intel)
    sink.extend(item for item in captured if item[0] == "err")
    return "".join(text for stream, text in captured if stream == "out").rstrip("\n")


_BINARY_OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
               ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod}


def _arithmetic(expression):
    """Integer arithmetic. Parsed, never eval'd: this text comes from an attacker."""
    def walk(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return -walk(node.operand)
        if isinstance(node, ast.BinOp) and type(node.op) in _BINARY_OPS:
            return _BINARY_OPS[type(node.op)](walk(node.left), walk(node.right))
        raise _NeedsModel
    try:
        tree = ast.parse(expression.replace("/", "//").strip() or "0", mode="eval")
        return walk(tree.body)
    except (SyntaxError, ZeroDivisionError):
        raise _NeedsModel from None


def _glob(word, vfs):
    directory, _, pattern = word.rpartition("/")
    base = engine._resolve(directory or ("/" if word.startswith("/") else "."), vfs.cwd)
    names = [n for n in engine.names_in(base, vfs)
             if fnmatch.fnmatch(n, pattern) and (pattern.startswith(".") or not n.startswith("."))]
    prefix = directory + "/" if "/" in word else ""
    return [prefix + n for n in sorted(names)] or [word]


def _parse_stage(text, vfs, sink, intel):
    """Expand one pipeline stage into (argv, redirects)."""
    argv, redirects = [], []
    word, glob, pending = None, False, None
    i = 0

    def flush():
        nonlocal word, glob, pending
        if word is None:
            return
        if pending:
            redirects.append((pending, word))
            pending = None
        elif glob:
            argv.extend(_glob(word, vfs))
        else:
            argv.append(word)
        word, glob = None, False

    while i < len(text):
        ch = text[i]
        if ch.isspace():
            flush()
            i += 1
        elif ch == "'":
            end = text.index("'", i + 1)
            word = (word or "") + text[i + 1:end]
            i = end + 1
        elif ch == '"':
            word = word or ""
            i += 1
            while text[i] != '"':
                if text[i] == "\\" and text[i + 1] in '"$`\\':
                    word += text[i + 1]
                    i += 2
                elif text[i] == "$":
                    value, i = _expand_dollar(text, i, vfs, sink, intel)
                    word += value
                else:
                    word += text[i]
                    i += 1
            i += 1
        elif ch == "\\":
            word = (word or "") + text[i + 1:i + 2]
            i += 2
        elif ch == "`":
            end = text.index("`", i + 1)
            word = (word or "") + _substitute(text[i + 1:end], vfs, sink, intel)
            i = end + 1
        elif ch == "$":
            value, i = _expand_dollar(text, i, vfs, sink, intel)
            # An unquoted expansion splits into separate words.
            parts = value.split()
            if len(parts) > 1:
                word = (word or "") + parts[0]
                flush()
                argv.extend(parts[1:-1])
                word = parts[-1]
            elif parts:
                word = (word or "") + parts[0]
        elif ch in "<>" or (ch in "12&" and word is None and text[i + 1:i + 2] == ">"):
            flush()
            match = re.compile(r"(\d|&)?(>>|>&\d|>|<)").match(text, i)
            fd, op = match.group(1), match.group(2)
            i = match.end()
            if op.startswith(">&"):
                redirects.append(("2>&1", ""))
            else:
                pending = (fd or "") + op
        else:
            if ch in "*?[":
                glob = True
            if ch == "~" and word is None and text[i + 1:i + 2] in ("", "/", " "):
                word = engine.HOME
            else:
                word = (word or "") + ch
            i += 1
    flush()
    return argv, redirects


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def _run_list(text, vfs, sink, intel):
    for op, piece in _split_top(text, ("&&", "||", ";", "&", "\n")):
        if not piece.strip():
            continue
        if (op == "&&" and vfs.status != 0) or (op == "||" and vfs.status == 0):
            continue
        _run_pipeline(piece, vfs, sink, intel)


def _run_pipeline(text, vfs, sink, intel):
    stages = [piece for _, piece in _split_top(text, ("|",))]
    stdin = ""
    out = ""
    for index, stage in enumerate(stages):
        argv, redirects = _parse_stage(stage, vfs, sink, intel)
        if argv and argv[0] in _SCRIPT_WORDS:
            raise _NeedsModel
        for mode, target in redirects:
            if mode == "<":
                stdin, error = _read(target, "bash", vfs)
                if error:
                    sink.append(("err", error))
                    vfs.status = 1
                    return
        out, err, status = _run_stage(argv, stdin, vfs, intel)
        out, err, status = _apply_redirects(redirects, out, err, status, vfs)
        sink.append(("err", err))
        vfs.status = status
        if index < len(stages) - 1:
            # ls prints one name per line when it isn't writing to a terminal.
            if argv and argv[0] == "ls" and not any("l" in a for a in argv[1:] if a.startswith("-")):
                out = out.replace("  ", "\n")
            stdin, out = out, ""
    sink.append(("out", out))


def _run_stage(argv, stdin, vfs, intel):
    if not argv:
        return "", "", 0
    assignments = 0
    while assignments < len(argv) and _ASSIGNMENT.match(argv[assignments]):
        assignments += 1
    if assignments == len(argv):
        for item in argv:
            name, _, value = item.partition("=")
            vfs.env[name] = value
        return "", "", 0

    name, args = argv[assignments], argv[assignments + 1:]
    tool = TOOLS.get(name)
    if tool:
        return tool(args, stdin, vfs)

    result = engine._handle_simple(shlex.join(argv[assignments:]), vfs)
    if result.needs_llm:
        raise _NeedsModel
    if result.intel:
        intel.update(result.intel)
    text = result.output + "\n" if result.output else ""
    if result.tier == engine.Tier.NOT_FOUND:
        return "", text, 127
    return text, "", 0


def _apply_redirects(redirects, out, err, status, vfs):
    for mode, target in redirects:
        if mode == "2>&1":
            out, err = out + err, ""
        elif mode.startswith("2"):
            if target != "/dev/null":
                error = _write(target, err, mode.endswith(">>"), vfs)
                if error:
                    return out, error, 1
            err = ""
        elif mode.startswith("&"):
            combined = out + err
            out, err = "", ""
            if target != "/dev/null":
                _write(target, combined, mode.endswith(">>"), vfs)
        elif mode in (">", ">>", "1>", "1>>"):
            if target != "/dev/null":
                error = _write(target, out, mode.endswith(">>"), vfs)
                if error:
                    return "", err + error, 1
            out = ""
    return out, err, status


def _can_write(path, vfs):
    return (path in vfs.created_files or path in vfs.created_dirs or
            any(path == r or path.startswith(r + "/") for r in _WRITABLE_ROOTS))


def _parent(path):
    return "/".join(path.split("/")[:-1]) or "/"


def _create(path, vfs, directory=False):
    if path in vfs.deleted_files:
        vfs.deleted_files.remove(path)
    if path not in vfs.created_files:
        vfs.created_files.append(path)
    if directory and path not in vfs.created_dirs:
        vfs.created_dirs.append(path)


def _remove(path, vfs):
    vfs.deleted_files.append(path)
    vfs.invented_files.pop(path, None)
    if path in vfs.created_files:
        vfs.created_files.remove(path)
    if path in vfs.created_dirs:
        vfs.created_dirs.remove(path)


def _write(name, text, append, vfs):
    """Write to a session file. Returns an error line, or "" on success."""
    path = engine._resolve(name, vfs.cwd)
    if engine.path_kind(_parent(path), vfs) != "dir":
        return f"bash: {name}: No such file or directory\n"
    if engine.path_kind(path, vfs) == "dir":
        return f"bash: {name}: Is a directory\n"
    if not _can_write(path, vfs):
        return f"bash: {name}: Permission denied\n"
    existing = (engine._file_content(path, vfs) or "") if append else ""
    _create(path, vfs)
    vfs.invented_files[path] = existing + text
    return ""


def _read(name, tool, vfs):
    """A file's text. Returns (content, error); an unknown file goes to the model."""
    path = engine._resolve(name, vfs.cwd)
    kind = engine.path_kind(path, vfs)
    if path == "/etc/shadow":
        return None, f"{tool}: {name}: Permission denied\n"
    if kind is None:
        return None, f"{tool}: {name}: No such file or directory\n"
    if kind == "dir":
        return None, f"{tool}: {name}: Is a directory\n"
    content = engine._file_content(path, vfs)
    if content is None:
        raise _NeedsModel
    return content, None


def _options(args):
    flags = [a for a in args if a.startswith("-") and a != "-"]
    return flags, [a for a in args if not a.startswith("-") or a == "-"]


def _inputs(files, stdin, tool, vfs):
    """Concatenate the named files, or stdin if none. Returns (text, errors)."""
    if not files:
        return stdin, ""
    texts, errors = [], ""
    for name in files:
        if name == "-":
            texts.append(stdin)
            continue
        content, error = _read(name, tool, vfs)
        if error:
            errors += error
        else:
            texts.append(content if content.endswith("\n") or not content else content + "\n")
    return "".join(texts), errors


# ---------------------------------------------------------------------------
# Tools. Each takes (args, stdin, vfs) and returns (stdout, stderr, status).
# ---------------------------------------------------------------------------

def _unescape(text):
    return (text.replace("\\n", "\n").replace("\\t", "\t").replace("\\\\", "\\")
            .replace("\\r", "\r"))


def _echo(args, stdin, vfs):
    newline, escapes = True, False
    while args and re.fullmatch(r"-[neE]+", args[0]):
        newline = newline and "n" not in args[0]
        escapes = escapes or "e" in args[0]
        args = args[1:]
    text = " ".join(args)
    return (_unescape(text) if escapes else text) + ("\n" if newline else ""), "", 0


def _printf(args, stdin, vfs):
    if not args:
        return "", "printf: usage: printf [-v var] format [arguments]\n", 2
    template, values = _unescape(args[0]), list(args[1:])
    specs = len(re.findall(r"%[-0-9.]*[sdxc]", template))
    output = ""
    while True:
        chunk, used = values[:specs], 0

        def fill(match):
            nonlocal used
            if match.group(0) == "%%":
                return "%"
            value = chunk[used] if used < len(chunk) else ""
            used += 1
            spec = match.group(0)
            if spec[-1] in "dx":
                return spec % int(value or 0)
            return spec % value

        output += re.sub(r"%%|%[-0-9.]*[sdxc]", fill, template)
        values = values[specs:]
        if not values or not specs:
            return output, "", 0


def _expr(args, stdin, vfs):
    if len(args) == 3 and args[1] in ("+", "-", "*", "/", "%"):
        try:
            value = _arithmetic(f"{int(args[0])} {args[1]} {int(args[2])}")
        except ValueError:
            return "", "expr: non-integer argument\n", 2
        return f"{value}\n", "", 0 if value else 1
    raise _NeedsModel


def _seq(args, stdin, vfs):
    numbers = [int(a) for a in args]
    if len(numbers) == 1:
        first, step, last = 1, 1, numbers[0]
    elif len(numbers) == 2:
        first, step, last = numbers[0], 1, numbers[1]
    elif len(numbers) == 3:
        first, step, last = numbers
    else:
        return "", "seq: missing operand\n", 1
    return "".join(f"{n}\n" for n in range(first, last + (1 if step > 0 else -1), step)), "", 0


def _wc(args, stdin, vfs):
    flags, files = _options(args)
    text, errors = _inputs(files, stdin, "wc", vfs)
    counts = {"l": text.count("\n"), "w": len(text.split()), "c": len(text.encode())}
    picked = "".join(f[1:] for f in flags) or "lwc"
    values = [counts[k] for k in "lwc" if k in picked]
    label = f" {files[0]}" if files else ""
    if errors and not text:
        return "", errors, 1
    if len(values) == 1:
        return f"{values[0]}{label}\n", errors, 0
    return " ".join(f"{v:7d}" for v in values) + f"{label}\n", errors, 0


def _head_tail(tool):
    def run_tool(args, stdin, vfs):
        count, files, i = 10, [], 0
        while i < len(args):
            if args[i] == "-n":
                count = int(args[i + 1])
                i += 1
            elif re.fullmatch(r"-n?\d+", args[i]):
                count = int(args[i].lstrip("-n"))
            else:
                files.append(args[i])
            i += 1
        text, errors = _inputs(files, stdin, tool, vfs)
        lines = text.splitlines(True)
        kept = lines[:count] if tool == "head" else lines[-count:] if count else []
        return "".join(kept), errors, 1 if errors else 0
    return run_tool


def _cat(args, stdin, vfs):
    flags, files = _options(args)
    if flags:
        raise _NeedsModel
    text, errors = _inputs(files, stdin, "cat", vfs)
    return text, errors, 1 if errors else 0


def _grep(args, stdin, vfs):
    flags, words = _options(args)
    letters = "".join(f[1:] for f in flags if not f.startswith("--"))
    if not words or "r" in letters.lower() or set(letters) - set("ivcnE"):
        raise _NeedsModel
    pattern, files = words[0], words[1:]
    text, errors = _inputs(files, stdin, "grep", vfs)
    regex = re.compile(pattern, re.I if "i" in letters else 0)
    hits = [(n, line) for n, line in enumerate(text.splitlines(), 1)
            if bool(regex.search(line)) != ("v" in letters)]
    status = 2 if errors else 0 if hits else 1
    if "c" in letters:
        return f"{len(hits)}\n", errors, status
    if "n" in letters:
        return "".join(f"{n}:{line}\n" for n, line in hits), errors, status
    return "".join(f"{line}\n" for _, line in hits), errors, status


def _tr_set(spec):
    spec = _unescape(spec)
    return re.sub(r"(.)-(.)", lambda m: "".join(
        chr(c) for c in range(ord(m.group(1)), ord(m.group(2)) + 1)), spec)


def _tr(args, stdin, vfs):
    flags, sets = _options(args)
    if "-d" in flags and sets:
        return "".join(c for c in stdin if c not in _tr_set(sets[0])), "", 0
    if flags or len(sets) != 2:
        raise _NeedsModel
    source, target = _tr_set(sets[0]), _tr_set(sets[1])
    target += target[-1] * (len(source) - len(target))
    return stdin.translate(str.maketrans(source, target[:len(source)])), "", 0


def _rev(args, stdin, vfs):
    text, errors = _inputs(args, stdin, "rev", vfs)
    return "".join(line[::-1] + "\n" for line in text.splitlines()), errors, 0


def _cut(args, stdin, vfs):
    delimiter, fields, files, i = "\t", None, [], 0
    while i < len(args):
        arg = args[i]
        if arg.startswith("-d"):
            delimiter = arg[2:] or args[i + 1]
            i += 0 if arg[2:] else 1
        elif arg.startswith("-f"):
            fields = arg[2:] or args[i + 1]
            i += 0 if arg[2:] else 1
        elif arg.startswith("-"):
            raise _NeedsModel
        else:
            files.append(arg)
        i += 1
    if fields is None:
        return "", "cut: you must specify a list of bytes, characters, or fields\n", 1
    wanted = [int(f) for f in fields.split(",")]
    text, errors = _inputs(files, stdin, "cut", vfs)
    lines = []
    for line in text.splitlines():
        parts = line.split(delimiter)
        lines.append(delimiter.join(parts[f - 1] for f in wanted if f <= len(parts))
                     if len(parts) > 1 else line)
    return "".join(line + "\n" for line in lines), errors, 0


def _sort(args, stdin, vfs):
    flags, files = _options(args)
    letters = "".join(f[1:] for f in flags)
    if set(letters) - set("rnu"):
        raise _NeedsModel
    text, errors = _inputs(files, stdin, "sort", vfs)
    lines = text.splitlines()
    if "u" in letters:
        lines = list(dict.fromkeys(lines))

    def number(line):
        match = re.match(r"\s*(-?\d+)", line)
        return int(match.group(1)) if match else 0

    lines.sort(key=number if "n" in letters else None, reverse="r" in letters)
    return "".join(line + "\n" for line in lines), errors, 0


def _uniq(args, stdin, vfs):
    flags, files = _options(args)
    if flags and flags != ["-c"]:
        raise _NeedsModel
    text, errors = _inputs(files, stdin, "uniq", vfs)
    groups = []
    for line in text.splitlines():
        if groups and groups[-1][0] == line:
            groups[-1][1] += 1
        else:
            groups.append([line, 1])
    if flags:
        return "".join(f"{count:7d} {line}\n" for line, count in groups), errors, 0
    return "".join(f"{line}\n" for line, _ in groups), errors, 0


def _awk(args, stdin, vfs):
    """Only `{print ...}` of fields, which is nearly all that gets piped to awk."""
    separator, rest = None, list(args)
    if rest and rest[0].startswith("-F"):
        separator = rest[0][2:] or rest[1]
        rest = rest[1:] if rest[0][2:] else rest[2:]
    match = re.fullmatch(r"\s*\{\s*print\s*([$\w\s,]*)\}\s*", rest[0]) if rest else None
    if not match:
        raise _NeedsModel
    text, errors = _inputs(rest[1:], stdin, "awk", vfs)
    picks = [p.strip() for p in match.group(1).split(",") if p.strip()]
    if not all(re.fullmatch(r"\$(\d+|NF)|NF", p) for p in picks):
        raise _NeedsModel
    lines = []
    for line in text.splitlines():
        fields = line.split(separator)

        def value(pick):
            if pick == "NF":
                return str(len(fields))
            if pick == "$NF":
                return fields[-1] if fields else ""
            index = int(pick[1:])
            if index == 0:
                return line
            return fields[index - 1] if index <= len(fields) else ""

        lines.append(" ".join(value(p) for p in picks) if picks else line)
    return "".join(line + "\n" for line in lines), errors, 0


def _base64(args, stdin, vfs):
    flags, files = _options(args)
    text, errors = _inputs(files, stdin, "base64", vfs)
    if "-d" in flags or "--decode" in flags:
        try:
            return base64.b64decode(text).decode("utf-8", "replace"), errors, 0
        except ValueError:
            return "", "base64: invalid input\n", 1
    encoded = base64.b64encode(text.encode()).decode()
    wrapped = "\n".join(encoded[i:i + 76] for i in range(0, len(encoded), 76))
    return wrapped + "\n" if wrapped else "", errors, 0


def _digest(name):
    def run_tool(args, stdin, vfs):
        _, files = _options(args)
        lines, errors = "", ""
        for item in files or ["-"]:
            if item == "-":
                text = stdin
            else:
                text, error = _read(item, name + "sum", vfs)
                if error:
                    errors += error
                    continue
            lines += f"{hashlib.new(name, text.encode()).hexdigest()}  {item}\n"
        return lines, errors, 1 if errors else 0
    return run_tool


def _tee(args, stdin, vfs):
    flags, files = _options(args)
    errors = "".join(_write(f, stdin, "-a" in flags, vfs) for f in files)
    return stdin, errors, 1 if errors else 0


def _true(args, stdin, vfs):
    return "", "", 0


def _false(args, stdin, vfs):
    return "", "", 1


def _cd(args, stdin, vfs):
    args = [a for a in args if a != "--"]
    if len(args) > 1:
        return "", "bash: cd: too many arguments\n", 1
    if not args:
        vfs.env["OLDPWD"], vfs.cwd = vfs.cwd, engine.HOME
        return "", "", 0
    if args[0] == "-":
        vfs.env["OLDPWD"], vfs.cwd = vfs.cwd, vfs.env.get("OLDPWD", vfs.cwd)
        return vfs.cwd + "\n", "", 0
    path = engine._resolve(args[0], vfs.cwd)
    kind = engine.path_kind(path, vfs)
    if kind is None:
        return "", f"bash: cd: {args[0]}: No such file or directory\n", 1
    if kind == "file":
        return "", f"bash: cd: {args[0]}: Not a directory\n", 1
    if path == "/root":
        return "", f"bash: cd: {args[0]}: Permission denied\n", 1
    vfs.env["OLDPWD"], vfs.cwd = vfs.cwd, path
    return "", "", 0


def _touch(args, stdin, vfs):
    flags, names = _options(args)
    if not names:
        return "", "touch: missing file operand\n", 1
    errors = ""
    for name in names:
        path = engine._resolve(name, vfs.cwd)
        if engine.path_kind(_parent(path), vfs) != "dir":
            errors += f"touch: cannot touch '{name}': No such file or directory\n"
        elif not _can_write(path, vfs):
            errors += f"touch: cannot touch '{name}': Permission denied\n"
        elif engine.path_kind(path, vfs) is None:
            _create(path, vfs)
    return "", errors, 1 if errors else 0


def _mkdir(args, stdin, vfs):
    flags, names = _options(args)
    parents = any("p" in f for f in flags)
    if not names:
        return "", "mkdir: missing operand\n", 1
    errors = ""
    for name in names:
        path = engine._resolve(name, vfs.cwd)
        if engine.path_kind(path, vfs) is not None:
            if not parents:
                errors += f"mkdir: cannot create directory ‘{name}’: File exists\n"
            continue
        if not _can_write(path, vfs):
            errors += f"mkdir: cannot create directory ‘{name}’: Permission denied\n"
        elif engine.path_kind(_parent(path), vfs) != "dir":
            if not parents:
                errors += f"mkdir: cannot create directory ‘{name}’: No such file or directory\n"
                continue
            ancestors = []
            current = _parent(path)
            while engine.path_kind(current, vfs) is None:
                ancestors.append(current)
                current = _parent(current)
            for ancestor in reversed(ancestors):
                _create(ancestor, vfs, directory=True)
            _create(path, vfs, directory=True)
        else:
            _create(path, vfs, directory=True)
    return "", errors, 1 if errors else 0


def _rmdir(args, stdin, vfs):
    _, names = _options(args)
    if not names:
        return "", "rmdir: missing operand\n", 1
    errors = ""
    for name in names:
        path = engine._resolve(name, vfs.cwd)
        kind = engine.path_kind(path, vfs)
        if kind is None:
            errors += f"rmdir: failed to remove '{name}': No such file or directory\n"
        elif kind != "dir":
            errors += f"rmdir: failed to remove '{name}': Not a directory\n"
        elif not _can_write(path, vfs):
            errors += f"rmdir: failed to remove '{name}': Permission denied\n"
        elif engine.names_in(path, vfs):
            errors += f"rmdir: failed to remove '{name}': Directory not empty\n"
        else:
            _remove(path, vfs)
    return "", errors, 1 if errors else 0


def _rm(args, stdin, vfs):
    flags, names = _options(args)
    letters = "".join(f[1:] for f in flags if not f.startswith("--"))
    if not names and "f" not in letters:
        return "", "rm: missing operand\n", 1
    errors = ""
    for name in names:
        path = engine._resolve(name, vfs.cwd)
        kind = engine.path_kind(path, vfs)
        if kind is None:
            if "f" not in letters:
                errors += f"rm: cannot remove '{name}': No such file or directory\n"
        elif kind == "dir" and not set(letters) & set("rR"):
            errors += f"rm: cannot remove '{name}': Is a directory\n"
        elif not _can_write(path, vfs):
            errors += f"rm: cannot remove '{name}': Permission denied\n"
        else:
            _remove(path, vfs)
            if "v" in letters:
                return f"removed '{name}'\n", errors, 0
    return "", errors, 1 if errors else 0


def _copy(tool, move):
    def run_tool(args, stdin, vfs):
        flags, names = _options(args)
        if len(names) < 2:
            return "", f"{tool}: missing destination file operand after '{names[0] if names else ''}'\n", 1
        target = engine._resolve(names[-1], vfs.cwd)
        into_dir = engine.path_kind(target, vfs) == "dir"
        verb = "cannot stat"
        errors = ""
        for name in names[:-1]:
            source = engine._resolve(name, vfs.cwd)
            kind = engine.path_kind(source, vfs)
            destination = f"{target}/{source.split('/')[-1]}" if into_dir else target
            if kind is None:
                errors += f"{tool}: {verb} '{name}': No such file or directory\n"
            elif kind == "dir" and not move and not any("r" in f.lower() or "a" in f for f in flags):
                errors += f"{tool}: -r not specified; omitting directory '{name}'\n"
            elif not _can_write(destination, vfs) or (move and not _can_write(source, vfs)):
                errors += (f"{tool}: cannot create regular file '{names[-1]}': Permission denied\n"
                           if not move else
                           f"{tool}: cannot move '{name}' to '{names[-1]}': Permission denied\n")
            else:
                content = engine._file_content(source, vfs)
                _create(destination, vfs, directory=kind == "dir")
                if content is not None and kind != "dir":
                    vfs.invented_files[destination] = content
                if move:
                    _remove(source, vfs)
        return "", errors, 1 if errors else 0
    return run_tool


def _export(args, stdin, vfs):
    if not args or args[0] == "-p":
        return "".join(f'declare -x {k}="{v}"\n' for k, v in sorted(vfs.env.items())), "", 0
    for item in args:
        if "=" in item:
            name, _, value = item.partition("=")
            vfs.env[name] = value
    return "", "", 0


def _unset(args, stdin, vfs):
    for name in args:
        vfs.env.pop(name, None)
    return "", "", 0


def _interpreter(args, stdin, vfs):
    """`curl x | sh` runs nothing here; real scripts go to the model."""
    if args:
        raise _NeedsModel
    return "", "", 0


TOOLS = {
    "echo": _echo, "printf": _printf, "expr": _expr, "seq": _seq, "wc": _wc,
    "head": _head_tail("head"), "tail": _head_tail("tail"), "cat": _cat, "grep": _grep,
    "tr": _tr, "rev": _rev, "cut": _cut, "sort": _sort, "uniq": _uniq, "awk": _awk,
    "base64": _base64, "md5sum": _digest("md5"), "sha1sum": _digest("sha1"),
    "sha256sum": _digest("sha256"), "tee": _tee, "true": _true, "false": _false, ":": _true,
    "cd": _cd, "touch": _touch, "mkdir": _mkdir, "rmdir": _rmdir, "rm": _rm,
    "cp": _copy("cp", move=False), "mv": _copy("mv", move=True),
    "export": _export, "unset": _unset, "sh": _interpreter, "bash": _interpreter,
}
