import json
import config
import httpx
from shared import command_engine

# One client for the whole process, so commands reuse the connection to Ollama.
client = httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=5.0))

OPTIONS = {
    "temperature": 0.05,
    "num_ctx": 1024,
    "num_predict": 128,  # terminal output is short; don't let it ramble
    "stop": ["ubuntu@prod-db-01", "\n\n\n"],
}


async def preload():
  """Load the model at startup, so the first attacker isn't the cold start."""
  try:
    response = await client.post(
        config.OLLAMA_URL,
        json={"model": config.OLLAMA_MODEL, "keep_alive": -1},
    )
    response.raise_for_status()
    print(f"[LLM] {config.OLLAMA_MODEL} loaded")
  except Exception as e:
    print(f"[LLM] Could not preload {config.OLLAMA_MODEL}: {e}")


def _is_leak(line: str) -> bool:
  lowered = line.lower()
  return any(marker in lowered for marker in command_engine._LEAK_MARKERS)


def _keep(line: str, command: str) -> bool:
  """Drops the lines a model adds around real output, keeping blank ones."""
  if not line.strip():
    return True
  if line.strip() == command.strip():
    return False
  return bool(command_engine.sanitize_llm_output(line))


async def _model_lines(command: str, vfs):
  """Yields complete lines from the model, as it writes them."""
  payload = {
      "model": config.OLLAMA_MODEL,
      "messages": command_engine.build_messages(command, vfs),
      "stream": True,
      # Ollama unloads an idle model after five minutes; -1 keeps it resident.
      "keep_alive": -1,
      "options": OPTIONS,
  }
  buffer = ""
  async with client.stream(
      "POST", command_engine.chat_url(config.OLLAMA_URL), json=payload
  ) as response:
    response.raise_for_status()
    async for raw in response.aiter_lines():
      if not raw:
        continue
      buffer += json.loads(raw).get("message", {}).get("content", "")
      while "\n" in buffer:
        line, buffer = buffer.split("\n", 1)
        yield line
  if buffer:
    yield buffer


async def stream_reply(command: str, vfs):
  """
  Yields the reply one line at a time, so output appears as it is written.

  Lines already sent can't be taken back, so a reply that breaks character
  partway through stops there. A reply with nothing usable falls back to a
  plausible shell error, never an error from this code.
  """
  unknown = command_engine.unknown_file_in(command, vfs)
  if unknown and command != f"cat {unknown}":
    async for _ in stream_reply(f"cat {unknown}", vfs):
      pass
    result = command_engine.handle_command(command, vfs)
    if not result.needs_llm:
      if result.output:
        for line in result.output.split("\n"):
          yield line
      return

  cached = command_engine.cached_reply(command, vfs)
  if cached is not None:
    command_engine.remember_llm_output(command, cached, vfs)
    for line in cached.split("\n"):
      yield line
    return

  lines = []
  clean = True
  try:
    async for line in _model_lines(command, vfs):
      if _is_leak(line):
        clean = False
        break
      if _keep(line, command) and (lines or line.strip()):
        lines.append(line.rstrip())
        yield line.rstrip()
  except Exception as e:
    print(f"[LLM] {e}")
    clean = False

  text = "\n".join(lines).strip()
  validated = command_engine.validate_against_state(text, command, vfs)
  if clean and validated is not None:
    command_engine.remember_llm_output(command, validated, vfs)
    command_engine.store_reply(command, validated, vfs)
  elif not lines:
    yield command_engine.fallback_output(command)
