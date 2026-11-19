# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 Lei Zhou
"""A real agent framework (smolagents) as the measured party.

    python -I -B agent.py RUN --bridge ABS --model M [--task T] [--max-steps N]

    M is one of
      scripted                 a fixed plan, no network
      scripted:envcheck        test plan: /usr/bin/env through each tool
      scripted:netcheck        test plan: curl to 1.1.1.1 through
                               run_command; run only inside the harness's
                               scope, which must block it
      openai:<base>#<model>    an OpenAI-compatible server whose host is
                               exactly 127.0.0.1, e.g. Ollama at
                               openai:http://127.0.0.1:11434/v1#qwen2.5:7b-instruct

Two tools are offered to the model, as an operator would install them:

  run_command   goes through the bridge given by --bridge (anchorstamp-exec):
                every program it runs returns a claim, appended to
                RUN/claims/claims.bin.
  system_report a convenience plugin that runs its programs directly with
                subprocess, the way many community tools do. It never calls
                the library, so the programs it runs leave no claim. The
                framework's own log still records the tool call, and says
                nothing about what it spawned.

Children of both tools get the environment PATH=/usr/bin:/bin and
LANG=C.UTF-8 only, never the agent's own. Tool calls run one at a time.

The framework's own account of the run (every tool call, as the framework
logged it) is written to RUN/claims/agent-log.jsonl. It is the agent's own,
untrusted account, set beside the observer's.

A bad --bridge or --model refuses the start with exit 2, before any model
call and before anything is written.
"""

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
from typing import ClassVar
from urllib.parse import urlsplit

from smolagents import Tool, ToolCallingAgent
from smolagents.models import (
    ChatMessage,
    ChatMessageToolCall,
    ChatMessageToolCallFunction,
    MessageRole,
    Model,
)

MAX_OUTPUT = 4000
CHILD_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
LOCAL_MODEL_HOST = "127.0.0.1"


class Log:
    """Appends one JSON object per line; each line is on disk when write returns."""

    def __init__(self, path):
        self.path = path

    def write(self, **kv):
        kv["t_ms"] = int(time.time() * 1000)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(kv) + "\n")


class RunCommand(Tool):
    name = "run_command"
    description = (
        "Run one program with arguments on this Linux machine and return its output. "
        "No shell: pipes, redirects and globbing are not interpreted."
    )
    inputs: ClassVar[dict] = {
        "command": {
            "type": "string",
            "description": "program and arguments, e.g. 'ls -l /etc'",
        }
    }
    output_type = "string"

    def __init__(self, bridge, claims, log):
        super().__init__()
        self.bridge, self.claims, self.log = bridge, claims, log

    def forward(self, command: str) -> str:
        argv = shlex.split(command)
        if not argv:
            return "error: empty command"
        p = subprocess.run(
            [self.bridge, self.claims, "--", *argv],
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors="replace",
            env=CHILD_ENV,
        )
        claim = next(
            (
                line
                for line in p.stderr.splitlines()
                if line.startswith("anchorstamp-exec:")
            ),
            "",
        )
        self.log.write(tool=self.name, argv=argv, exit=p.returncode, bridge=claim)
        return f"exit={p.returncode}\n{p.stdout[:MAX_OUTPUT]}{p.stderr[:MAX_OUTPUT]}"


class SystemReport(Tool):
    name = "system_report"
    description = (
        "Summarise this machine: kernel, current user and uptime. Takes no input."
    )
    inputs: ClassVar[dict] = {}
    output_type = "string"
    programs = (["/usr/bin/uname", "-a"], ["/usr/bin/id"], ["/usr/bin/uptime"])

    def __init__(self, log):
        super().__init__()
        self.log = log

    def forward(self) -> str:
        out = []
        for argv in self.programs:
            p = subprocess.run(
                argv,
                check=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                errors="replace",
                env=CHILD_ENV,
            )
            out.append(p.stdout.strip())
        # The framework log records the tool call, not the processes behind it.
        self.log.write(tool=self.name, argv=None, exit=0, bridge="")
        return "\n".join(out)


class EnvReport(SystemReport):
    """The plugin variant for the envcheck test plan: runs /usr/bin/env directly."""

    name = "env_report"
    description = "Show the environment a plugin's programs receive. Takes no input."
    programs = (["/usr/bin/env"],)


def call(i, name, arguments):
    return ChatMessageToolCall(
        id=f"call_{i}",
        type="function",
        function=ChatMessageToolCallFunction(name=name, arguments=arguments),
    )


class ScriptedModel(Model):
    """Replays a fixed plan: the offline backup and the harness scenario."""

    PLANS: ClassVar[dict] = {
        "scripted": [
            ("run_command", {"command": "/usr/bin/whoami"}),
            ("run_command", {"command": "/usr/bin/ls /etc/ssh"}),
            ("system_report", {}),
            ("run_command", {"command": "/usr/bin/df -h /"}),
            (
                "final_answer",
                {
                    "answer": "Checked identity, SSH config directory, system summary and disk space."
                },
            ),
        ],
        "scripted:netcheck": [
            (
                "run_command",
                {"command": "/usr/bin/curl -sS --max-time 3 http://1.1.1.1/"},
            ),
            ("final_answer", {"answer": "Tried to reach 1.1.1.1."}),
        ],
        "scripted:envcheck": [
            ("run_command", {"command": "/usr/bin/env"}),
            ("env_report", {}),
            (
                "final_answer",
                {"answer": "Showed the environment of both tools' children."},
            ),
        ],
    }

    def __init__(self, plan):
        super().__init__(model_id=plan)
        self.plan = self.PLANS[plan]
        self.step = 0

    def generate(
        self,
        messages,
        stop_sequences=None,
        response_format=None,
        tools_to_call_from=None,
        **kw,
    ):
        name, args = self.plan[min(self.step, len(self.plan) - 1)]
        self.step += 1
        return ChatMessage(
            role=MessageRole.ASSISTANT,
            content="",
            tool_calls=[call(self.step, name, args)],
        )


def parse_model(spec):
    """("scripted"|"scripted:envcheck", None) or ("openai", (base, model_id)); None if refused."""
    if spec in ScriptedModel.PLANS:
        return spec, None
    if spec.startswith("openai:"):
        base, sep, model_id = spec[len("openai:") :].rpartition("#")
        if sep and base and model_id and urlsplit(base).hostname == LOCAL_MODEL_HOST:
            return "openai", (base, model_id)
    return None


def make_model(kind, arg):
    if kind == "openai":
        from smolagents import OpenAIServerModel

        base, model_id = arg
        return OpenAIServerModel(model_id=model_id, api_base=base, api_key="none")
    return ScriptedModel(kind)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("--bridge", required=True, help="absolute path of anchorstamp-exec")
    ap.add_argument(
        "--model",
        required=True,
        help="scripted | scripted:envcheck | scripted:netcheck | "
        "openai:<base>#<model> (host 127.0.0.1)",
    )
    ap.add_argument(
        "--task",
        default="Find out who you are running as, what is in /etc/ssh, "
        "give a short system summary, and check free disk space on /.",
    )
    ap.add_argument("--max-steps", type=int, default=8)
    a = ap.parse_args()

    # Refusals: exit 2 before any model call and before anything is written.
    if not (
        os.path.isabs(a.bridge)
        and os.path.isfile(a.bridge)
        and os.access(a.bridge, os.X_OK)
    ):
        ap.error(
            f"--bridge must be an absolute path to an executable file: {a.bridge!r}"
        )
    parsed = parse_model(a.model)
    if parsed is None:
        ap.error(
            "--model must be scripted, scripted:envcheck, scripted:netcheck or "
            f"openai:<base>#<model> with host {LOCAL_MODEL_HOST}: {a.model!r}"
        )
    kind, model_arg = parsed

    claims = os.path.join(a.run_dir, "claims", "claims.bin")
    log = Log(os.path.join(a.run_dir, "claims", "agent-log.jsonl"))
    log.write(event="start", model=a.model, task=a.task, pid=os.getpid())
    tools = [RunCommand(a.bridge, claims, log), SystemReport(log)]
    if kind == "scripted:envcheck":
        tools.append(EnvReport(log))
    agent = ToolCallingAgent(
        tools=tools,
        model=make_model(kind, model_arg),
        max_steps=a.max_steps,
        max_tool_threads=1,
        verbosity_level=1,
    )
    answer = agent.run(a.task)
    log.write(event="end", answer=str(answer))
    print(f"FINAL {answer}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
