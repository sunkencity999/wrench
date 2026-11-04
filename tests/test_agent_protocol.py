"""Agent protocol normalization — tolerate small-model JSON flubs."""

from wrench.agent import _normalize_action


def test_canonical_tool_shape_untouched():
    obj = {"action": "tool", "tool": "run_diag", "args": {"command": "df -h"}}
    assert _normalize_action(obj) == obj


def test_final_untouched():
    obj = {"action": "final", "answer": "all good"}
    assert _normalize_action(obj) == obj


def test_tool_name_in_action_field():
    # seen live from qwen2.5:3b during the ollama guided-setup smoke test
    obj = {"action": "run_diag", "tool": "run_diag", "args": {"command": "date +%s"}}
    n = _normalize_action(obj)
    assert n["action"] == "tool" and n["tool"] == "run_diag"
    assert n["args"] == {"command": "date +%s"}


def test_tool_key_without_action():
    n = _normalize_action({"tool": "read_logs", "args": {"unit": "sshd"}})
    assert n["action"] == "tool" and n["tool"] == "read_logs"


def test_unknown_action_left_alone():
    obj = {"action": "think", "note": "hmm"}
    assert _normalize_action(obj) == obj
