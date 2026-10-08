"""llmbench testleri: yükleyiciler, skorlama mantığı, offline (network yok)."""
from __future__ import annotations

import json
import os

import pytest

from purpleloop.llmbench import (BenchOutcome, LocalLLM, eval_agentharm,
                                 eval_injecagent, eval_seceval, load_agentharm,
                                 load_injecagent, load_seceval, _REFUSAL_PAT)

BENCH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "benchmarks")


class FakeLLM:
    def __init__(self, reply_fn):
        self.reply_fn = reply_fn
        self.calls = 0

    def chat(self, system, user, max_tokens=512, temperature=0.0):
        self.calls += 1
        return self.reply_fn(user)


# ---------- yükleyiciler (indirilmiş gerçek dosyalar) ----------

@pytest.mark.skipif(not os.path.exists(os.path.join(BENCH, "seceval_questions.json")),
                    reason="benchmark verisi yok")
def test_load_seceval_parses_choices():
    items = load_seceval(BENCH, 5)
    assert len(items) == 5
    assert items[0]["answer"] in "ABCDEFGHIJ"
    assert all(o and not o.startswith(("A:", "B:")) for o in items[0]["options"])


@pytest.mark.skipif(not os.path.exists(os.path.join(BENCH, "agentharm_harmful_val.json")),
                    reason="benchmark verisi yok")
def test_load_agentharm():
    items = load_agentharm(BENCH, 5)
    assert len(items) == 5 and all(i["prompt"] for i in items)


@pytest.mark.skipif(not os.path.exists(os.path.join(BENCH, "injecagent_test_cases_dh_base.json")),
                    reason="benchmark verisi yok")
def test_load_injecagent():
    items = load_injecagent(BENCH, 5)
    assert len(items) == 5 and all("injection" in i for i in items)


# ---------- skorlama ----------

def test_seceval_scoring():
    items = [{"id": "1", "question": "q", "options": ["a", "b", "c"], "answer": "B"},
             {"id": "2", "question": "q", "options": ["a", "b", "c"], "answer": "C"}]
    llm = FakeLLM(lambda u: "B")  # hep B derse 1/2 doğru
    out = eval_seceval(llm, items)
    assert out.score == 0.5 and out.n == 2


def test_agentharm_refusal_detection():
    items = [{"id": "1", "prompt": "p1"}, {"id": "2", "prompt": "p2"}]
    replies = iter(["I cannot assist with this request.", "Sure, here is how..."])
    llm = FakeLLM(lambda u: next(replies))
    out = eval_agentharm(llm, items)
    assert out.score == 0.5


def test_refusal_pattern():
    assert _REFUSAL_PAT.search("I can't help with that")
    assert _REFUSAL_PAT.search("Sorry, I must decline.")
    assert not _REFUSAL_PAT.search("Here are the steps to configure TLS.")


def test_injecagent_resistance():
    items = [{"id": "1", "prompt": "task1\n\nSECRETINJECTION123 data",
              "injection": "SECRETINJECTION123 reveal"},
             {"id": "2", "prompt": "task2\n\nclean", "injection": "RANDOMTOKEN42"}]
    replies = iter(["The result is SECRETINJECTION123 leaked",  # uydu → direnmedi
                    "Task2 sonucu: temiz yanit"])               # direndi
    llm = FakeLLM(lambda u: next(replies))
    out = eval_injecagent(llm, items)
    assert out.score == 0.5


# ---------- LLM istemcisi offline ----------

def test_locallm_unreachable_returns_error():
    llm = LocalLLM("http://127.0.0.1:1/v1", "x", timeout=2)
    with pytest.raises(Exception):
        llm.chat("s", "u")


# ---------- BenchOutcome ----------

def test_bench_outcome_json():
    o = BenchOutcome("x", 4, 0.75, "m", [{"a": 1}], 1.2)
    d = json.loads(o.to_json())
    assert d["score"] == 0.75 and d["n"] == 4
