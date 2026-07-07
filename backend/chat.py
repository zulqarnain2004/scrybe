"""
chat.py — "Chat with the repo." Retrieves the most relevant code chunks for
a user question using the local embedding index, then asks the LLM to answer
using ONLY those chunks — with explicit file:line citations attached to every
claim, so answers are checkable against the actual source.
"""

import textwrap
from dataclasses import dataclass

from .embeddings import EmbeddingIndex, embed_query
from .llm_client import complete

SYSTEM_PROMPT = """You answer questions about a codebase using ONLY the provided code \
excerpts. Every factual claim about the code must end with a citation in the exact form \
[file_path:start_line-end_line]. If the excerpts don't contain enough information to answer, \
say so explicitly rather than guessing. Never invent file paths or line numbers not present \
in the excerpts."""


@dataclass
class ChatAnswer:
    text: str
    citations: list  # [{"file_path":..., "start_line":..., "end_line":..., "score":...}]


def answer_question(question: str, index: EmbeddingIndex, api_key: str | None = None, top_k: int = 6) -> ChatAnswer:
    query_vec = embed_query(question)
    results = index.search(query_vec, top_k=top_k)

    if not results:
        return ChatAnswer(
            text="I couldn't find any relevant code for this question — the project may not "
                 "be indexed yet, or the question may be about something outside the codebase.",
            citations=[],
        )

    excerpt_blob = "\n\n".join(
        f"[{chunk.file_path}:{chunk.start_line}-{chunk.end_line}]"
        f"{' (' + chunk.symbol_name + ')' if chunk.symbol_name else ''}\n```\n{chunk.text[:1000]}\n```"
        for chunk, score in results
    )

    prompt = textwrap.dedent(f"""
        Question: {question}

        Relevant code excerpts:
        {excerpt_blob}

        Answer the question using only these excerpts, with a [file_path:start-end] citation
        after every factual claim about the code.
    """).strip()

    answer_text = complete(prompt, api_key=api_key, system=SYSTEM_PROMPT, max_tokens=1200)

    citations = [
        {
            "file_path": chunk.file_path, "start_line": chunk.start_line,
            "end_line": chunk.end_line, "symbol_name": chunk.symbol_name,
            "relevance_score": round(score, 3),
        }
        for chunk, score in results
    ]
    return ChatAnswer(text=answer_text, citations=citations)
