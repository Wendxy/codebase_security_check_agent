from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class FileChunk:
    file: str
    chunk_index: int
    total_chunks: int
    content: str


def chunk_text(content: str, chunk_size: int = 8000, overlap: int = 400) -> list[str]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if overlap >= chunk_size:
        raise ValueError("overlap must be smaller than chunk_size")

    if len(content) <= chunk_size:
        return [content]

    chunks: list[str] = []
    step = chunk_size - overlap
    start = 0
    while start < len(content):
        end = min(len(content), start + chunk_size)
        chunk = content[start:end]
        chunks.append(chunk)
        if end >= len(content):
            break
        start += step
    return chunks


def chunk_files(files: dict[str, str], chunk_size: int = 8000, overlap: int = 400) -> list[FileChunk]:
    out: list[FileChunk] = []
    for file_path, content in files.items():
        split = chunk_text(content, chunk_size=chunk_size, overlap=overlap)
        total = len(split)
        for idx, chunk in enumerate(split, start=1):
            out.append(
                FileChunk(
                    file=file_path,
                    chunk_index=idx,
                    total_chunks=total,
                    content=chunk,
                )
            )
    return out
