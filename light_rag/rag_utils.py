def split_text_to_chunks(text, chunk_size=500, overlap=50):
    tokens = text.split()
    chunks = []
    start = 0
    while start < len(tokens):
        end = start + chunk_size
        chunk = " ".join(tokens[start:end])
        chunks.append(chunk)
        start += chunk_size - overlap
    return chunks
