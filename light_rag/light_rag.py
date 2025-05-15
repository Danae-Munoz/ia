import os
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer
from .rag_utils import split_text_to_chunks


class LightRAG:
    def __init__(self, docs_folder):
        self.docs_folder = docs_folder
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        self.text_chunks = []
        self.embeddings = None
        self.index = None
        self._load_documents_and_build_index()

    def _load_documents_and_build_index(self):
        texts = []
        for filename in os.listdir(self.docs_folder):
            if filename.endswith('.txt'):
                with open(os.path.join(self.docs_folder, filename), 'r', encoding='utf-8') as f:
                    text = f.read()
                    chunks = split_text_to_chunks(text)
                    texts.extend(chunks)

        self.text_chunks = texts
        embeddings = self.model.encode(texts, convert_to_numpy=True, show_progress_bar=True)

        self.embeddings = embeddings
        dimension = embeddings.shape[1]
        self.index = faiss.IndexFlatL2(dimension)
        self.index.add(embeddings)

    def get_relevant_context(self, query, top_k=3):
        query_emb = self.model.encode([query], convert_to_numpy=True)
        distances, indices = self.index.search(query_emb, top_k)
        results = []
        for idx in indices[0]:
            results.append(self.text_chunks[idx])
        return "\n\n".join(results)
