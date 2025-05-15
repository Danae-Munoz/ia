# rag_utils.py

from sentence_transformers import SentenceTransformer
import faiss
import numpy as np

# Cargar modelo de embeddings
model = SentenceTransformer('all-MiniLM-L6-v2')

# Lista de documentos base (puedes iniciarla vacía si prefieres cargar después)
documents = [
    "Flask es un framework ligero para Python.",
    "Ollama permite correr modelos LLM localmente.",
    "LightRAG usa embeddings para encontrar contexto relevante."
]

# Crear embeddings iniciales
document_embeddings = model.encode(documents)

# Inicializar el índice FAISS
dimension = document_embeddings.shape[1]
index = faiss.IndexFlatL2(dimension)
index.add(np.array(document_embeddings))

def retrieve_context(question, top_k=2):
    """
    Recupera el contexto más relevante desde los documentos según la pregunta.
    """
    question_embedding = model.encode([question])
    distances, indices = index.search(question_embedding, top_k)
    results = [documents[i] for i in indices[0]]
    return " ".join(results)

def ingest_document(new_text):
    """
    Agrega un nuevo documento a la base y actualiza el índice FAISS.
    """
    if new_text and isinstance(new_text, str):
        documents.append(new_text)
        new_embedding = model.encode([new_text])
        index.add(np.array(new_embedding))

def reset_index():
    """
    Opcional: reinicia completamente el índice FAISS (puede ser útil si cargas archivos en bloque).
    """
    global index
    index = faiss.IndexFlatL2(dimension)
    if documents:
        embeddings = model.encode(documents)
        index.add(np.array(embeddings))
