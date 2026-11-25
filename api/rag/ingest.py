from pathlib import Path

import chromadb
from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_ollama import OllamaEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter

ROOT = Path(__file__).resolve().parents[2]
DATA_DIRS = [ROOT / "data" / "notes", ROOT / "data" / "cve"]
COLLECTION = "secnotes"

def load_docs():
    docs = []
    for d in DATA_DIRS:
        for p in sorted(d.glob("*.md")) + sorted(d.glob("*.txt")):
            docs.append(Document(page_content=p.read_text(encoding="utf-8"),
                                 metadata={"source": f"{d.name}/{p.name}"}))
    return docs

def main():
    docs = load_docs()
    print(f"Loaded {len(docs)} files")
    splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)
    chunks = splitter.split_documents(docs)
    print(f"Split into {len(chunks)} chunks")

    client = chromadb.HttpClient(host="localhost", port=8000)
    try:
        client.delete_collection(COLLECTION)   # start clean so reruns don't duplicate
    except Exception:
        pass

    emb = OllamaEmbeddings(model="nomic-embed-text", base_url="http://localhost:11434")
    Chroma.from_documents(chunks, emb, client=client, collection_name=COLLECTION)
    print("Stored in Chroma collection:", COLLECTION)

if __name__ == "__main__":
    main()
