from fastapi import FastAPI
from pydantic import BaseModel, Field

from rag.chain import ask

app = FastAPI(title="SecOps Assistant")


class AskRequest(BaseModel):
    question: str = Field(min_length=3, max_length=500)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/ask")
def ask_endpoint(req: AskRequest):
    return ask(req.question)
