from fastapi import FastAPI
from pydantic import BaseModel, Field

from rag.chain import ask, CANARY
from sanitizer import is_suspicious, leaks_secret

app = FastAPI(title="SecOps Assistant")


class AskRequest(BaseModel):
    question: str = Field(min_length=3, max_length=500)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/ask")
def ask_endpoint(req: AskRequest):
    if is_suspicious(req.question):
        return {"answer": "Request blocked by input filter.", "sources": [], "blocked": True}
    result = ask(req.question)
    if leaks_secret(result["answer"], CANARY):
        return {"answer": "Response withheld by output filter.", "sources": [], "blocked": True}
    return result
