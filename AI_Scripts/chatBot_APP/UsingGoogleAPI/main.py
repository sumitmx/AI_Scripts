'''Run the code with command : uvicorn main:app --reload'''

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from dotenv import load_dotenv
import os

# Load API key from .env
load_dotenv()
api_key = os.getenv("GOOGLE_API_KEY")

llm = ChatGoogleGenerativeAI(model="gemini-2.0-flash", google_api_key=api_key)

app = FastAPI()
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def serve_home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/chat")
async def chat_with_bot(topic: str = Form(...)):
    try:
        prompt = ChatPromptTemplate.from_template("{topic}")
        actual_prompt = prompt.format_prompt(topic=topic)
        response = llm.invoke(actual_prompt)
        return JSONResponse(content={"response": response.content})
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)
