import os
from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from analiz import sifre_analiz_et

app = FastAPI(title="The Shield v2.0")

# Setup template directory
current_dir = os.path.dirname(os.path.realpath(__file__))
templates = Jinja2Templates(directory=os.path.join(current_dir, "templates"))

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/v1/audit")
async def audit(password: str = Query(...)):
    return sifre_analiz_et(password)