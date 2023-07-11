#! /workspace/Python-3.10.0/python


from fastapi import FastAPI
import uvicorn

app = FastAPI()


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/ps")
async def new():
    import os

    os.system("ps")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
