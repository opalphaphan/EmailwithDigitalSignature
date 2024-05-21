from fastapi import FastAPI, Request
from typing import Dict
from dotenv import load_dotenv
from fastapi.responses import JSONResponse
import os
import sign 
from pydantic import BaseModel
from fastapi import HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

app = FastAPI() # Create a FastAPI application instance
load_dotenv() # Load environment variables from a .env file

# Define a Pydantic model for the email request
class EmailRequest(BaseModel):
    text: str # Text content of the email
    signature: str # Signature for verification

# Route for the root URL
@app.get("/")
async def read_root():
    return FileResponse("static/index.html")

# Route for sending emails
@app.post("/send-email/")
async def send(email_request: EmailRequest):
    sign.genkey() # Generate a key pair for signing the email
    receiver_email = os.getenv("receiver_email") # Get the receiver's email address from environment
    subject = "project"
    body = email_request.text
    sign.send(receiver_email, subject, body) # Sending the email using the sign from sign.py
    return {"message": "Email sent successfully"} # Returning a success message

# Route for receiving emails
@app.post("/receive-email")
def receive_email(email_request: EmailRequest):
    status = sign.receive(email_request.text, email_request.signature) # Verifying the received email signature
    return {"status": status} # Returning the verification status


# Mount the static files directory
app.mount("/static", StaticFiles(directory="static"), name="static")