import os
import google.generativeai as genai
from groq import Groq
from dotenv import load_dotenv
from PIL import Image

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))

def get_oracle_analysis(password):
    try:
        completion = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "system", "content": "You are the Aegis Oracle. Grade the password and give tactical security advice."},
                      {"role": "user", "content": f"Analyze: {password}"}]
        )
        return completion.choices[0].message.content
    except: return "Oracle Link Unstable."

def verify_payment_screenshot(image_file, expected_amount):
    model = genai.GenerativeModel('gemini-1.5-flash')
    img = Image.open(image_file)
    prompt = f"Analyze this UPI screenshot. If it's a 'Success' payment of ₹{expected_amount} to Sayar Bhattacharyya (sayarbhattacharyya9@oksbi), reply ONLY with 'VERIFIED'. Otherwise, reply 'FAILED' with a short reason."
    try:
        response = model.generate_content([prompt, img])
        return response.text.strip()
    except Exception as e: return f"ERROR: {str(e)}"