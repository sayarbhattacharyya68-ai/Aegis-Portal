import os
import google.generativeai as genai
from groq import Groq
from dotenv import load_dotenv
from PIL import Image

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))

def get_oracle_analysis(password):
    """Returns a rating and a rapid-fire opinion for the user."""
    try:
        completion = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{
                "role": "system", 
                "content": "You are the Aegis Oracle. Start your response with '[STRONG]' or '[WEAK]'. Then provide 3 extremely short, rapid-fire tactical security opinions (max 5 words each)."
            },
            {"role": "user", "content": f"Analyze: {password}"}]
        )
        return completion.choices[0].message.content
    except: return "[ERROR] Oracle offline."

def verify_payment_screenshot(image_file, expected_amount):
    model = genai.GenerativeModel('gemini-1.5-flash')
    img = Image.open(image_file)
    prompt = f"Verify UPI screenshot: Success status, Amount ₹{expected_amount}, Receiver: Sayar Bhattacharyya. Reply ONLY 'VERIFIED' or 'FAILED: reason'."
    try:
        response = model.generate_content([prompt, img])
        return response.text.strip()
    except Exception as e: return f"ERROR: {str(e)}"