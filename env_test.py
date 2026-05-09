from dotenv import load_dotenv
import os

load_dotenv()

print(os.getenv("NVD_API_KEY"))