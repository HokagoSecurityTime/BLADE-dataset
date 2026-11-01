FROM python:3.11-slim
WORKDIR /fixture
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN python manage.py spectacular --file openapi.yaml --validate
EXPOSE 8080
CMD ["python","manage.py","runserver","0.0.0.0:8080","--noreload"]
