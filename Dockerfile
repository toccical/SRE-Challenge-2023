FROM python:3.8-alpine
EXPOSE 8000
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python3", "app.py"]
