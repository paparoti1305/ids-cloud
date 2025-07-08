FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY . /app

RUN apt-get update && apt-get install -y gcc
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

EXPOSE 8080

CMD streamlit run app.py --server.port=$PORT --server.address=0.0.0.0
