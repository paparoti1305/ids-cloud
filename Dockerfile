FROM python:3.10-slim

# 1. Cài các biến môi trường tối ưu hóa
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# 2. Cài hệ thống tối thiểu, clean cache sau khi cài
RUN apt-get update && \
    apt-get install -y gcc build-essential && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 3. Copy sớm requirements để tận dụng cache tốt hơn
COPY requirements.txt /app/

# 4. Cài đặt thư viện Python
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 5. Copy phần còn lại của source code
COPY . /app

# 6. Khai báo cổng
EXPOSE 8080

# 7. Lệnh chạy app (Cloud Run sẽ truyền biến $PORT)
CMD ["streamlit", "run", "app.py", "--server.port=$PORT", "--server.address=0.0.0.0"]
