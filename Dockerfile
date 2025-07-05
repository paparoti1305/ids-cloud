FROM python:3.10
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt

# Sử dụng biến PORT do Cloud Run truyền vào
CMD streamlit run app.py --server.port=${PORT:-8080} --server.address=0.0.0.0
