FROM python:3.11-slim

WORKDIR /app

COPY server.py /app/
COPY index.html /app/

EXPOSE 8080

CMD ["python3", "-u", "server.py"]
