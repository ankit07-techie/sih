FROM python:3.11-slim

WORKDIR /app

COPY services/ /app/services/

EXPOSE 80 9999 53 443

CMD ["python3", "-u", "services/victim_server.py"]
