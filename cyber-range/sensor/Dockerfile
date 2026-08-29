FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends tcpdump && rm -rf /var/lib/apt/lists/*

COPY capture/ /app/capture/

CMD ["python3", "-u", "capture/passive_pcap_sensor.py", "--scenario", "mixed", "--duration", "10"]
