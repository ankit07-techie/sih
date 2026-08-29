FROM python:3.11-slim

WORKDIR /app

COPY simulator/ /app/simulator/

CMD ["python3", "-u", "simulator/generator_cli.py", "--scenario", "mixed", "--duration", "15"]
