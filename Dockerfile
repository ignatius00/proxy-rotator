FROM python:3.12-slim

WORKDIR /app
COPY rotator.py proxies.txt ./

EXPOSE 18800
EXPOSE 9090

CMD ["python3", "rotator.py", "--interval", "300", "--listen", "0.0.0.0", "--port", "18800", "--status-port", "9090", "--status-listen", "0.0.0.0"]
