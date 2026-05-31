FROM python:3.11-slim

LABEL project="zt-honeypot-mesh"
LABEL phase="1"
LABEL service="ssh-honeypot"

RUN groupadd -r honeypot && useradd -r -g honeypot -m honeypot

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY config/        ./config/
COPY core_logging/  ./core_logging/
COPY honeypots/     ./honeypots/

RUN mkdir -p /app/logs && chown -R honeypot:honeypot /app/logs

USER honeypot

EXPOSE 2222

CMD ["python", "-u", "honeypots/ssh/ssh_honeypot.py"]