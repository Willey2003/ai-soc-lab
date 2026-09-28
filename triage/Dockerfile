FROM python:3.12-slim-bookworm

RUN groupadd -g 1000 triage && useradd -u 1000 -g triage -s /usr/sbin/nologin -M triage

WORKDIR /opt/soc-triage
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY soc_triage ./soc_triage
COPY samples ./samples

USER triage
EXPOSE 8020
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8020/health')"
CMD ["python", "-m", "soc_triage"]
