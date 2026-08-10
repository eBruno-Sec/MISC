# OWASP Benchmark for Python v0.1 — a SECOND, foreign-stack scoring target beside the Java v1.2 suite.
# Everything we have measured so far was one Java/Tomcat app; this is Flask, so it tells us whether the
# engines generalize or whether we quietly fitted to Tomcat's behaviour.
#
# Upstream ships no Docker image, so the source is cloned here and PINNED BY COMMIT — a moving branch
# would silently change the ground truth under a benchmark, which is the one place that must not drift.
FROM python:3.12-slim

# lxml / cryptography / ldap3 in the test cases need these to build; git is only used at build time.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git build-essential libxml2-dev libxslt1-dev libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

ARG BPY_COMMIT=f1291485808b66e20ddb6b01b10dc71b3df8c8ba
WORKDIR /opt
RUN git clone --no-checkout https://github.com/OWASP-Benchmark/BenchmarkPython.git bpy \
    && cd bpy && git checkout --detach "${BPY_COMMIT}"

WORKDIR /opt/bpy
RUN pip install --no-cache-dir -r requirements.txt

# NOTE: upstream's runRemoteAccessibleBenchmark.sh passes --debug. We deliberately DO NOT.
# Flask debug mode renders a full Werkzeug traceback on every unhandled exception, which would hand our
# error-based oracles a signal no real deployment leaks and inflate the score dishonestly. Running
# without it keeps the target representative of production.
EXPOSE 8443
CMD ["flask", "--app", "app.py", "run", "--port", "8443", "--cert=adhoc", "--host=0.0.0.0"]
