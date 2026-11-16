# Supply a reviewed immutable base image, e.g. python:<version>@sha256:<digest>.
ARG PYTHON_BASE
FROM ${PYTHON_BASE}
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY src /app/src
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
