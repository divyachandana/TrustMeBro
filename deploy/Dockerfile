FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -e ".[dev]"
EXPOSE 8000 8501
CMD ["trustmebro-mcp"]
