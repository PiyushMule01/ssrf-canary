FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .

# Create directory for SQLite database
RUN mkdir -p /app/data

# Expose port
EXPOSE 8443

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DATABASE_URL=sqlite:////app/data/ssrf_canary.db

# Run the application
CMD ["python", "app.py"]
