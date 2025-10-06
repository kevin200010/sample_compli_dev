# Use the official Python slim image as the base for smaller size and security
FROM python:3.11-slim AS base

# Use a separate builder stage for installing build tools and dependencies to reduce image size
FROM base AS builder

# Set the working directory
WORKDIR /app

# Install build dependencies and clean up afterward
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy only the requirements file to leverage Docker layer caching for dependencies
COPY requirements.txt /app/

# Install Python dependencies into a dedicated directory
RUN python3.11 -m pip install --no-cache-dir --upgrade pip \
    && python3.11 -m pip install --no-cache-dir --prefix=/install -r requirements.txt

# Create the final runtime image
FROM base AS runtime

# Set the working directory
WORKDIR /app

# Install runtime-only dependencies to keep the image slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libstdc++6 \
    unzip \
    curl \
    && curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && ./aws/install \
    && rm -rf awscliv2.zip aws \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python dependencies from builder stage to runtime stage
COPY --from=builder /install /usr/local

# Copy the application code
USER root
COPY . /app

# Set environment variables for production readiness
# Set FLASK_ENV dynamically to switch between development and production
ARG FLASK_ENV=development
ENV FLASK_ENV=${FLASK_ENV}
ENV PYTHONUNBUFFERED=1

# Expose the port your application runs on
EXPOSE 1100

# Specify the default command
CMD ["python3.11", "run.py"]
