# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container
COPY . .
RUN chmod +x /app/wait_for_dataset.py

# Install needed packages
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port the app runs on
EXPOSE 8000

# Create a non-root user
RUN useradd -m myuser
USER myuser

# Run the application with the wait script
CMD ["/bin/sh", "-c", "python3 -m uvicorn main:app --host 0.0.0.0 --port 8000"]
