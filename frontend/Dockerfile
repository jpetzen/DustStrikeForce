# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container
COPY . .

# Install needed packages
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port the app runs on
EXPOSE 8072

# Create a non-root user
RUN useradd -m myuser
USER myuser

# Run the application
CMD ["streamlit", "run", "mainUI.py", "--server.port", "8072"]
