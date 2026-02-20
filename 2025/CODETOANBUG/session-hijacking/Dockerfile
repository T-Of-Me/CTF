# Use the official Python image as a base
FROM python:3.9-slim

# Create a non-root user and group named 'web'
RUN useradd -ms /bin/bash web

# Set the working directory in the container
WORKDIR /home/app

# Copy the current directory contents into the container at /app
COPY . /home/app

# Change ownership and permissions of the /app directory to the 'web' user
RUN chmod 5 /home/app/app.py
USER web
# Install Flask (or use requirements.txt if you have it)
RUN pip install Flask
# Expose the port that the Flask app runs on
EXPOSE 4500

# Run the application
CMD ["python", "app.py"]

