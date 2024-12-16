# Use the official Golang image as base
FROM golang:1.23-alpine

# Set the working directory
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the application code
COPY . .

# Build the Go application
RUN go build -o main .

# Expose port 3000
EXPOSE 3000

# Command to run the application
CMD ["./main"]
