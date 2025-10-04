FROM golang:1.25-alpine AS builder

WORKDIR /app

# �������� �������� ���
COPY . .

# ��������� ����������� (go.sum ��������� �������������)
RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -o main ./main.go

FROM alpine:latest

RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/main .

EXPOSE 3000
CMD ["./main"]