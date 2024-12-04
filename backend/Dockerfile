# Flask 빌드 환경
FROM python:3.13
WORKDIR /app

# 의존성 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 소스 복사
COPY . .

# Flask 실행 포트
EXPOSE 5001

# Flask 앱 실행
CMD ["python", "run.py"]
