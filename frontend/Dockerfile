# Node.js 이미지를 베이스로 사용
FROM node:20

# 작업 디렉토리 생성
WORKDIR /app

# package.json과 yarn.lock 파일을 복사
COPY package.json yarn.lock ./

# 의존성 설치 (react-router-dom 및 mui 관련 패키지 포함)
RUN yarn install

# react-router-dom 및 mui 패키지 설치
RUN yarn add react-router-dom @mui/material @emotion/react @emotion/styled

# 프로젝트 파일을 모두 복사
COPY . .

# 빌드 
RUN yarn build

# 포트 노출 
EXPOSE 3001

# 컨테이너 시작 시 실행할 명령어
CMD ["yarn", "start"]


