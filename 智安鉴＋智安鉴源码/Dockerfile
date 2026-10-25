# ---------- 前端构建（React + Vite → static/app） ----------
FROM node:20-alpine AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund --registry=https://registry.npmmirror.com
COPY frontend/ ./
RUN npm run build

FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Asia/Shanghai \
    ZS_HOST=0.0.0.0 \
    ZS_PORT=8080 \
    ZS_NO_BROWSER=1

# 中文字体（PDF 导出需要 CJK 字体）+ 时区数据
RUN apt-get update && apt-get install -y --no-install-recommends \
        fonts-wqy-zenhei \
        tzdata \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime \
    && echo $TZ > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

# 使用国内 PyPI 镜像，提升依赖安装可靠性
RUN pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 前端产物由构建阶段生成（覆盖仓库里可能存在的旧产物）
COPY --from=web /static/app ./static/app

EXPOSE 8080

CMD ["python", "app.py"]
