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

EXPOSE 8080

CMD ["python", "app.py"]
