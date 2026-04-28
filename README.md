# 🛡️ Mini Shield

Anti-DDoS Layer 7 + WAF + Reverse Proxy gọn nhẹ viết bằng **TypeScript / Node.js**.
Một file config, chạy 1 lệnh, có dashboard realtime — không cần Redis, Docker hay quyền root.

---

## ✨ Tính năng

| Lớp bảo vệ | Mô tả |
|---|---|
| 🔁 Reverse Proxy | Chuyển tiếp request tới backend của bạn (HTTP + WebSocket) |
| ⏱️ Rate Limit | Token bucket theo IP, có burst |
| 🧱 WAF | 20+ rule cho SQLi, XSS, LFI, RCE, SSRF, scanner |
| 🤖 Bot Detect | Chặn `curl`, `wget`, `sqlmap`, scrapers, UA rỗng… |
| 🧠 JS PoW Challenge | Trình duyệt nghi ngờ phải giải SHA-256 trước khi vào |
| 🔒 Auto Ban | Tự khoá IP khi vi phạm liên tục (cấu hình được) |
| 📜 White / Blacklist | Hỗ trợ IP đơn lẻ và CIDR (`10.0.0.0/8`) |
| 📊 Dashboard | UI thời gian thực qua WebSocket — không CDN ngoài |
| 🟢 Demo Backend | Có sẵn backend mẫu để test ngay |

---

## 🚀 Chạy thử

```bash
cd node-shield
npm install
npm start              # tsx (dev mode)
# hoặc
npm run build && npm run serve   # production
```

- Proxy: <http://localhost:8080>
- Dashboard: <http://localhost:5000>
- Demo backend: <http://localhost:8081>

Mở dashboard, rồi thử các lệnh sau để thấy WAF chặn ngay:

```bash
# SQL Injection
curl "http://localhost:8080/?id=1%27%20UNION%20SELECT%20password--"

# XSS
curl "http://localhost:8080/?q=%3Cscript%3Ealert(1)%3C/script%3E"

# Bot
curl http://localhost:8080/         # curl UA → bị chặn

# Spam → tự ban
for i in {1..200}; do curl -s http://localhost:8080/ > /dev/null; done
```

---

## ⚙️ Cấu hình (`config.yaml`)

Mọi thứ nằm trong **một** file. Phần quan trọng:

```yaml
proxy:
  port: 8080
  upstream: "http://127.0.0.1:8081"   # ← đổi sang backend của bạn
  trustProxy: true

dashboard:
  port: 5000
  username: "admin"                    # đặt user/pass khi public
  password: "đổi-mật-khẩu"

rateLimit:
  maxRequests: 30                      # 30 req/giây/IP
  burst: 60

ban:
  maxViolations: 5                     # vi phạm 5 lần…
  durationMs: 600000                   # …khoá 10 phút

waf:
  enabled: true
  blockOnMatch: true                   # false = chỉ log, không chặn

challenge:
  enabled: true
  difficulty: 4                        # số ký tự "0" đầu hash
```

Tắt demo backend khi đã trỏ proxy sang upstream thật:
```yaml
demoBackend:
  enabled: false
```

---

## 🗂️ Cấu trúc

```
node-shield/
├── config.yaml
├── src/
│   ├── index.ts          ← entrypoint
│   ├── config.ts         ← đọc YAML
│   ├── proxy.ts          ← pipeline shield + reverse proxy
│   ├── waf.ts            ← rule SQLi/XSS/LFI/RCE/SSRF
│   ├── rateLimiter.ts    ← token bucket per-IP
│   ├── botDetect.ts      ← phân loại UA
│   ├── challenge.ts      ← trang JS Proof-of-Work
│   ├── state.ts          ← stats + ban store + event bus
│   ├── ipUtil.ts         ← IP, CIDR helpers
│   ├── logger.ts         ← log màu
│   ├── dashboard.ts      ← REST + WebSocket
│   ├── dashboardHtml.ts  ← UI 1 file (zero-dep)
│   └── demoBackend.ts    ← backend test
└── package.json
```

---

## 📡 Dashboard API

| Method | Route | Mô tả |
|---|---|---|
| GET | `/api/stats` | Thống kê tổng |
| GET | `/api/recent` | 100 sự kiện tấn công gần nhất |
| GET | `/api/banned` | IP đang bị khoá |
| POST | `/api/ban` | `{ip, minutes}` — khoá thủ công |
| POST | `/api/unban` | `{ip}` — gỡ khoá |
| GET | `/api/health` | Kiểm tra sống |
| WS | `/ws` | Stream stats + attack realtime |

---

## ☁️ Deploy lên Render (1-click)

Repo này có sẵn `render.yaml` ở thư mục gốc. Cách deploy:

1. Push repo lên GitHub.
2. Vào [Render Dashboard](https://dashboard.render.com/) → **New +** → **Blueprint**.
3. Chọn repo của bạn → Render đọc `render.yaml` và tạo service `mini-shield`.
4. Trước khi confirm, đổi 2 biến môi trường:
   - **`PROXY_UPSTREAM`** = URL của backend bạn muốn bảo vệ (ví dụ `https://api.yoursite.com`).
   - **`DASHBOARD_USERNAME`** + **`DASHBOARD_PASSWORD`** (Render tự sinh password ngẫu nhiên — copy lại để đăng nhập).
5. Click **Apply**, đợi vài phút build xong.

Sau đó:
- Trang được bảo vệ:  `https://<service>.onrender.com/`
- Dashboard quản trị: `https://<service>.onrender.com/__shield/`

> Render chỉ cấp 1 cổng public (`PORT`), Mini Shield tự phát hiện và gộp dashboard
> + proxy vào chung 1 server. Dashboard nằm dưới đường dẫn `/__shield/` để không
> đụng với routes của upstream.

### Biến môi trường được hỗ trợ

| Biến | Tác dụng |
|---|---|
| `PORT` | Render đặt sẵn — bật chế độ chung 1 cổng |
| `PROXY_UPSTREAM` | Ghi đè `proxy.upstream` trong YAML |
| `DASHBOARD_USERNAME` | User Basic-Auth |
| `DASHBOARD_PASSWORD` | Password Basic-Auth |
| `DASHBOARD_BASE_PATH` | Đổi `/__shield` thành đường dẫn khác |

Cách hosting tương tự (Fly.io, Railway, Heroku, Koyeb…) đều dùng được — chúng đều cấp `PORT` env var.

⚠️ **Lưu ý plan free của Render**: instance sẽ "sleep" sau 15 phút không có traffic.
Khi sleep, mọi IP ban / counter trong RAM bị mất. Production thật nên dùng plan trả phí
hoặc một service "always-on".

---

## 🛠️ Triển khai production

1. Đổi `dashboard.username` / `password` để bật Basic Auth.
2. Trỏ `proxy.upstream` về backend thật, tắt `demoBackend`.
3. Đặt sau Cloudflare/Nginx → bật `proxy.trustProxy: true` để IP chuẩn.
4. Build & chạy:
   ```bash
   npm run build && node dist/index.js -c config.yaml
   ```
5. Hoặc đóng gói bằng `pm2 / systemd / Docker` tuỳ thích.

---

## 📝 License

MIT — dùng tự do, fork tự do.
