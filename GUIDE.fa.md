<div dir="rtl">

# 🧰 PrivateToolBox: راهنمای سریع

[English 🇬🇧](GUIDE.md) | [توضیح کامل](README.fa.md)

یک سرور تازه را در حدود 5 دقیقه امن تر و سریع تر کن. تا نگویی بله هیچ چیز عوض نمیشود
و همه چیز قابل برگشت است. 🛟

## 🚀 شروع

**1️⃣ نصب** (با root وارد سرور شو یا از `sudo` استفاده کن)

```bash
curl -fsSL https://raw.githubusercontent.com/Sorena-max/PrivateToolBox/main/install.sh | sudo bash
```

فقط فایل ها را کپی میکند و دستور `privatetoolbox` را اضافه میکند. هنوز به سرورت دست نمیزند.

**2️⃣ اول ببین 🔍**

```bash
sudo privatetoolbox scan
```

یک امتیاز از 100 و یک فهرست میگیری: ✔ یعنی خوب است و ✖ یعنی میشود بهترش کرد.

**3️⃣ پیش نمایش 🧾**

```bash
sudo privatetoolbox plan --profile recommended
```

همه تغییر هایی را که میدهد چاپ میکند. هنوز چیزی عوض نشده.

**4️⃣ اعمال ✅**

```bash
sudo privatetoolbox apply --profile recommended
```

نقشه را بخوان و `y` بزن. وقتی تمام شد:

- 🪟 یک ترمینال **جدید** باز کن و مطمئن شو هنوز میتوانی وارد شوی
- ⌨️ به ترمینال اول برگرد و `yes` بنویس

اگر کاری نکنی بعد از 2 دقیقه **همه چیز خودش برمیگردد**. 🛟

## 🎯 یک پروفایل انتخاب کن

| پروفایل | برای |
|---|---|
| `recommended` | هر سرور: BBR، سخت سازی کرنل، SSH، فایروال، Fail2Ban، آپدیت، ساعت، لاگ |
| `vpn` | سرور پروکسی و VPN: همچنین تست DNS، محدودیت MSS و محافظ آبیوز |
| `web` | سایت: recommended به اضافه فایل swap |
| `bot` | ربات تلگرام و برنامه های کوچک |
| `game` | سرور بازی: DNS، BBR، فایروال |
| `all` | همه چیز بجز IPv6 |

یا ماژول ها را خودت انتخاب کن: `sudo privatetoolbox apply bbr dns firewall`

## 🧩 هر ماژول چه میکند

- 🌐 `dns` پنج DNS عمومی را از **سرور تو** تست میکند و سریع ترین را میگذارد
- 🚀 `bbr` اتصال سریع تر روی مسیرهای دور
- 🧱 `sysctl` تنظیم های امن تر شبکه کرنل
- 🔐 `ssh` تلاش ورود کمتر، بدون X11، و اختیاری فقط با کلید
- 🔥 `firewall` SSH و پورت های در حال استفاده را باز میکند و بقیه را میبندد
- 🚫 `fail2ban` جلوی کسی که رمز SSH تو را حدس میزند را میگیرد
- 🛡 `abuse` نمیگذارد سرورت شبکه های خصوصی را اسکن کند تا دیتاسنتر شکایت نکند
- ⏱ `updates` و `timesync` و `journald` و `swap` کارهای کوچکی که سرور را سالم نگه میدارند

## ✅ کارهای رایج

- 🕵️ **یک پورت دیگر باز کن:** `sudo privatetoolbox apply firewall --open "8443 51820/udp"`
- 🔑 **رمز خاموش، فقط کلید:** `sudo privatetoolbox apply ssh --ssh-keys-only` (کلید تو باید روی سرور باشد)
- 🔢 **پورت دوم برای SSH:** `sudo privatetoolbox apply ssh firewall --ssh-port 2222`
- 🏎 **فقط تست DNS:** `sudo privatetoolbox dns-test`
- 🇮🇷 **ایران به من میرسد؟** `sudo privatetoolbox verify --iran`
- 📲 **ارسال نتیجه به تلگرام:** `--notify` را اضافه کن (PrivateChecker باید روی همین سرور باشد)
- ⏪ **نظرم عوض شد:** `sudo privatetoolbox undo`
- 🕘 **قبلا چه چیزی را عوض کردم؟** `sudo privatetoolbox history`
- 🌍 **تغییر زبان:** `sudo privatetoolbox lang fa` یا `lang en`

## 🆘 مشکل ها

| مشکل | چه کنم |
|---|---|
| 😱 بعد از یک تغییر نمیتوانم وارد شوم | 2 دقیقه صبر کن: تایمر برش میگرداند. یا از کنسول دیتاسنتر `privatetoolbox undo` را بزن |
| ⏳ "could not arm the rollback timer" | سرور systemd ندارد. فقط اگر به کنسول دسترسی داری از `--no-rollback` استفاده کن |
| 🔥 پورت های Docker باز هستند | Docker از UFW رد میشود. پورت ها را روی `127.0.0.1` منتشر کن یا از زنجیره `DOCKER-USER` استفاده کن |
| 🌐 DNS عوض نشد | ابزار دیگری (netplan یا NetworkManager) DNS را مدیریت میکند. عمدا دست نخورد |
| 🧊 هیچ اتفاقی نمیافتد | همه چیز از قبل تنظیم است. `scan` را بزن |

## 🔒 خوب است بدانی

- 🔍 `scan` و `plan` و `history` و `dns-test` هیچ وقت چیزی را عوض نمیکنند.
- 📒 هر اجرا در `/var/lib/privatetoolbox` ذخیره میشود.
- 🆓 این پروژه رایگان است و فروش یا دریافت وجه بابت آن ممنوع است.

GitHub: [Sorena-max/PrivateToolBox](https://github.com/Sorena-max/PrivateToolBox)

</div>
