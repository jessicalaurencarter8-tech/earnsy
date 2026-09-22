# موقع أربح من بيتك (Arbah Min Baytak)

منصة متكاملة للمهام والمكافآت في سوريا مع تدقيق يدوي للهويات ومنع الحسابات المكررة عبر تليجرام وقاعدة بيانات Upstash Redis.

## إعداد المشروع على Railway

1. ارفع المشروع إلى مستودع جديد على GitHub.
2. اذهب إلى Railway واختر **New Project** ثم **Deploy from GitHub repo**.
3. في تبويب **Variables** على Railway، أضف المتغيرات التالية:
   - `UPSTASH_REDIS_REST_URL`: رابط REST من لوحة تحكم Upstash.
   - `UPSTASH_REDIS_REST_TOKEN`: توكن قاعدة بيانات Upstash.
   - `TELEGRAM_BOT_TOKEN`: رمز البوت الخاص بك.
   - `TELEGRAM_ADMIN_CHAT_ID`: رقم معرّف المحادثة الخاص بك (من bot @userinfobot).
   - `JWT_SECRET`: أي نص عشوائي قوي لتشفير الجلسات.
4. فعّل النطاق (Generate Domain) لتحصل على رابط الموقع العام.
5. اربط الـ Webhook الخاص بتليجرام بفتح الرابط التالي في المتصفح:
   `https://api.telegram.org/bot<TELEGRAM_BOT_TOKEN>/setWebhook?url=https://<YOUR_RAILWAY_DOMAIN>/api/telegram-webhook`