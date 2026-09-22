const express = require('express');
const { Redis } = require('@upstash/redis');
const multer = require('multer');
const FormData = require('form-data');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'arbah-min-baytak-secret-key-2026';

// بيانات البوت الجديد ومعرف حسابك
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '8236604963:AAEDTid3y1suHB_WR_lqmhTuz9-224sFa0E';
const TELEGRAM_ADMIN_CHAT_ID = process.env.TELEGRAM_ADMIN_CHAT_ID || '7401854621';
const TELEGRAM_API = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}`;

// إعداد Upstash مع دعم التخزين المؤقت
let redis;
if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
  redis = new Redis({
    url: process.env.UPSTASH_REDIS_REST_URL,
    token: process.env.UPSTASH_REDIS_REST_TOKEN,
  });
} else {
  const memoryStore = new Map();
  const setStore = new Map();
  redis = {
    async hset(key, data) {
      const existing = memoryStore.get(key) || {};
      memoryStore.set(key, { ...existing, ...data });
    },
    async hget(key, field) {
      const data = memoryStore.get(key) || {};
      return data[field];
    },
    async hgetall(key) {
      return memoryStore.get(key) || {};
    },
    async hexists(key, field) {
      const data = memoryStore.get(key) || {};
      return field in data;
    },
    async hincrby(key, field, amount) {
      const data = memoryStore.get(key) || {};
      const current = parseInt(data[field] || 0);
      data[field] = current + amount;
      memoryStore.set(key, data);
      return data[field];
    },
    async sadd(key, val) {
      if (!setStore.has(key)) setStore.set(key, new Set());
      setStore.get(key).add(val);
    },
    async sismember(key, val) {
      if (!setStore.has(key)) return 0;
      return setStore.get(key).has(val) ? 1 : 0;
    },
    async srem(key, val) {
      if (setStore.has(key)) setStore.get(key).delete(val);
    },
    async smembers(key) {
      if (!setStore.has(key)) return [];
      return Array.from(setStore.get(key));
    },
    async scard(key) {
      if (!setStore.has(key)) return 0;
      return setStore.get(key).size;
    }
  };
}

// استقبال الصور
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

app.use(express.json());
app.use(express.static(path.join(__dirname, '.')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

function escapeHtml(text) {
  if (!text) return '';
  return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function hashNationalId(id) {
  return crypto.createHash('sha256').update(id.trim()).digest('hex');
}

async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ');
  if (!token) return res.status(401).json({ error: 'يرجى تسجيل الدخول أولاً' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'جلسة الدخول غير صالحة' });
    req.user = user;
    next();
  });
}

// --- 1. مسار التسجيل ورفع الصور ---
app.post('/api/register', upload.fields([
  { name: 'id_front', maxCount: 1 },
  { name: 'id_back', maxCount: 1 },
  { name: 'id_card', maxCount: 1 },
  { name: 'selfie', maxCount: 1 }
]), async (req, res) => {
  try {
    const { username, phone, national_id, password } = req.body;

    if (!username || !phone || !national_id || !password) {
      return res.status(400).json({ error: 'جميع الحقول مطلوبة.' });
    }

    // تحديد الصور المرفوعة بمرونة
    const frontImg = (req.files && (req.files['id_front']?.[0] || req.files['id_card']?.[0])) || null;
    const backImg = (req.files && req.files['id_back']?.[0]) || null;
    const selfieImg = (req.files && req.files['selfie']?.[0]) || null;

    if (!frontImg) {
      return res.status(400).json({ error: 'يرجى إرفاق صورة واجهة الهوية على الأقل.' });
    }

    const nationalIdHash = hashNationalId(national_id);

    // فحص منع التكرار
    const isIdTaken = await redis.sismember('registered_national_ids', nationalIdHash);
    if (isIdTaken) {
      return res.status(400).json({ error: 'عذراً، هذا الرقم الوطني مسجل مسبقاً في النظام لمنع تكرار الحسابات.' });
    }

    const isPhoneTaken = await redis.hexists('users_by_phone', phone.trim());
    if (isPhoneTaken) {
      return res.status(400).json({ error: 'رقم الهاتف مستخدم لحساب آخر.' });
    }

    const userId = crypto.randomUUID();
    const hashedPassword = await bcrypt.hash(password, 10);

    await redis.hset(`user:${userId}`, {
      id: userId,
      username: username.trim(),
      phone: phone.trim(),
      national_id_hash: nationalIdHash,
      password: hashedPassword,
      status: 'pending',
      balance: 0,
      created_at: new Date().toISOString(),
    });

    await redis.sadd('registered_national_ids', nationalIdHash);
    await redis.hset('users_by_phone', { [phone.trim()]: userId });

    // إرسال الصورة 1: واجهة الهوية مع أزرار القبول والرفض
    const frontCaption = `📋 <b>طلب تحقق جديد - موقع أربح من بيتك</b>\n\n` +
                         `👤 <b>الاسم:</b> ${escapeHtml(username)}\n` +
                         `📱 <b>الهاتف:</b> ${escapeHtml(phone)}\n` +
                         `🆔 <b>الرقم الوطني:</b> <code>${escapeHtml(national_id)}</code>\n` +
                         `🔑 <b>معرف الحساب:</b> <code>${userId}</code>\n\n` +
                         `1️⃣ <b>صورة الهوية (الوجه الأمامي):</b>`;

    const formFront = new FormData();
    formFront.append('chat_id', TELEGRAM_ADMIN_CHAT_ID);
    formFront.append('caption', frontCaption);
    formFront.append('parse_mode', 'HTML');
    formFront.append('photo', frontImg.buffer, { filename: 'id_front.jpg' });
    formFront.append('reply_markup', JSON.stringify({
      inline_keyboard: [
        [
          { text: '✅ قبول وتفعيل الحساب', callback_data: `approve_user:${userId}` },
          { text: '❌ رفض الطلب', callback_data: `reject_user:${userId}` }
        ]
      ]
    }));

    await axios.post(`${TELEGRAM_API}/sendPhoto`, formFront, { headers: formFront.getHeaders() });

    // إرسال الصورة 2 (الوجه الخلفي إن وجدت)
    if (backImg) {
      const formBack = new FormData();
      formBack.append('chat_id', TELEGRAM_ADMIN_CHAT_ID);
      formBack.append('caption', `2️⃣ <b>صورة الهوية (الوجه الخلفي) للمستخدم:</b> ${escapeHtml(username)}`);
      formBack.append('parse_mode', 'HTML');
      formBack.append('photo', backImg.buffer, { filename: 'id_back.jpg' });
      await axios.post(`${TELEGRAM_API}/sendPhoto`, formBack, { headers: formBack.getHeaders() });
    }

    // إرسال الصورة 3 (السيلفي إن وجدت)
    if (selfieImg) {
      const formSelfie = new FormData();
      formSelfie.append('chat_id', TELEGRAM_ADMIN_CHAT_ID);
      formSelfie.append('caption', `3️⃣ <b>صورة السيلفي للمطابقة للمستخدم:</b> ${escapeHtml(username)}`);
      formSelfie.append('parse_mode', 'HTML');
      formSelfie.append('photo', selfieImg.buffer, { filename: 'selfie.jpg' });
      await axios.post(`${TELEGRAM_API}/sendPhoto`, formSelfie, { headers: formSelfie.getHeaders() });
    }

    res.json({
      success: true,
      message: 'تم إرسال طلبك وصور الهوية بنجاح! حسابك قيد المراجعة وسيتم تفعيله من الإدارة قريباً.',
    });

  } catch (err) {
    console.error('Telegram/Registration Error:', err.response?.data || err.message);
    res.status(500).json({ error: 'حدث خطأ أثناء إرسال البيانات إلى تليجرام، تأكد من الضغط على Start للبوت أولاً.' });
  }
});

// باقي المسارات
app.post('/api/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password) return res.status(400).json({ error: 'يرجى إدخال الهاتف وكلمة المرور' });

    const userId = await redis.hget('users_by_phone', phone.trim());
    if (!userId) return res.status(400).json({ error: 'بيانات الدخول غير صحيحة' });

    const user = await redis.hgetall(`user:${userId}`);
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(400).json({ error: 'بيانات الدخول غير صحيحة' });

    if (user.status !== 'verified') {
      return res.status(403).json({
        error: user.status === 'pending'
          ? 'حسابك ما زال قيد تدقيق الهوية من قبل الإدارة.'
          : 'تم رفض طلب حسابك، يرجى التواصل مع الإدارة.'
      });
    }

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { username: user.username, balance: user.balance } });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

app.get('/api/me', authenticateToken, async (req, res) => {
  try {
    const user = await redis.hgetall(`user:${req.user.id}`);
    res.json({ username: user.username, phone: user.phone, balance: parseInt(user.balance || 0) });
  } catch (err) {
    res.status(500).json({ error: 'تعذر جلب البيانات' });
  }
});

app.get('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const taskIds = await redis.smembers('active_task_ids');
    const tasks = [];
    for (const id of taskIds) {
      const task = await redis.hgetall(`task:${id}`);
      if (task) tasks.push(task);
    }
    res.json(tasks);
  } catch (err) {
    res.status(500).json({ error: 'خطأ في جلب المهام' });
  }
});

app.post('/api/tasks/:taskId/submit', authenticateToken, upload.single('screenshot'), async (req, res) => {
  try {
    const { taskId } = req.params;
    const { proof_text } = req.body;
    const task = await redis.hgetall(`task:${taskId}`);
    if (!task) return res.status(404).json({ error: 'المهمة غير موجودة' });

    const submissionId = crypto.randomUUID();
    await redis.hset(`submission:${submissionId}`, {
      id: submissionId,
      user_id: req.user.id,
      task_id: taskId,
      task_title: task.title,
      reward: task.reward,
      proof_text: proof_text || '',
      status: 'pending',
      created_at: new Date().toISOString(),
    });

    const caption = `🎯 <b>إثبات مهمة جديد</b>\n\n` +
                    `👤 <b>المستخدم:</b> ${escapeHtml(req.user.username)}\n` +
                    `📌 <b>المهمة:</b> ${escapeHtml(task.title)}\n` +
                    `💰 <b>المكافأة:</b> ${task.reward} ل.س\n` +
                    (proof_text ? `🔗 <b>الإثبات النصي:</b> ${escapeHtml(proof_text)}\n` : '');

    const replyMarkup = {
      inline_keyboard: [
        [
          { text: '✅ قبول وإضافة الرصيد', callback_data: `approve_sub:${submissionId}` },
          { text: '❌ رفض الإثبات', callback_data: `reject_sub:${submissionId}` }
        ]
      ]
    };

    if (req.file) {
      const form = new FormData();
      form.append('chat_id', TELEGRAM_ADMIN_CHAT_ID);
      form.append('caption', caption);
      form.append('parse_mode', 'HTML');
      form.append('photo', req.file.buffer, { filename: 'proof.jpg' });
      form.append('reply_markup', JSON.stringify(replyMarkup));
      await axios.post(`${TELEGRAM_API}/sendPhoto`, form, { headers: form.getHeaders() });
    } else {
      await axios.post(`${TELEGRAM_API}/sendMessage`, {
        chat_id: TELEGRAM_ADMIN_CHAT_ID,
        text: caption,
        parse_mode: 'HTML',
        reply_markup: replyMarkup,
      });
    }

    res.json({ success: true, message: 'تم إرسال إثبات المهمة للمراجعة بنجاح!' });
  } catch (err) {
    res.status(500).json({ error: 'خطأ أثناء إرسال إثبات المهمة' });
  }
});

app.post('/api/withdraw', authenticateToken, async (req, res) => {
  try {
    const { amount, method, destination } = req.body;
    const withdrawAmount = parseInt(amount);

    if (!withdrawAmount || withdrawAmount <= 0) return res.status(400).json({ error: 'يرجى إدخال مبلغ صحيح' });
    if (!method || !destination) return res.status(400).json({ error: 'يرجى تحديد طريقة السحب ورقم الحساب/المحفظة' });

    const user = await redis.hgetall(`user:${req.user.id}`);
    const currentBalance = parseInt(user.balance || 0);

    if (currentBalance < withdrawAmount) return res.status(400).json({ error: 'رصيدك الحالي غير كافٍ لإتمام السحب' });

    await redis.hincrby(`user:${req.user.id}`, 'balance', -withdrawAmount);

    const withdrawalId = crypto.randomUUID();
    await redis.hset(`withdrawal:${withdrawalId}`, {
      id: withdrawalId,
      user_id: req.user.id,
      amount: withdrawAmount,
      method,
      destination,
      status: 'pending',
      created_at: new Date().toISOString(),
    });

    const msg = `💸 <b>طلب سحب أرباح جديد</b>\n\n` +
                `👤 <b>المستخدم:</b> ${escapeHtml(user.username)} (${escapeHtml(user.phone)})\n` +
                `💵 <b>المبلغ:</b> ${withdrawAmount.toLocaleString()} ل.س\n` +
                `🏦 <b>وسيلة السحب:</b> ${escapeHtml(method)}\n` +
                `📍 <b>الحساب المستلم:</b> <code>${escapeHtml(destination)}</code>`;

    await axios.post(`${TELEGRAM_API}/sendMessage`, {
      chat_id: TELEGRAM_ADMIN_CHAT_ID,
      text: msg,
      parse_mode: 'HTML',
      reply_markup: {
        inline_keyboard: [
          [
            { text: '✅ تأكيد التحويل المالي', callback_data: `pay_with:${withdrawalId}` },
            { text: '❌ رفض وإعادة الرصيد', callback_data: `reject_with:${withdrawalId}` }
          ]
        ]
      }
    });

    res.json({ success: true, message: 'تم تسجيل طلب السحب وسيتم التحويل لك قريباً.' });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في معالجة طلب السحب' });
  }
});

// أزرار تليجرام
app.post('/api/telegram-webhook', async (req, res) => {
  try {
    const update = req.body;
    if (update.callback_query) {
      const cb = update.callback_query;
      const [action, targetId] = cb.data.split(':');

      if (action === 'approve_user') {
        await redis.hset(`user:${targetId}`, { status: 'verified' });
        await axios.post(`${TELEGRAM_API}/editMessageCaption`, {
          chat_id: cb.message.chat.id,
          message_id: cb.message.message_id,
          caption: cb.message.caption + `\n\n🟢 <b>تم تفعيل الحساب بنجاح.</b>`,
          parse_mode: 'HTML',
        });
        await axios.post(`${TELEGRAM_API}/answerCallbackQuery`, { callback_query_id: cb.id, text: 'تم تفعيل الحساب' });
      } else if (action === 'reject_user') {
        const u = await redis.hgetall(`user:${targetId}`);
        await redis.hset(`user:${targetId}`, { status: 'rejected' });
        if (u && u.national_id_hash) {
          await redis.srem('registered_national_ids', u.national_id_hash);
        }
        await axios.post(`${TELEGRAM_API}/editMessageCaption`, {
          chat_id: cb.message.chat.id,
          message_id: cb.message.message_id,
          caption: cb.message.caption + `\n\n🔴 <b>تم رفض هذا الطلب.</b>`,
          parse_mode: 'HTML',
        });
        await axios.post(`${TELEGRAM_API}/answerCallbackQuery`, { callback_query_id: cb.id, text: 'تم الرفض' });
      } else if (action === 'approve_sub') {
        const sub = await redis.hgetall(`submission:${targetId}`);
        if (sub && sub.status === 'pending') {
          await redis.hset(`submission:${targetId}`, { status: 'approved' });
          await redis.hincrby(`user:${sub.user_id}`, 'balance', parseInt(sub.reward));
          await axios.post(`${TELEGRAM_API}/sendMessage`, {
            chat_id: cb.message.chat.id,
            text: `🟢 تمت الموافقة على المهمة وإضافة ${sub.reward} ل.س لرصيد المستخدم بنجاح.`,
          });
        }
        await axios.post(`${TELEGRAM_API}/answerCallbackQuery`, { callback_query_id: cb.id, text: 'تم قبول الإثبات' });
      } else if (action === 'reject_sub') {
        await redis.hset(`submission:${targetId}`, { status: 'rejected' });
        await axios.post(`${TELEGRAM_API}/sendMessage`, {
          chat_id: cb.message.chat.id,
          text: `🔴 تم رفض إثبات هذه المهمة.`,
        });
        await axios.post(`${TELEGRAM_API}/answerCallbackQuery`, { callback_query_id: cb.id, text: 'تم رفض الإثبات' });
      } else if (action === 'pay_with') {
        await redis.hset(`withdrawal:${targetId}`, { status: 'paid' });
        await axios.post(`${TELEGRAM_API}/sendMessage`, {
          chat_id: cb.message.chat.id,
          text: `✅ تم تأكيد إرسال الحوالة للمستخدم.`,
        });
        await axios.post(`${TELEGRAM_API}/answerCallbackQuery`, { callback_query_id: cb.id, text: 'تم تأكيد الدفع' });
      } else if (action === 'reject_with') {
        const w = await redis.hgetall(`withdrawal:${targetId}`);
        if (w && w.status === 'pending') {
          await redis.hset(`withdrawal:${targetId}`, { status: 'rejected' });
          await redis.hincrby(`user:${w.user_id}`, 'balance', parseInt(w.amount));
          await axios.post(`${TELEGRAM_API}/sendMessage`, {
            chat_id: cb.message.chat.id,
            text: `↩️ تم رفض السحب وإعادة مبلغ ${w.amount} ل.س إلى محفظة المستخدم.`,
          });
        }
        await axios.post(`${TELEGRAM_API}/answerCallbackQuery`, { callback_query_id: cb.id, text: 'تم الرفض وإعادة الرصيد' });
      }
    }
    res.sendStatus(200);
  } catch (error) {
    console.error('Webhook error:', error);
    res.sendStatus(500);
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
      
