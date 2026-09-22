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

// --- 0. التحقق من متغيرات البيئة الحرجة عند الإقلاع (بدون قيم افتراضية للأسرار) ---
const REQUIRED_ENV = ['JWT_SECRET', 'TELEGRAM_BOT_TOKEN', 'TELEGRAM_ADMIN_CHAT_ID', 'TELEGRAM_WEBHOOK_SECRET'];
const missingEnv = REQUIRED_ENV.filter((k) => !process.env[k]);
if (missingEnv.length) {
  console.error(
    `❌ متغيرات بيئة ناقصة: ${missingEnv.join(', ')}\n` +
    `أنشئ ملف .env بالاعتماد على .env.example وعبّئ القيم الحقيقية قبل التشغيل.`
  );
  process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET;
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_ADMIN_CHAT_ID = process.env.TELEGRAM_ADMIN_CHAT_ID;
const TELEGRAM_WEBHOOK_SECRET = process.env.TELEGRAM_WEBHOOK_SECRET;
const TELEGRAM_API = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}`;

// إعداد الاتصال بقاعدة بيانات Upstash (مع مخزن مؤقت في الذاكرة للتطوير المحلي فقط)
let redis;
if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
  redis = new Redis({
    url: process.env.UPSTASH_REDIS_REST_URL,
    token: process.env.UPSTASH_REDIS_REST_TOKEN,
  });
} else {
  console.warn('⚠️  لا يوجد اتصال Upstash — سيتم استخدام مخزن مؤقت في الذاكرة (يُفقد عند إعادة التشغيل). لا تستخدم هذا في الإنتاج.');
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
    },
  };
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) {
      return cb(new Error('يُسمح برفع صور فقط'));
    }
    cb(null, true);
  },
});

app.use(express.json());

// رؤوس أمان أساسية بدون الحاجة لحزم إضافية
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

// هام: نقدّم فقط مجلد public — أبداً لا نقدّم جذر المشروع (كان هذا يكشف server.js وpackage.json و.env)
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- محدد معدل بسيط في الذاكرة لحماية تسجيل الدخول والتسجيل من محاولات التخمين ---
const rateLimitStore = new Map();
function rateLimit({ windowMs, max }) {
  return (req, res, next) => {
    const key = `${req.ip}:${req.path}`;
    const now = Date.now();
    const entry = rateLimitStore.get(key) || { count: 0, resetAt: now + windowMs };
    if (now > entry.resetAt) {
      entry.count = 0;
      entry.resetAt = now + windowMs;
    }
    entry.count += 1;
    rateLimitStore.set(key, entry);
    if (entry.count > max) {
      return res.status(429).json({ error: 'محاولات كثيرة جداً، يرجى المحاولة لاحقاً.' });
    }
    next();
  };
}
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });

function escapeHtml(text) {
  if (!text) return '';
  return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function hashNationalId(id) {
  return crypto.createHash('sha256').update(id.trim()).digest('hex');
}

// --- التحقق من هوية المستخدم عبر التوكن (تصحيح استخراج التوكن الفعلي) ---
async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
  if (!token) return res.status(401).json({ error: 'يرجى تسجيل الدخول أولاً' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'جلسة الدخول غير صالحة' });
    req.user = user;
    next();
  });
}

// --- التحقق من أن طلب الويبهوك قادم فعلاً من تيليجرام ---
function verifyTelegramWebhook(req, res, next) {
  const secret = req.headers['x-telegram-bot-api-secret-token'];
  if (secret !== TELEGRAM_WEBHOOK_SECRET) {
    return res.sendStatus(401);
  }
  next();
}

// تهيئة المهام الافتراضية
async function initSampleTasks() {
  try {
    const taskCount = await redis.scard('active_task_ids');
    if (taskCount === 0) {
      const sampleTasks = [
        {
          id: 'task_1',
          title: 'الانضمام إلى قناة تليجرام الرسمية',
          description: 'انضم للقناة وخذ لقطة شاشة تؤكد انضمامك.',
          reward: 3000,
          proof_type: 'screenshot',
        },
        {
          id: 'task_2',
          title: 'الاشتراك بقناة يوتيوب وتفعيل الجرس',
          description: 'اشترك بالقناة وضع لايك على آخر فيديو وأرسل لقطة شاشة.',
          reward: 5000,
          proof_type: 'screenshot',
        },
        {
          id: 'task_3',
          title: 'مشاركة رابط الموقع على فيسبوك',
          description: 'انشر رابط الموقع في مجموعة وضع رابط المنشور كإثبات.',
          reward: 4000,
          proof_type: 'text_url',
        },
      ];

      for (const t of sampleTasks) {
        await redis.hset(`task:${t.id}`, t);
        await redis.sadd('active_task_ids', t.id);
      }
    }
  } catch (err) {
    console.error('Task init error:', err);
  }
}
initSampleTasks();

// --- تهيئة منتجات تجريبية لمهمة "ضغط صورة المنتج والإعجاب بها" (مكافأة فورية) ---
async function initSampleProducts() {
  try {
    const productCount = await redis.scard('active_product_ids');
    if (productCount === 0) {
      const sampleProducts = [
        { id: 'prod_1', name: 'حقيبة يد جلدية', image_url: '/images/products/bag.jpg', reward: 100 },
        { id: 'prod_2', name: 'ساعة يد كلاسيكية', image_url: '/images/products/watch.jpg', reward: 100 },
        { id: 'prod_3', name: 'سماعات لاسلكية', image_url: '/images/products/headphones.jpg', reward: 100 },
      ];
      for (const p of sampleProducts) {
        await redis.hset(`product:${p.id}`, p);
        await redis.sadd('active_product_ids', p.id);
      }
    }
  } catch (err) {
    console.error('Product init error:', err);
  }
}
initSampleProducts();

// --- 1. تسجيل الحساب ورفع الهوية ---
app.post('/api/register', authLimiter, upload.fields([
  { name: 'id_front', maxCount: 1 },
  { name: 'id_back', maxCount: 1 },
  { name: 'id_card', maxCount: 1 },
  { name: 'selfie', maxCount: 1 },
]), async (req, res) => {
  try {
    const { username, phone, national_id, password } = req.body;

    if (!username || !phone || !national_id || !password) {
      return res.status(400).json({ error: 'جميع الحقول مطلوبة.' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 6 خانات على الأقل.' });
    }
    if (!/^\d{11}$/.test(national_id.trim())) {
      return res.status(400).json({ error: 'الرقم الوطني يجب أن يتكون من 11 رقماً.' });
    }

    const frontImg = (req.files && (req.files['id_front']?.[0] || req.files['id_card']?.[0])) || null;
    const backImg = (req.files && req.files['id_back']?.[0]) || null;
    const selfieImg = (req.files && req.files['selfie']?.[0]) || null;

    if (!frontImg) {
      return res.status(400).json({ error: 'يرجى إرفاق صورة واجهة الهوية على الأقل.' });
    }

    const nationalIdHash = hashNationalId(national_id);

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

    // نرد على المستخدم فوراً بمجرد حفظ الحساب في قاعدة البيانات —
    // لا داعي لانتظار رفع 3 صور إلى تيليجرام قبل أن يرى المستخدم رسالة النجاح.
    res.json({
      success: true,
      message: 'تم إرسال طلبك وصور الهوية بنجاح! حسابك قيد المراجعة وسيتم تفعيله من الإدارة قريباً.',
    });

    // إرسال صور الهوية الثلاث إلى تيليجرام يحدث بعد الرد، وبالتوازي فيما بينها
    // بدل التسلسل (await واحد تلو الآخر) الذي كان يبطئ التسجيل بشكل ملحوظ.
    sendRegistrationPhotosToTelegram({ userId, username, phone, national_id, frontImg, backImg, selfieImg })
      .catch((err) => {
        console.error('Telegram registration photos error:', err.response?.data || err.message);
      });

  } catch (err) {
    console.error('Registration Error:', err.response?.data || err.message);
    res.status(500).json({ error: 'حدث خطأ أثناء معالجة طلب التسجيل.' });
  }
});

// إرسال صور التسجيل إلى بوت تيليجرام في الخلفية (لا يوقف رد المستخدم)
async function sendRegistrationPhotosToTelegram({ userId, username, phone, national_id, frontImg, backImg, selfieImg }) {
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
        { text: '❌ رفض الطلب', callback_data: `reject_user:${userId}` },
      ],
    ],
  }));

  const sends = [
    axios.post(`${TELEGRAM_API}/sendPhoto`, formFront, { headers: formFront.getHeaders() }),
  ];

  if (backImg) {
    const formBack = new FormData();
    formBack.append('chat_id', TELEGRAM_ADMIN_CHAT_ID);
    formBack.append('caption', `2️⃣ <b>صورة الهوية (الوجه الخلفي) للمستخدم:</b> ${escapeHtml(username)}`);
    formBack.append('parse_mode', 'HTML');
    formBack.append('photo', backImg.buffer, { filename: 'id_back.jpg' });
    sends.push(axios.post(`${TELEGRAM_API}/sendPhoto`, formBack, { headers: formBack.getHeaders() }));
  }

  if (selfieImg) {
    const formSelfie = new FormData();
    formSelfie.append('chat_id', TELEGRAM_ADMIN_CHAT_ID);
    formSelfie.append('caption', `3️⃣ <b>صورة السيلفي للمطابقة للمستخدم:</b> ${escapeHtml(username)}`);
    formSelfie.append('parse_mode', 'HTML');
    formSelfie.append('photo', selfieImg.buffer, { filename: 'selfie.jpg' });
    sends.push(axios.post(`${TELEGRAM_API}/sendPhoto`, formSelfie, { headers: formSelfie.getHeaders() }));
  }

  await Promise.all(sends);
}

// --- 2. تسجيل الدخول ---
app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password) return res.status(400).json({ error: 'يرجى إدخال الهاتف وكلمة المرور' });

    const userId = await redis.hget('users_by_phone', phone.trim());
    if (!userId) return res.status(400).json({ error: 'بيانات الدخول غير صحيحة' });

    const user = await redis.hgetall(`user:${userId}`);
    if (!user || !user.password) return res.status(400).json({ error: 'بيانات الدخول غير صحيحة' });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(400).json({ error: 'بيانات الدخول غير صحيحة' });

    if (user.status !== 'verified') {
      return res.status(403).json({
        error: user.status === 'pending'
          ? 'حسابك ما زال قيد تدقيق الهوية من قبل الإدارة.'
          : 'تم رفض طلب حسابك، يرجى التواصل مع الإدارة.',
      });
    }

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { username: user.username, balance: user.balance } });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

// --- 3. جلب بيانات الحساب ورصيده ---
app.get('/api/me', authenticateToken, async (req, res) => {
  try {
    const user = await redis.hgetall(`user:${req.user.id}`);
    res.json({ username: user.username, phone: user.phone, balance: parseInt(user.balance || 0) });
  } catch (err) {
    res.status(500).json({ error: 'تعذر جلب البيانات' });
  }
});

// --- 4. جلب المهام مع حالة كل مهمة بالنسبة للمستخدم الحالي ---
app.get('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const taskIds = await redis.smembers('active_task_ids');
    const userTaskStatuses = (await redis.hgetall(`user_tasks:${req.user.id}`)) || {};
    const tasks = [];
    for (const id of taskIds) {
      const task = await redis.hgetall(`task:${id}`);
      if (task && task.id) {
        tasks.push({ ...task, status: userTaskStatuses[id] || 'available' });
      }
    }
    res.json(tasks);
  } catch (err) {
    res.status(500).json({ error: 'خطأ في جلب المهام' });
  }
});

// --- 4ب. جلب منتجات مهمة "ضغط الصورة والإعجاب" مع حالة كل منتج بالنسبة للمستخدم الحالي ---
app.get('/api/products', authenticateToken, async (req, res) => {
  try {
    const productIds = await redis.smembers('active_product_ids');
    const products = [];
    for (const id of productIds) {
      const product = await redis.hgetall(`product:${id}`);
      if (product && product.id) {
        const liked = await redis.sismember(`user_liked_products:${req.user.id}`, id);
        products.push({ ...product, liked: !!liked });
      }
    }
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: 'خطأ في جلب المنتجات' });
  }
});

// --- 4ج. تنفيذ مهمة "ضغط صورة المنتج والإعجاب" — إضافة فورية للرصيد بدون مراجعة يدوية ---
// المستخدم يضغط صورة المنتج من المتصفح (canvas) ثم يرسلها هنا مع إعجابه؛ مرة واحدة فقط لكل منتج لكل مستخدم.
app.post('/api/products/:productId/like', authenticateToken, upload.single('compressed_image'), async (req, res) => {
  try {
    const { productId } = req.params;
    const product = await redis.hgetall(`product:${productId}`);
    if (!product || !product.id) return res.status(404).json({ error: 'المنتج غير موجود' });

    const alreadyLiked = await redis.sismember(`user_liked_products:${req.user.id}`, productId);
    if (alreadyLiked) {
      return res.status(400).json({ error: 'لقد قمت بتنفيذ هذه المهمة على هذا المنتج مسبقاً.' });
    }

    const reward = parseInt(product.reward || 100);

    // إضافة الرصيد فوراً — هذه المهمة معتمدة تلقائياً بدون انتظار مراجعة الأدمن
    const newBalance = await redis.hincrby(`user:${req.user.id}`, 'balance', reward);
    await redis.sadd(`user_liked_products:${req.user.id}`, productId);

    // إشعار الأدمن للعلم فقط (لا يوقف أو يؤخر الرد على المستخدم)
    const notifyAdmin = async () => {
      const caption = `📦 <b>إعجاب + ضغط صورة منتج</b>\n\n` +
        `👤 <b>المستخدم:</b> ${escapeHtml(req.user.username)}\n` +
        `🛍️ <b>المنتج:</b> ${escapeHtml(product.name)}\n` +
        `💰 <b>أُضيف فورياً:</b> ${reward} ل.س`;
      if (req.file) {
        const form = new FormData();
        form.append('chat_id', TELEGRAM_ADMIN_CHAT_ID);
        form.append('caption', caption);
        form.append('parse_mode', 'HTML');
        form.append('photo', req.file.buffer, { filename: 'compressed.jpg' });
        return axios.post(`${TELEGRAM_API}/sendPhoto`, form, { headers: form.getHeaders() });
      }
      return axios.post(`${TELEGRAM_API}/sendMessage`, { chat_id: TELEGRAM_ADMIN_CHAT_ID, text: caption, parse_mode: 'HTML' });
    };
    notifyAdmin().catch((err) => console.error('Product-like notify error:', err.response?.data || err.message));

    res.json({ success: true, message: `تمت إضافة ${reward} ل.س إلى رصيدك فوراً!`, balance: newBalance });
  } catch (err) {
    console.error('Product like error:', err.response?.data || err.message);
    res.status(500).json({ error: 'خطأ أثناء تنفيذ المهمة' });
  }
});

// --- 5. إرسال إثبات تنفيذ مهمة ---
app.post('/api/tasks/:taskId/submit', authenticateToken, upload.single('screenshot'), async (req, res) => {
  try {
    const { taskId } = req.params;
    const { proof_text } = req.body;
    const task = await redis.hgetall(`task:${taskId}`);
    if (!task || !task.id) return res.status(404).json({ error: 'المهمة غير موجودة' });

    const currentStatus = await redis.hget(`user_tasks:${req.user.id}`, taskId);
    if (currentStatus === 'pending' || currentStatus === 'approved') {
      return res.status(400).json({ error: 'لقد قمت بإرسال إثبات لهذه المهمة مسبقاً.' });
    }

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
    await redis.hset(`user_tasks:${req.user.id}`, { [taskId]: 'pending' });

    const caption = `🎯 <b>إثبات مهمة جديد</b>\n\n` +
                    `👤 <b>المستخدم:</b> ${escapeHtml(req.user.username)}\n` +
                    `📌 <b>المهمة:</b> ${escapeHtml(task.title)}\n` +
                    `💰 <b>المكافأة:</b> ${task.reward} ل.س\n` +
                    (proof_text ? `🔗 <b>الإثبات النصي:</b> ${escapeHtml(proof_text)}\n` : '');

    const replyMarkup = {
      inline_keyboard: [
        [
          { text: '✅ قبول وإضافة الرصيد', callback_data: `approve_sub:${submissionId}` },
          { text: '❌ رفض الإثبات', callback_data: `reject_sub:${submissionId}` },
        ],
      ],
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
    console.error('Task submit error:', err.response?.data || err.message);
    res.status(500).json({ error: 'خطأ أثناء إرسال إثبات المهمة' });
  }
});

// --- 6. طلب سحب الرصيد ---
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
            { text: '❌ رفض وإعادة الرصيد', callback_data: `reject_with:${withdrawalId}` },
          ],
        ],
      },
    });

    res.json({ success: true, message: 'تم تسجيل طلب السحب وسيتم التحويل لك قريباً.' });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في معالجة طلب السحب' });
  }
});

// --- 7. معالجة أزرار تليجرام (محمي بسر الويبهوك) ---
app.post('/api/telegram-webhook', verifyTelegramWebhook, async (req, res) => {
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
          await redis.hset(`user_tasks:${sub.user_id}`, { [sub.task_id]: 'approved' });
          await axios.post(`${TELEGRAM_API}/sendMessage`, {
            chat_id: cb.message.chat.id,
            text: `🟢 تمت الموافقة على المهمة وإضافة ${sub.reward} ل.س لرصيد المستخدم بنجاح.`,
          });
        }
        await axios.post(`${TELEGRAM_API}/answerCallbackQuery`, { callback_query_id: cb.id, text: 'تم قبول الإثبات' });
      } else if (action === 'reject_sub') {
        const sub = await redis.hgetall(`submission:${targetId}`);
        if (sub && sub.status === 'pending') {
          await redis.hset(`submission:${targetId}`, { status: 'rejected' });
          if (sub.user_id && sub.task_id) {
            await redis.hset(`user_tasks:${sub.user_id}`, { [sub.task_id]: 'rejected' });
          }
        }
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
    console.error('Webhook error:', error.response?.data || error.message);
    res.sendStatus(500);
  }
});

app.listen(port, () => {
  console.log(`✅ Server running on port ${port}`);
});
