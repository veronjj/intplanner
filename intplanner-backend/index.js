/*!
 * INTPLANNER PRO — Backend de reemplazo de Firebase (Auth + Firestore + RTDB + Storage)
 * usando MongoDB, en un solo archivo.
 *
 * Uso:
 *   1) npm install
 *   2) copiar .env.example a .env y completar
 *   3) npm start
 *
 * Ver README.md para el despliegue en Render + MongoDB Atlas, e INTEGRACION.md
 * para conectar esto con el HTML de INTPLANNER PRO vía firebase-mongo-shim.js.
 */
require('dotenv').config();

const http = require('http');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const { Server } = require('socket.io');

// =======================================================================
// MODELOS
// =======================================================================

// Usuario: une credenciales (Firebase Auth) + perfil (colección "usuarios"
// de Firestore) en un solo documento, porque en la app original ambos
// comparten el mismo id (fbUid).
const UserSchema = new mongoose.Schema(
  {
    _id: { type: String, required: true }, // uuid — se expone como "id" hacia el frontend
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    perfil: { type: mongoose.Schema.Types.Mixed, default: {} },
  },
  { timestamps: true, _id: false }
);
UserSchema.methods.checkPassword = function (plain) { return bcrypt.compare(plain, this.passwordHash); };
UserSchema.statics.hashPassword = function (plain) { return bcrypt.hash(plain, 10); };
UserSchema.methods.toProfileJSON = function () { return { id: this._id, email: this.email, ...(this.perfil || {}) }; };
const User = mongoose.model('User', UserSchema);

// Documento genérico: reemplaza cualquier colección de Firestore (tareas,
// clientes, equipo, proyectos, facturas, anticipos, alertas, servicios,
// cargos, visitas_cliente, qr_tokens, ip_rate_limits, etc.)
const DocumentSchema = new mongoose.Schema(
  {
    collection: { type: String, required: true, index: true },
    docId: { type: String, required: true },
    data: { type: mongoose.Schema.Types.Mixed, required: true },
  },
  { timestamps: { createdAt: false, updatedAt: 'updatedAt' }, suppressReservedKeysWarning: true }
);
DocumentSchema.index({ collection: 1, docId: 1 }, { unique: true });
const DocumentModel = mongoose.model('Document', DocumentSchema);

// Nodo RTDB genérico: reemplaza Firebase Realtime Database (usado por el chat).
const RtdbNodeSchema = new mongoose.Schema(
  {
    path: { type: String, required: true, unique: true, index: true },
    value: { type: mongoose.Schema.Types.Mixed },
  },
  { timestamps: { createdAt: false, updatedAt: 'updatedAt' } }
);
const RtdbNode = mongoose.model('RtdbNode', RtdbNodeSchema);

// =======================================================================
// MIDDLEWARE DE AUTENTICACIÓN
// =======================================================================

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No autenticado — falta token' });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = payload.sub;
    req.userEmail = payload.email;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

function optionalAuth(req, _res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (token) {
    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      req.userId = payload.sub;
      req.userEmail = payload.email;
    } catch (_e) { /* token inválido en ruta opcional: se ignora */ }
  }
  next();
}

function escapeRegex(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

// =======================================================================
// RUTAS: AUTH  (reemplaza Firebase Auth + colección Firestore "usuarios")
// =======================================================================

function buildAuthRouter(io) {
  const router = express.Router();

  function broadcastUserChange(type, profileOrId) {
    if (!io) return;
    const payload = type === 'remove' ? { id: profileOrId } : { id: profileOrId.id, data: profileOrId };
    io.to('col:usuarios').emit('col:change', { collection: 'usuarios', type, ...payload });
  }

  const loginLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 8,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (_req, res) => res.status(429).json({ error: 'too-many-requests' }),
  });

  function signToken(user) {
    return jwt.sign({ sub: user._id, email: user.email }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || '30d',
    });
  }

  // POST /api/auth/login — equivalente a signInWithEmailAndPassword
  router.post('/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'invalid-email' });

    const user = await User.findOne({ email: String(email).trim().toLowerCase() });
    if (!user) return res.status(404).json({ error: 'user-not-found' });
    if (user.perfil?.activo === false) return res.status(403).json({ error: 'user-disabled' });

    const ok = await user.checkPassword(password);
    if (!ok) return res.status(401).json({ error: 'wrong-password' });

    const token = signToken(user);
    res.json({ token, user: user.toProfileJSON() });
  });

  // GET /api/auth/me — equivalente a leer usuarios/{uid} tras onAuthStateChanged
  router.get('/me', requireAuth, async (req, res) => {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: 'user-not-found' });
    res.json({ user: user.toProfileJSON() });
  });

  // PUT /api/auth/me — actualizar el propio perfil (merge)
  router.put('/me', requireAuth, async (req, res) => {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: 'user-not-found' });
    user.perfil = { ...(user.perfil || {}), ...(req.body?.perfil || {}) };
    await user.save();
    broadcastUserChange('set', user.toProfileJSON());
    res.json({ user: user.toProfileJSON() });
  });

  // PUT /api/auth/me/password — equivalente a auth.currentUser.updatePassword(newPass)
  router.put('/me/password', requireAuth, async (req, res) => {
    const { newPassword } = req.body || {};
    if (!newPassword || newPassword.length < 8) return res.status(400).json({ error: 'weak-password' });
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: 'user-not-found' });
    user.passwordHash = await User.hashPassword(newPassword);
    await user.save();
    res.json({ ok: true });
  });

  // POST /api/auth/users — crear usuario (solo administrador)
  router.post('/users', requireAuth, async (req, res) => {
    const requester = await User.findById(req.userId);
    if (!requester || requester.perfil?.rol !== 'administrador') return res.status(403).json({ error: 'permission-denied' });

    const { email, password, perfil } = req.body || {};
    if (!email || !password || password.length < 8) return res.status(400).json({ error: 'invalid-input' });

    const exists = await User.findOne({ email: String(email).trim().toLowerCase() });
    if (exists) return res.status(409).json({ error: 'email-already-in-use' });

    const id = crypto.randomUUID();
    const user = new User({
      _id: id,
      email: String(email).trim().toLowerCase(),
      passwordHash: await User.hashPassword(password),
      perfil: { id, email: String(email).trim().toLowerCase(), ...(perfil || {}) },
    });
    await user.save();
    broadcastUserChange('set', user.toProfileJSON());
    res.status(201).json({ user: user.toProfileJSON() });
  });

  // GET /api/auth/users — listar usuarios
  router.get('/users', requireAuth, async (_req, res) => {
    const users = await User.find({});
    res.json({ users: users.map((u) => u.toProfileJSON()) });
  });

  // PUT /api/auth/users/:id — actualizar perfil de otro usuario (solo admin)
  router.put('/users/:id', requireAuth, async (req, res) => {
    const requester = await User.findById(req.userId);
    if (!requester || requester.perfil?.rol !== 'administrador') return res.status(403).json({ error: 'permission-denied' });
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'user-not-found' });
    user.perfil = { ...(user.perfil || {}), ...(req.body?.perfil || {}) };
    await user.save();
    broadcastUserChange('set', user.toProfileJSON());
    res.json({ user: user.toProfileJSON() });
  });

  // DELETE /api/auth/users/:id — eliminar usuario (solo admin)
  router.delete('/users/:id', requireAuth, async (req, res) => {
    const requester = await User.findById(req.userId);
    if (!requester || requester.perfil?.rol !== 'administrador') return res.status(403).json({ error: 'permission-denied' });
    await User.findByIdAndDelete(req.params.id);
    broadcastUserChange('remove', req.params.id);
    res.json({ ok: true });
  });

  // POST /api/auth/bootstrap-admin — crea el PRIMER administrador (una sola vez)
  router.post('/bootstrap-admin', async (req, res) => {
    const { token, email, password, nombre } = req.body || {};
    if (!process.env.BOOTSTRAP_ADMIN_TOKEN || token !== process.env.BOOTSTRAP_ADMIN_TOKEN) {
      return res.status(403).json({ error: 'permission-denied' });
    }
    const already = await User.findOne({});
    if (already) return res.status(409).json({ error: 'ya-existe-al-menos-un-usuario' });

    const id = crypto.randomUUID();
    const user = new User({
      _id: id,
      email: String(email).trim().toLowerCase(),
      passwordHash: await User.hashPassword(password),
      perfil: { id, email: String(email).trim().toLowerCase(), nombre: nombre || 'Administrador', rol: 'administrador', activo: true },
    });
    await user.save();
    const jwtToken = signToken(user);
    res.status(201).json({ token: jwtToken, user: user.toProfileJSON() });
  });

  return router;
}

// =======================================================================
// RUTAS: COLECCIONES GENÉRICAS  (reemplaza Firestore .collection().doc())
// =======================================================================

const PUBLIC_COLLECTIONS = new Set(['qr_tokens']);

function buildCollectionsRouter(io) {
  const router = express.Router();

  function authForCollection(req, res, next) {
    if (PUBLIC_COLLECTIONS.has(req.params.col)) return optionalAuth(req, res, next);
    return requireAuth(req, res, next);
  }

  function broadcastChange(col, payload) {
    io.to(`col:${col}`).emit('col:change', { collection: col, ...payload });
  }

  // GET /api/collections/:col — carga inicial equivalente a onSnapshot
  router.get('/:col', authForCollection, async (req, res) => {
    const docs = await DocumentModel.find({ collection: req.params.col });
    res.json({ docs: docs.map((d) => ({ ...d.data, id: d.docId })) });
  });

  // GET /api/collections/:col/:id — equivalente a .doc(id).get()
  router.get('/:col/:id', authForCollection, async (req, res) => {
    const doc = await DocumentModel.findOne({ collection: req.params.col, docId: req.params.id });
    if (!doc) return res.json({ exists: false });
    res.json({ exists: true, data: { ...doc.data, id: doc.docId } });
  });

  // PUT /api/collections/:col/:id — equivalente a .doc(id).set(data,{merge})
  router.put('/:col/:id', authForCollection, async (req, res) => {
    const { col, id } = req.params;
    const merge = req.query.merge !== 'false';
    const incoming = req.body?.data || {};

    let doc = await DocumentModel.findOne({ collection: col, docId: id });
    if (doc && merge) doc.data = { ...doc.data, ...incoming };
    else { doc = doc || new DocumentModel({ collection: col, docId: id, data: {} }); doc.data = incoming; }
    doc.collection = col;
    doc.docId = id;
    await doc.save();

    broadcastChange(col, { type: 'set', id, data: { ...doc.data, id } });
    res.json({ data: { ...doc.data, id } });
  });

  // PATCH /api/collections/:col/:id — equivalente a .doc(id).update(fields)
  router.patch('/:col/:id', authForCollection, async (req, res) => {
    const { col, id } = req.params;
    const doc = await DocumentModel.findOne({ collection: col, docId: id });
    if (!doc) return res.status(404).json({ error: 'not-found' });
    doc.data = { ...doc.data, ...(req.body?.data || {}) };
    await doc.save();
    broadcastChange(col, { type: 'modify', id, data: { ...doc.data, id } });
    res.json({ data: { ...doc.data, id } });
  });

  // DELETE /api/collections/:col/:id — equivalente a .doc(id).delete()
  router.delete('/:col/:id', authForCollection, async (req, res) => {
    const { col, id } = req.params;
    await DocumentModel.deleteOne({ collection: col, docId: id });
    broadcastChange(col, { type: 'remove', id });
    res.json({ ok: true });
  });

  return router;
}

// =======================================================================
// RUTAS: RTDB GENÉRICO  (reemplaza Firebase Realtime Database — chat)
// =======================================================================

function pushId() { return Date.now().toString(36) + '_' + crypto.randomUUID().slice(0, 8); }
function basePathOf(fullPath) { const p = fullPath.split('/'); p.pop(); return p.join('/'); }

function buildRtdbRouter(io) {
  const router = express.Router();
  router.use(requireAuth);

  function broadcast(basePath, payload) {
    io.to(`rtdb:${basePath}`).emit('rtdb:change', { path: basePath, ...payload });
  }

  // GET /api/rtdb/list?path=chat/mensajes&limit=200
  router.get('/list', async (req, res) => {
    const path = String(req.query.path || '');
    const limit = Math.min(parseInt(req.query.limit, 10) || 200, 1000);
    if (!path) return res.status(400).json({ error: 'falta path' });

    const nodes = await RtdbNode.find({ path: new RegExp('^' + escapeRegex(path) + '/') }).sort({ updatedAt: 1 }).limit(limit);
    const value = {};
    nodes.forEach((n) => { value[n.path.slice(path.length + 1)] = n.value; });
    res.json({ value });
  });

  // POST /api/rtdb/push — equivalente a ref(path).push(value)
  router.post('/push', async (req, res) => {
    const { path, value } = req.body || {};
    if (!path) return res.status(400).json({ error: 'falta path' });
    const key = pushId();
    const node = await RtdbNode.create({ path: `${path}/${key}`, value });
    broadcast(path, { type: 'set', key, value: node.value });
    res.status(201).json({ key });
  });

  // PUT /api/rtdb/node — equivalente a ref(fullPath).set(value)
  router.put('/node', async (req, res) => {
    const { path, value } = req.body || {};
    if (!path) return res.status(400).json({ error: 'falta path' });
    const node = await RtdbNode.findOneAndUpdate({ path }, { value }, { upsert: true, new: true });
    const base = basePathOf(path);
    broadcast(base, { type: 'set', key: path.slice(base.length + 1), value: node.value });
    res.json({ ok: true });
  });

  // PATCH /api/rtdb/node — equivalente a ref(fullPath).update(value)
  router.patch('/node', async (req, res) => {
    const { path, value } = req.body || {};
    if (!path) return res.status(400).json({ error: 'falta path' });
    const existing = await RtdbNode.findOne({ path });
    const merged = { ...(existing?.value || {}), ...(value || {}) };
    const node = await RtdbNode.findOneAndUpdate({ path }, { value: merged }, { upsert: true, new: true });
    const base = basePathOf(path);
    broadcast(base, { type: 'set', key: path.slice(base.length + 1), value: node.value });
    res.json({ ok: true });
  });

  // DELETE /api/rtdb/node?path=... — equivalente a ref(fullPath).remove()
  router.delete('/node', async (req, res) => {
    const path = String(req.query.path || '');
    if (!path) return res.status(400).json({ error: 'falta path' });
    await RtdbNode.deleteOne({ path });
    const base = basePathOf(path);
    broadcast(base, { type: 'remove', key: path.slice(base.length + 1) });
    res.json({ ok: true });
  });

  return router;
}

// =======================================================================
// RUTAS: STORAGE (GridFS)  (reemplaza Firebase Storage)
// =======================================================================

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 25 * 1024 * 1024 } });
function gridBucket() { return new mongoose.mongo.GridFSBucket(mongoose.connection.db, { bucketName: 'storage' }); }

function buildStorageRouter() {
  const router = express.Router();
  router.use(requireAuth);

  // PUT /api/storage/file (multipart: campos "file" y "path")
  router.put('/file', upload.single('file'), async (req, res) => {
    const filePath = req.body?.path;
    if (!filePath || !req.file) return res.status(400).json({ error: 'faltan path o file' });

    const gfs = gridBucket();
    const existing = await gfs.find({ filename: filePath }).toArray();
    await Promise.all(existing.map((f) => gfs.delete(f._id).catch(() => {})));

    const uploadStream = gfs.openUploadStream(filePath, {
      contentType: req.file.mimetype,
      metadata: { customMetadata: req.body?.customMetadata ? JSON.parse(req.body.customMetadata) : {} },
    });
    uploadStream.end(req.file.buffer);
    uploadStream.on('finish', () => res.status(201).json({ path: filePath }));
    uploadStream.on('error', (e) => res.status(500).json({ error: e.message }));
  });

  // GET /api/storage/list?prefix=backups/uid/auto
  router.get('/list', async (req, res) => {
    const prefix = String(req.query.prefix || '');
    const gfs = gridBucket();
    const files = await gfs.find({ filename: new RegExp('^' + escapeRegex(prefix) + '/') }).sort({ filename: 1 }).toArray();
    res.json({ items: files.map((f) => ({ name: f.filename.split('/').pop(), path: f.filename })) });
  });

  // GET /api/storage/download?path=...
  router.get('/download', async (req, res) => {
    const filePath = String(req.query.path || '');
    const gfs = gridBucket();
    const files = await gfs.find({ filename: filePath }).toArray();
    if (!files.length) return res.status(404).json({ error: 'not-found' });
    res.set('Content-Type', files[0].contentType || 'application/octet-stream');
    gfs.openDownloadStreamByName(filePath).pipe(res);
  });

  // DELETE /api/storage/file?path=...
  router.delete('/file', async (req, res) => {
    const filePath = String(req.query.path || '');
    const gfs = gridBucket();
    const files = await gfs.find({ filename: filePath }).toArray();
    await Promise.all(files.map((f) => gfs.delete(f._id)));
    res.json({ ok: true });
  });

  return router;
}

// =======================================================================
// SOCKET.IO — salas por colección/ruta RTDB + emulación de onDisconnect
// =======================================================================

function setupSockets(io) {
  const disconnectActions = new Map(); // socketId -> [{path, action, value}]

  io.use((socket, next) => {
    try {
      const token = socket.handshake.auth?.token;
      if (!token) return next(new Error('unauthorized'));
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      socket.userId = payload.sub;
      next();
    } catch (e) {
      next(new Error('unauthorized'));
    }
  });

  io.on('connection', (socket) => {
    socket.on('col:subscribe', (col) => { if (typeof col === 'string') socket.join(`col:${col}`); });
    socket.on('col:unsubscribe', (col) => { if (typeof col === 'string') socket.leave(`col:${col}`); });

    socket.on('rtdb:subscribe', (path) => { if (typeof path === 'string') socket.join(`rtdb:${path}`); });
    socket.on('rtdb:unsubscribe', (path) => { if (typeof path === 'string') socket.leave(`rtdb:${path}`); });

    socket.on('rtdb:onDisconnect', ({ path, action, value }) => {
      if (!path || !['remove', 'update'].includes(action)) return;
      const list = disconnectActions.get(socket.id) || [];
      list.push({ path, action, value });
      disconnectActions.set(socket.id, list);
    });

    socket.on('rtdb:onDisconnect:cancel', ({ path }) => {
      const list = disconnectActions.get(socket.id) || [];
      disconnectActions.set(socket.id, list.filter((a) => a.path !== path));
    });

    socket.on('disconnect', async () => {
      const actions = disconnectActions.get(socket.id) || [];
      disconnectActions.delete(socket.id);
      for (const { path, action, value } of actions) {
        try {
          if (action === 'remove') {
            await RtdbNode.deleteOne({ path });
          } else if (action === 'update') {
            const existing = await RtdbNode.findOne({ path });
            const merged = { ...(existing?.value || {}), ...(value || {}) };
            await RtdbNode.findOneAndUpdate({ path }, { value: merged }, { upsert: true });
          }
          const base = basePathOf(path);
          const key = path.slice(base.length + 1);
          io.to(`rtdb:${base}`).emit('rtdb:change', {
            path: base,
            type: action === 'remove' ? 'remove' : 'set',
            key,
            value: action === 'update' ? (await RtdbNode.findOne({ path }))?.value : undefined,
          });
        } catch (e) {
          console.warn('Error ejecutando acción onDisconnect:', e.message);
        }
      }
    });
  });
}

// =======================================================================
// SERVIDOR PRINCIPAL
// =======================================================================

async function main() {
  const uri = process.env.MONGODB_URI;
  if (!uri) throw new Error('Falta la variable de entorno MONGODB_URI');
  mongoose.set('strictQuery', true);
  await mongoose.connect(uri, { serverSelectionTimeoutMS: 10000 });
  console.log('✅ MongoDB conectado:', mongoose.connection.name);
  mongoose.connection.on('error', (err) => console.error('❌ Error de conexión a MongoDB:', err.message));
  mongoose.connection.on('disconnected', () => console.warn('⚠️ MongoDB desconectado — mongoose reintentará automáticamente'));

  const app = express();
  const server = http.createServer(app);

  const origins = (process.env.CORS_ORIGINS || '*').split(',').map((s) => s.trim());
  const corsOptions = { origin: origins.includes('*') ? true : origins, credentials: true };

  app.use(cors(corsOptions));
  app.use(express.json({ limit: '10mb' }));

  const io = new Server(server, { cors: corsOptions });
  setupSockets(io);

  app.get('/health', (_req, res) => res.json({ ok: true, ts: Date.now() }));

  app.use('/api/auth', buildAuthRouter(io));
  app.use('/api/collections', buildCollectionsRouter(io));
  app.use('/api/rtdb', buildRtdbRouter(io));
  app.use('/api/storage', buildStorageRouter());

  app.use((err, _req, res, _next) => {
    console.error('Error no manejado:', err);
    res.status(500).json({ error: 'internal-error' });
  });

  const port = process.env.PORT || 4000;
  server.listen(port, () => console.log(`🚀 Backend INTPLANNER PRO escuchando en puerto ${port}`));
}

main().catch((err) => {
  console.error('❌ No se pudo iniciar el servidor:', err);
  process.exit(1);
});
