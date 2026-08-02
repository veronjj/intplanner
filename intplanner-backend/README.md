# Backend INTPLANNER PRO (MongoDB) — reemplazo de Firebase

Este servidor reemplaza Firebase Auth + Firestore + Realtime Database + Storage
usando MongoDB. Está pensado para usarse junto con el archivo de compatibilidad
`firebase-mongo-shim.js` que se coloca en el HTML de INTPLANNER PRO, de forma
que el código de la app **no necesita reescribirse**.

## 1. Crear la base de datos gratuita (MongoDB Atlas)

1. Crea una cuenta en https://www.mongodb.com/cloud/atlas/register
2. Crea un cluster **M0 (Free)** — 512 MB, suficiente para este tipo de app.
3. En "Database Access", crea un usuario con contraseña.
4. En "Network Access", agrega `0.0.0.0/0` (permitir desde cualquier IP) —
   es la opción más simple para empezar; puedes restringirla después a la IP
   de tu servidor en Render.
5. En "Connect" → "Drivers", copia la cadena de conexión. Se ve así:
   `mongodb+srv://usuario:<password>@cluster0.xxxxx.mongodb.net/`
   Agrega el nombre de la base al final: `.../intplanner?retryWrites=true...`

## 2. Configurar variables de entorno

Copia `.env.example` a `.env` y completa:

- `MONGODB_URI`: la cadena de conexión del paso anterior.
- `JWT_SECRET`: genera uno con `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`.
- `BOOTSTRAP_ADMIN_TOKEN`: un valor aleatorio, solo para crear el primer admin.
- `CORS_ORIGINS`: el dominio desde donde se sirve tu HTML (o `*` mientras pruebas).

## 3. Probar en local (opcional pero recomendado)

```bash
npm install
npm run dev
```

Verifica que responde: `curl http://localhost:4000/health`

Crea el primer usuario administrador (una sola vez):

```bash
curl -X POST http://localhost:4000/api/auth/bootstrap-admin \
  -H "Content-Type: application/json" \
  -d '{"token":"EL_BOOTSTRAP_ADMIN_TOKEN_DE_TU_.ENV","email":"tu@correo.com","password":"TuPassword123","nombre":"Tu Nombre"}'
```

Guarda el `token` (JWT) que te devuelve — es el equivalente a haber iniciado
sesión. Después de este paso, considera borrar o cambiar
`BOOTSTRAP_ADMIN_TOKEN` en el `.env` para que nadie más pueda usarlo.

## 4. Desplegar en Render (gratis)

1. Sube esta carpeta a un repositorio de GitHub.
2. En https://render.com → "New +" → "Web Service" → conecta el repo.
3. Configuración:
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Plan**: Free
4. En "Environment", agrega las mismas variables del `.env` (MONGODB_URI,
   JWT_SECRET, JWT_EXPIRES_IN, CORS_ORIGINS, BOOTSTRAP_ADMIN_TOKEN).
5. Despliega. Render te da una URL como `https://intplanner-backend.onrender.com`.

Nota: en el plan free, el servicio "duerme" tras 15 minutos sin uso y la
primera petición después de eso tarda 30-50 segundos en responder. Si eso
resulta molesto para tu equipo, el plan pago ($7/mes) lo elimina.

## 5. Conectar el HTML de INTPLANNER PRO

Ver el archivo `firebase-mongo-shim.js` y las instrucciones en
`INTEGRACION.md` — son los únicos 2 archivos que se tocan en tu app.

## Estructura de la API

| Firebase original | Endpoint equivalente |
|---|---|
| `signInWithEmailAndPassword` | `POST /api/auth/login` |
| `createUserWithEmailAndPassword` | `POST /api/auth/users` (solo admin) |
| `onAuthStateChanged` / perfil | `GET /api/auth/me` |
| `auth.currentUser.updatePassword` | `PUT /api/auth/me/password` |
| `_db.collection(c).doc(id).set()` | `PUT /api/collections/:col/:id` |
| `_db.collection(c).doc(id).update()` | `PATCH /api/collections/:col/:id` |
| `_db.collection(c).doc(id).delete()` | `DELETE /api/collections/:col/:id` |
| `_db.collection(c).doc(id).get()` | `GET /api/collections/:col/:id` |
| `_db.collection(c).onSnapshot()` | `GET /api/collections/:col` + Socket.io evento `col:change` |
| `_rtdb.ref(p).push()` | `POST /api/rtdb/push` |
| `_rtdb.ref(p).set()` | `PUT /api/rtdb/node` |
| `_rtdb.ref(p).update()` | `PATCH /api/rtdb/node` |
| `_rtdb.ref(p).remove()` | `DELETE /api/rtdb/node` |
| `_rtdb.ref(p).on('value')` | `GET /api/rtdb/list` + Socket.io evento `rtdb:change` |
| `_rtdb.ref(p).onDisconnect()` | evento de socket `rtdb:onDisconnect` |
| `storage.ref(p).put()` | `PUT /api/storage/file` |
| `storage.ref(p).listAll()` | `GET /api/storage/list` |

## Lo que NO se replica 1:1 (y por qué no es grave en esta app)

- **Persistencia offline nativa de Firestore** (`enablePersistence`): la app
  ya usa `localStorage` como caché principal y Firestore solo como capa de
  sincronización — el shim simplemente no activa esta función y la app sigue
  funcionando igual gracias a su propio diseño "localStorage-first".
- **Reglas de seguridad declarativas** (Firestore Security Rules): aquí la
  autorización vive en el backend (middleware `requireAuth`, chequeo de rol
  `administrador`) en vez de un archivo de reglas — mismo resultado, distinta
  ubicación.
