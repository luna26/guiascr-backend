const express = require('express');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
require('dotenv').config();


//install app
//https://oleomargaric-theosophic-vivienne.ngrok-free.dev/api/auth?shop=dev-mercatiko-app.myshopify.com

const {
  initDatabase,
  saveShopSession,
  getShopSession,
  deleteShopSession,
  getActiveShopsCount,
  createExtensionKey,
  validateExtensionKey,
  getShopExtensionKeys,
  revokeExtensionKey,
  saveSenderConfig,
  getSenderConfig,
  deleteShopData
} = require('./database');

const app = express();
app.use(cors());
app.use('/api/webhooks', express.raw({ type: 'application/json' }));
app.use(express.json());

// Configuración
const SHOPIFY_API_KEY = process.env.SHOPIFY_API_KEY;
const SHOPIFY_API_SECRET = process.env.SHOPIFY_API_SECRET;
const SCOPES = 'read_orders,read_fulfillments';
const APP_URL = process.env.RAILWAY_PUBLIC_DOMAIN
  ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
  : 'http://localhost:3000';

// Storage temporal para OAuth states
const temporaryStates = new Map();

// Función para verificar firma HMAC de Shopify
function verifyShopifyWebhook(data, hmacHeader) {
  const hash = crypto
    .createHmac('sha256', process.env.SHOPIFY_API_SECRET)
    .update(data, 'utf8')
    .digest('base64');

  return hash === hmacHeader;
}

// Limpiar states expirados
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of temporaryStates.entries()) {
    if (now - value.timestamp > 300000) {
      temporaryStates.delete(key);
    }
  }
}, 300000);

// ============================================================================
// OAUTH 2.0
// ============================================================================

app.get('/api/auth', (req, res) => {
  const shop = req.query.shop;

  console.log('🔵 INICIO OAuth para shop:', shop);

  if (!shop) {
    return res.status(400).send('Missing shop parameter');
  }

  const shopRegex = /^[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com$/;
  if (!shopRegex.test(shop)) {
    return res.status(400).send('Invalid shop parameter');
  }

  const state = crypto.randomBytes(16).toString('hex');
  const redirectUri = `${APP_URL}/api/auth/callback`;

  console.log('🔵 APP_URL:', APP_URL);
  console.log('🔵 Redirect URI:', redirectUri);
  console.log('🔵 State:', state);

  temporaryStates.set(`state_${shop}`, { state, timestamp: Date.now() });

  const authUrl = `https://${shop}/admin/oauth/authorize?` +
    `client_id=${SHOPIFY_API_KEY}&` +
    `scope=${SCOPES}&` +
    `redirect_uri=${redirectUri}&` +
    `state=${state}`;

  console.log('🔵 Redirigiendo a Shopify OAuth URL:', authUrl);

  res.redirect(authUrl);
});

app.get('/api/auth/callback', async (req, res) => {
  const { shop, code, state, hmac } = req.query;

  console.log('🟡 OAuth callback recibido');

  const savedState = temporaryStates.get(`state_${shop}`);
  if (!savedState || savedState.state !== state) {
    return res.status(403).send('Invalid state parameter');
  }

  const queryParams = { ...req.query };
  delete queryParams.hmac;
  const queryString = Object.keys(queryParams)
    .sort()
    .map(key => `${key}=${queryParams[key]}`)
    .join('&');

  const hash = crypto
    .createHmac('sha256', SHOPIFY_API_SECRET)
    .update(queryString)
    .digest('hex');

  if (hash !== hmac) {
    return res.status(403).send('HMAC validation failed');
  }

  temporaryStates.delete(`state_${shop}`);

  try {

    console.log('🟢 Haciendo request a Shopify para intercambiar código...');

    const tokenResponse = await axios.post(
      `https://${shop}/admin/oauth/access_token`,
      {
        client_id: SHOPIFY_API_KEY,
        client_secret: SHOPIFY_API_SECRET,
        code: code
      }
    );

    const accessToken = tokenResponse.data.access_token;
    const scope = tokenResponse.data.scope;

    console.log('💾 Guardando tienda:', shop);

    await saveShopSession(shop, accessToken, scope);

    console.log('✓ Tienda instalada:', shop);

    await createExtensionKey(shop, 'Access Key Inicial');

    await registerWebhooks(shop, accessToken);

    res.redirect(`https://${shop}/admin/apps/${SHOPIFY_API_KEY}`);

  } catch (error) {
    console.error('Error en OAuth callback:', error.response?.data || error.message);
    res.status(500).send('Error during authentication');
  }
});

// ============================================================================
// MIDDLEWARE: Session Token (IGNORA EXPIRACIÓN PARA TESTING)
// ============================================================================

async function verifySessionToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing authorization header' });
  }

  const sessionToken = authHeader.replace('Bearer ', '');

  try {
    const payload = jwt.decode(sessionToken);

    if (!payload || !payload.dest) {
      return res.status(401).json({ error: 'Invalid token format' });
    }

    const shop = payload.dest.replace('https://', '');

    // VERIFICAR TOKEN CON IGNOREEXPIRATION = TRUE
    // jwt.verify(sessionToken, SHOPIFY_API_SECRET, {
    //   algorithms: ['HS256'],
    //   audience: SHOPIFY_API_KEY,
    //   ignoreExpiration: true  // ← CRÍTICO PARA QUE FUNCIONE
    // });

    const shopData = await getShopSession(shop);

    if (!shopData || !shopData.isActive) {
      return res.status(401).json({ error: 'Shop not installed' });
    }

    req.shop = shop;
    req.accessToken = shopData.accessToken;
    req.authMethod = 'session_token';

    next();

  } catch (error) {
    console.error('Session token verification failed:', error.message);
    return res.status(401).json({ error: 'Invalid session token' });
  }
}

// ============================================================================
// MIDDLEWARE: Extension Access Key
// ============================================================================

async function verifyExtensionKey(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing authorization header' });
  }

  const accessKey = authHeader.replace('Bearer ', '');

  if (!accessKey.startsWith('sk_')) {
    return res.status(401).json({ error: 'Invalid access key format' });
  }

  try {
    const keyData = await validateExtensionKey(accessKey);

    if (!keyData) {
      return res.status(401).json({ error: 'Invalid or revoked access key' });
    }

    req.shop = keyData.shop;
    req.accessToken = keyData.accessToken;
    req.authMethod = 'extension_key';

    next();

  } catch (error) {
    console.error('Extension key verification failed:', error.message);
    return res.status(401).json({ error: 'Authentication failed' });
  }
}

// ============================================================================
// ENDPOINTS DE LA APP EMBEDDED
// ============================================================================

app.get('/api/app/extension-keys', verifySessionToken, async (req, res) => {
  try {
    const { shop } = req;
    const keys = await getShopExtensionKeys(shop);

    res.json({
      success: true,
      keys: keys.map(k => ({
        id: k.id,
        accessKey: k.accessKey,
        name: k.name,
        createdAt: k.createdAt,
        lastUsedAt: k.lastUsedAt
      }))
    });

  } catch (error) {
    console.error('Error fetching extension keys:', error);
    res.status(500).json({
      success: false,
      error: 'Error obteniendo access keys'
    });
  }
});

app.post('/api/app/extension-keys', verifySessionToken, async (req, res) => {
  try {
    const { shop } = req;
    const { name } = req.body;

    const key = await createExtensionKey(shop, name || 'Nuevo Access Key');

    res.json({
      success: true,
      key: {
        id: key.id,
        accessKey: key.accessKey,
        name: key.name,
        createdAt: key.createdAt
      }
    });

  } catch (error) {
    console.error('Error creating extension key:', error);
    res.status(500).json({
      success: false,
      error: 'Error creando access key'
    });
  }
});

app.delete('/api/app/extension-keys/:accessKey', verifySessionToken, async (req, res) => {
  try {
    const { shop } = req;
    const { accessKey } = req.params;

    await revokeExtensionKey(accessKey, shop);

    res.json({
      success: true,
      message: 'Access key revocado'
    });

  } catch (error) {
    console.error('Error revoking extension key:', error);
    res.status(500).json({
      success: false,
      error: 'Error revocando access key'
    });
  }
});

app.post('/api/sender-config', verifyExtensionKey, async (req, res) => {

  try {
    const { shop } = req;
    const config = req.body;

    await saveSenderConfig(shop, config);

    res.json({
      success: true,
      message: 'Configuración guardada'
    });

  } catch (error) {
    console.error('Error saving config:', error);
    res.status(500).json({
      success: false,
      error: 'Error guardando configuración'
    });
  }
});

app.get('/api/app/sender-config', verifySessionToken, async (req, res) => {
  try {
    console.log('---------- sender config GET 1')
    const { shop } = req;
    const config = await getSenderConfig(shop);

    res.json({
      success: true,
      config: config || {}
    });

  } catch (error) {
    console.error('Error fetching config:', error);
    res.status(500).json({
      success: false,
      error: 'Error obteniendo configuración'
    });
  }
});

// ============================================================================
// ENDPOINTS PARA LA EXTENSIÓN
// ============================================================================

app.get('/api/orders/pending', verifyExtensionKey, async (req, res) => {
  try {
    const { shop, accessToken } = req;

    // Usar REST API en lugar de GraphQL
    const response = await axios.get(
      `https://${shop}/admin/api/2024-01/orders.json`,
      {
        params: {
          status: 'any',
          financial_status: 'paid',
          fulfillment_status: 'unfulfilled',
          limit: 50
        },
        headers: {
          'X-Shopify-Access-Token': accessToken
        }
      }
    );

    const orders = response.data.orders.map(order => ({
      id: order.id,
      order_number: order.order_number,
      name: order.name,
      created_at: order.created_at,
      total_price: order.total_price,
      currency: order.currency,
      note: order.note,
      note_attributes: order.note_attributes || [], // ← Aquí están los attributes
      customer: order.customer ? {
        name: `${order.customer.first_name || ''} ${order.customer.last_name || ''}`,
        email: order.customer.email || '',
        phone: order.customer.phone || ''
      } : null,
      shipping_address: order.shipping_address,
      line_items: order.line_items.map(item => ({
        title: item.title,
        quantity: item.quantity,
        price: item.price
      })),
      // Extraer los custom attributes de ubicación
      province_id: order.note_attributes?.find(a => a.name === 'province_id')?.value,
      province_name: order.note_attributes?.find(a => a.name === 'province_name')?.value,
      county_id: order.note_attributes?.find(a => a.name === 'county_id')?.value,
      county_name: order.note_attributes?.find(a => a.name === 'county_name')?.value,
      district_id: order.note_attributes?.find(a => a.name === 'district_id')?.value,
      district_name: order.note_attributes?.find(a => a.name === 'district_name')?.value
    }));

    res.json({
      success: true,
      shop: shop,
      count: orders.length,
      orders: orders
    });

  } catch (error) {
    console.error('❌ Error fetching orders:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Error al obtener pedidos',
      details: error.response?.data || error.message
    });
  }
});

app.post('/api/orders/update-tracking', verifyExtensionKey, async (req, res) => {
  try {
    const { shop, accessToken } = req;
    const { order_id, tracking_number, tracking_company = 'Correos de Costa Rica' } = req.body;

    if (!order_id || !tracking_number) {
      return res.status(400).json({
        success: false,
        error: 'order_id y tracking_number son requeridos'
      });
    }

    const response = await axios.post(
      `https://${shop}/admin/api/2024-01/orders/${order_id}/fulfillments.json`,
      {
        fulfillment: {
          location_id: null,
          tracking_number: tracking_number,
          tracking_company: tracking_company,
          notify_customer: true
        }
      },
      {
        headers: {
          'X-Shopify-Access-Token': accessToken,
          'Content-Type': 'application/json'
        }
      }
    );

    res.json({
      success: true,
      message: 'Tracking actualizado exitosamente',
      fulfillment: response.data.fulfillment
    });

  } catch (error) {
    console.error('Error updating tracking:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Error al actualizar tracking',
      details: error.response?.data || error.message
    });
  }
});

app.get('/api/sender-config', verifyExtensionKey, async (req, res) => {
  try {
    const { shop } = req;
    const config = await getSenderConfig(shop);

    if (!config) {
      return res.status(404).json({
        success: false,
        error: 'Configuración no encontrada. Configura el remitente en la app de Shopify.'
      });
    }

    res.json({
      success: true,
      config: {
        senderIdentificationType: config.senderIdentificationType,
        senderId: config.senderId,
        senderName: config.senderName,
        senderPhone: config.senderPhone,
        senderMail: config.senderMail,
        provinciaSender: config.provinciaSender,
        cantonSender: config.cantonSender,
        distritoSender: config.distritoSender,
        senderPostalCode: config.senderPostalCode,
        senderDirection: config.senderDirection
      }
    });

  } catch (error) {
    console.error('Error fetching config:', error);
    res.status(500).json({
      success: false,
      error: 'Error obteniendo configuración'
    });
  }
});

// ============================================================================
// WEBHOOKS
// ============================================================================

app.post('/api/webhooks/app/uninstalled', async (req, res) => {
  const hmac = req.headers['x-shopify-hmac-sha256'];
  const shop = req.headers['x-shopify-shop-domain'];

  const hash = crypto
    .createHmac('sha256', SHOPIFY_API_SECRET)
    .update(JSON.stringify(req.body))
    .digest('base64');

  if (hash !== hmac) {
    return res.status(403).send('HMAC validation failed');
  }

  await deleteShopSession(shop);

  console.log(`App desinstalada de: ${shop}`);
  res.status(200).send('OK');
});

app.post('/api/webhooks', (req, res) => {
  const hmac = req.headers['x-shopify-hmac-sha256'];

  // Verificar HMAC
  if (!verifyShopifyWebhook(req.body, hmac)) {
    console.log('❌ HMAC verification failed on /api/webhooks');
    return res.status(401).send('Unauthorized');
  }

  console.log('✅ HMAC verification passed on /api/webhooks');
  res.status(200).send('OK');
});

async function registerWebhooks(shop, accessToken) {
  const webhooks = [
    {
      topic: 'app/uninstalled',
      address: `${APP_URL}/api/webhooks/app/uninstalled`
    }
  ];

  for (const webhook of webhooks) {
    try {
      await axios.post(
        `https://${shop}/admin/api/2024-01/webhooks.json`,
        {
          webhook: {
            topic: webhook.topic,
            address: webhook.address,
            format: 'json'
          }
        },
        {
          headers: {
            'X-Shopify-Access-Token': accessToken,
            'Content-Type': 'application/json'
          }
        }
      );
      console.log(`✓ Webhook registrado: ${webhook.topic}`);
    } catch (error) {
      if (error.response?.status === 422) {
        console.log(`Webhook ${webhook.topic} ya existe`);
      } else {
        console.error(`✗ Error registrando webhook:`, error.response?.data || error.message);
      }
    }
  }
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

app.get('/api/health', async (req, res) => {
  const activeShops = await getActiveShopsCount();

  res.json({
    success: true,
    message: 'API funcionando',
    stores: activeShops,
    timestamp: new Date().toISOString()
  });
});

// ============================================================================
// APP EMBEDDED
// ============================================================================

app.use(express.static('public'));

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/app.html');
});

// ========================================
// WEBHOOKS GDPR OBLIGATORIOS
// ========================================

// 1. Customer Data Request
app.post('/api/webhooks/customers/data_request', (req, res) => {
  const hmac = req.headers['x-shopify-hmac-sha256'];

  // Verificar que venga de Shopify
  if (!verifyShopifyWebhook(req.body, hmac)) {
    console.error('❌ HMAC verification failed');
    return res.status(401).send('Unauthorized');
  }

  const webhook = JSON.parse(req.body.toString());
  console.log('📧 Customer data request received:', webhook);

  // TODO: Aquí deberías:
  // 1. Buscar todos los datos del customer en tu DB
  // 2. Enviarlos al email del cliente o endpoint que Shopify especifique
  // Por ahora solo logueamos

  res.status(200).send('OK');
});

// 2. Customer Redact (Borrar datos del cliente)
app.post('/api/webhooks/customers/redact', async (req, res) => {
  const hmac = req.headers['x-shopify-hmac-sha256'];

  if (!verifyShopifyWebhook(req.body, hmac)) {
    console.error('❌ HMAC verification failed');
    return res.status(401).send('Unauthorized');
  }

  const webhook = JSON.parse(req.body.toString());
  const shopDomain = webhook.shop_domain;
  console.log('🗑️ Customer redact received:', webhook);

  // Borrar todos los datos
  const result = await deleteShopData(shopDomain);

  res.status(200).send('OK');
});

// 3. Shop Redact (Borrar datos de la tienda)
app.post('/api/webhooks/shop/redact', async (req, res) => {
  const hmac = req.headers['x-shopify-hmac-sha256'];

  if (!verifyShopifyWebhook(req.body, hmac)) {
    console.error('❌ HMAC verification failed');
    return res.status(401).send('Unauthorized');
  }

  const webhook = JSON.parse(req.body.toString());
  console.log('🗑️ Shop redact received:', webhook);

  // TODO: Borrar TODOS los datos de esta tienda
  // const shopDomain = webhook.shop_domain;
  // await db.query('DELETE FROM sessions WHERE shop = ?', [shopDomain]);
  // await db.query('DELETE FROM sender_configs WHERE shop = ?', [shopDomain]);

  res.status(200).send('OK');
});

// ============================================================================
// INICIAR SERVIDOR
// ============================================================================

async function startServer() {
  const dbReady = await initDatabase();

  if (!dbReady) {
    console.error('✗ No se pudo conectar a la base de datos');
    process.exit(1);
  }

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, async () => {
    const activeShops = await getActiveShopsCount();

    console.log('='.repeat(60));
    console.log('🚀 Servidor iniciado correctamente');
    console.log('='.repeat(60));
    console.log(`📍 Puerto: ${PORT}`);
    console.log(`🌐 URL: ${APP_URL}`);
    console.log(`🔑 API Key: ${SHOPIFY_API_KEY}`);
    console.log(`📊 Tiendas activas: ${activeShops}`);
    console.log('='.repeat(60));
  });
}

startServer();
